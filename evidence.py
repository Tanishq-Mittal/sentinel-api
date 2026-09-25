"""Sanitization helpers for authorized live-scan evidence.

The helpers in this module are deliberately independent of the database layer. They
remove credentials and unnecessary sensitive values before evidence is handed to the
canonical SentinelAPI persistence code.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit


REDACTED = "[REDACTED]"
MAX_STRING_LENGTH = 2_000
MAX_BODY_EXCERPT_LENGTH = 4_000

_CREDENTIAL_KEY_PATTERN = re.compile(
    r"(?:password|passwd|secret|token|api[-_]?key|access[-_]?key|"
    r"authorization|cookie|set[-_]?cookie|credential|private[-_]?key|"
    r"client[-_]?secret|refresh[-_]?token|bearer|oauth)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_KEY_PATTERN = re.compile(
    r"(?:password|passwd|secret|token|api[-_]?key|access[-_]?key|"
    r"authorization|cookie|credential|private[-_]?key|email|phone|ssn|"
    r"social[-_]?security|credit[-_]?card|card[-_]?number|internal|debug|"
    r"balance|owner[-_]?email|payment|processor|audit|risk|account[-_]?status)",
    re.IGNORECASE,
)
_JWT_PATTERN = re.compile(r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_BEARER_PATTERN = re.compile(r"(?i)\b(Bearer|Basic)\s+[^\s,;]+")
_KEY_VALUE_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[-_]?key|access[-_]?key|"
    r"client[-_]?secret|authorization|cookie|credential)\s*([:=])\s*([^\s,;]+)"
)
_URL_CREDENTIAL_PATTERN = re.compile(r"(?i)(https?://)[^/\s:@]+:[^@/\s]+@")
_SAFE_HEADERS = {
    "accept",
    "content-type",
    "cache-control",
    "pragma",
    "user-agent",
}


def redact_text(value: Any, *, max_length: int = MAX_STRING_LENGTH) -> Any:
    """Redact common credential forms and bound arbitrary string values."""

    if not isinstance(value, str):
        return value
    value = _BEARER_PATTERN.sub(r"\1 [REDACTED]", value)
    value = _KEY_VALUE_PATTERN.sub(r"\1\2[REDACTED]", value)
    value = _URL_CREDENTIAL_PATTERN.sub(r"\1[REDACTED]@", value)
    value = _JWT_PATTERN.sub(REDACTED, value)
    if len(value) > max_length:
        return value[:max_length] + "...[TRUNCATED]"
    return value


def sanitize_value(value: Any, *, key: str | None = None, depth: int = 0) -> Any:
    """Recursively redact sensitive members while preserving object field names."""

    if key is not None and (
        _CREDENTIAL_KEY_PATTERN.search(str(key))
        or _SENSITIVE_VALUE_KEY_PATTERN.search(str(key))
    ):
        return REDACTED
    if depth > 8:
        return "[TRUNCATED_DEPTH]"
    if isinstance(value, Mapping):
        return {
            str(item_key): sanitize_value(
                item_value,
                key=str(item_key),
                depth=depth + 1,
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            sanitize_value(item, depth=depth + 1)
            for item in value[:200]
        ]
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value))


def sanitize_url(value: str) -> str:
    """Return a URL without query/fragment data or embedded credentials."""

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return "[REDACTED_URL]"
    if parsed.username or parsed.password:
        host = f"[REDACTED]@{hostname}"
        if port:
            host += f":{port}"
    else:
        host = parsed.netloc
    return urlunsplit((parsed.scheme, host, parsed.path, "", ""))


def sanitize_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    """Retain useful safe headers and redact credential-bearing headers."""

    if not headers:
        return {}
    sanitized: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        name = str(raw_name)
        lowered = name.lower()
        if lowered in {"authorization", "proxy-authorization", "cookie", "set-cookie"}:
            sanitized[name] = REDACTED
        elif lowered in _SAFE_HEADERS:
            sanitized[name] = str(redact_text(str(raw_value)))
    return sanitized


def body_fields(body: Any) -> list[str]:
    """Return top-level object field names for response comparison evidence."""

    if isinstance(body, Mapping):
        return sorted(str(key) for key in body.keys())
    return []


def body_excerpt(body: Any, *, max_chars: int = MAX_BODY_EXCERPT_LENGTH) -> Any:
    """Return a sanitized, bounded response representation."""

    if isinstance(body, (bytes, bytearray)):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError:
            return "[BINARY_RESPONSE_REDACTED]"
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except (TypeError, json.JSONDecodeError):
            return redact_text(body, max_length=max_chars)
    sanitized = sanitize_value(body)
    try:
        rendered = json.dumps(sanitized, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        rendered = str(redact_text(str(sanitized)))
    if len(rendered) > max_chars:
        return rendered[:max_chars] + "...[TRUNCATED]"
    return sanitized


def bounded_json(value: Any, *, max_chars: int = MAX_BODY_EXCERPT_LENGTH) -> str:
    """Serialize sanitized data while keeping the stored TEXT valid JSON."""

    sanitized = sanitize_value(value)
    rendered = json.dumps(sanitized, ensure_ascii=False, sort_keys=True, default=str)
    if len(rendered) <= max_chars:
        return rendered
    return json.dumps(
        {
            "truncated": True,
            "preview": rendered[:max_chars],
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def request_evidence(
    *,
    method: str,
    url: str,
    identity: str,
    object_id: str | None,
    status_code: int | None,
    headers: Mapping[str, Any] | None = None,
    body_fields_list: list[str] | None = None,
) -> dict[str, Any]:
    """Build safe request evidence for a live request."""

    evidence: dict[str, Any] = {
        "source": "authorized_runtime_http",
        "method": method,
        "url": sanitize_url(url),
        "identity": identity,
        "status_code": status_code,
        "headers": sanitize_headers(headers),
    }
    if object_id is not None:
        evidence["object_id"] = object_id
    if body_fields_list:
        evidence["body_fields"] = sorted(str(field) for field in body_fields_list)
    return sanitize_value(evidence)


def response_evidence(
    *,
    status_code: int,
    content_type: str | None,
    body: Any,
    expected_fields: list[str] | None = None,
    actual_fields: list[str] | None = None,
    unexpected_fields: list[str] | None = None,
    comparison: str | None = None,
) -> dict[str, Any]:
    """Build safe response evidence for a live response."""

    evidence: dict[str, Any] = {
        "source": "authorized_runtime_http",
        "status_code": status_code,
        "content_type": content_type,
        "field_names": body_fields(body),
        "body_excerpt": body_excerpt(body),
    }
    if expected_fields is not None:
        evidence["expected_fields"] = sorted(str(field) for field in expected_fields)
    if actual_fields is not None:
        evidence["actual_fields"] = sorted(str(field) for field in actual_fields)
    if unexpected_fields is not None:
        evidence["unexpected_fields"] = sorted(
            str(field) for field in unexpected_fields
        )
    if comparison is not None:
        evidence["comparison"] = comparison
    return sanitize_value(evidence)


def poc_text(value: str) -> str:
    """Return a bounded, credential-free proof-of-concept description."""

    return str(redact_text(value, max_length=MAX_BODY_EXCERPT_LENGTH))


make_request_evidence = request_evidence
make_response_evidence = response_evidence
make_poc_text = poc_text


__all__ = [
    "REDACTED",
    "body_excerpt",
    "body_fields",
    "bounded_json",
    "make_poc_text",
    "make_request_evidence",
    "make_response_evidence",
    "poc_text",
    "redact_text",
    "request_evidence",
    "response_evidence",
    "sanitize_headers",
    "sanitize_url",
    "sanitize_value",
]
