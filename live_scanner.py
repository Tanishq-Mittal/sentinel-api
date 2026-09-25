"""Authorized, local-only live HTTP scanner adapter.

This module is intentionally constrained to the synthetic SentinelAPI sandbox. It
never trusts an arbitrary OpenAPI server URL and performs no writes to target APIs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx

try:  # Supports both script execution and package-style test imports.
    from evidence import (
        body_fields,
        make_poc_text,
        make_request_evidence,
        make_response_evidence,
    )
except ImportError:  # pragma: no cover - package-style fallback
    from .evidence import (  # type: ignore
        body_fields,
        make_poc_text,
        make_request_evidence,
        make_response_evidence,
    )


ALLOWED_TARGET = "http://127.0.0.1:5601"
ORDER_LIST_PATH = "/v1/orders"
ORDER_OBJECT_PATH = "/v1/orders/{order_id}"
ORDER_SECURE_PATH = "/v1/me/orders/{order_id}"
REPORT_LIST_PATH = "/v1/reports"
REPORT_OBJECT_PATH = "/v1/reports/{report_id}"
REPORT_SECURE_PATH = "/v1/me/reports/{report_id}"

_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_ORDER_PATH_PATTERN = re.compile(r"^/v1/orders/[A-Za-z0-9_-]{1,64}$")
_ORDER_ME_PATH_PATTERN = re.compile(r"^/v1/me/orders/[A-Za-z0-9_-]{1,64}$")
_REPORT_PATH_PATTERN = re.compile(r"^/v1/reports/[A-Za-z0-9_-]{1,64}$")
_REPORT_ME_PATH_PATTERN = re.compile(r"^/v1/me/reports/[A-Za-z0-9_-]{1,64}$")

_EXACT_ALLOWED_PATHS = {
    "/health",
    "/openapi.json",
    "/docs",
    "/redoc",
    "/v1/auth/token",
    "/v1/auth/me",
    "/v1/auth/logout",
    ORDER_LIST_PATH,
    REPORT_LIST_PATH,
}


class LiveScanError(RuntimeError):
    """Base class for safe, non-sensitive live scanner errors."""


class TargetValidationError(LiveScanError, ValueError):
    """Raised before any outbound request when a target is not allowlisted."""


class LiveRequestError(LiveScanError):
    """A sanitized request failure with a machine-readable code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class AuthenticationError(LiveScanError):
    """Raised when a local sandbox identity cannot be authenticated."""


class TargetPolicy:
    """Strict URL and path policy for the single authorized sandbox."""

    allowed_target = ALLOWED_TARGET

    @classmethod
    def validate_base_url(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TargetValidationError("Target must be a string")
        if "?" in value or "#" in value:
            raise TargetValidationError("Target query strings and fragments are not allowed")
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as error:
            raise TargetValidationError("Target URL is malformed") from error
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or port != 5601
            or parsed.netloc != "127.0.0.1:5601"
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise TargetValidationError(
                f"Only the exact target {cls.allowed_target} is allowed"
            )
        return cls.allowed_target

    @classmethod
    def validate_request_url(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TargetValidationError("Request URL must be a string")
        if "?" in value or "#" in value:
            raise TargetValidationError("Request query strings and fragments are not allowed")
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as error:
            raise TargetValidationError("Request URL is malformed") from error
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or port != 5601
            or parsed.netloc != "127.0.0.1:5601"
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise TargetValidationError("Request URL is outside the local allowlist")
        path = parsed.path
        if (
            path not in _EXACT_ALLOWED_PATHS
            and not _ORDER_PATH_PATTERN.fullmatch(path)
            and not _ORDER_ME_PATH_PATTERN.fullmatch(path)
            and not _REPORT_PATH_PATTERN.fullmatch(path)
            and not _REPORT_ME_PATH_PATTERN.fullmatch(path)
        ):
            raise TargetValidationError("Request path is not authorized")
        return value

    @classmethod
    def validate_spec_servers(cls, spec: Mapping[str, Any]) -> None:
        """Reject external root, path, or operation server declarations."""

        if not isinstance(spec, Mapping):
            raise TargetValidationError("OpenAPI document must be an object")
        sources: list[Mapping[str, Any]] = [spec]
        paths = spec.get("paths")
        if isinstance(paths, Mapping):
            for path_item in paths.values():
                if not isinstance(path_item, Mapping):
                    continue
                sources.append(path_item)
                for operation in path_item.values():
                    if isinstance(operation, Mapping):
                        sources.append(operation)

        for source in sources:
            if "servers" in source:
                servers = source.get("servers")
                if not isinstance(servers, list) or not servers:
                    raise TargetValidationError("OpenAPI servers must be explicit")
                for server in servers:
                    if not isinstance(server, Mapping):
                        raise TargetValidationError("OpenAPI server entry is invalid")
                    cls.validate_base_url(str(server.get("url", "")))

        # Swagger 2.0 uses host/schemes rather than servers.
        if "host" in spec or "schemes" in spec:
            host = spec.get("host")
            schemes = spec.get("schemes") or ["http"]
            if not isinstance(host, str) or not isinstance(schemes, list) or len(schemes) != 1:
                raise TargetValidationError("Swagger server declaration is invalid")
            base_path = spec.get("basePath") or ""
            if not isinstance(base_path, str):
                raise TargetValidationError("Swagger basePath is invalid")
            cls.validate_base_url(f"{schemes[0]}://{host}{base_path}")


@dataclass(frozen=True)
class LiveCredentials:
    username: str
    password: str = field(repr=False)

    def __post_init__(self) -> None:
        if not self.username or not self.password:
            raise ValueError("Both username and password are required")


@dataclass(frozen=True)
class LiveScanConfig:
    target_base_url: str
    user_a: LiveCredentials
    user_b: LiveCredentials
    timeout_seconds: float = 5.0
    max_response_bytes: int = 1_048_576
    max_requests_per_identity: int = 30

    def __post_init__(self) -> None:
        TargetPolicy.validate_base_url(self.target_base_url)
        if self.timeout_seconds <= 0 or self.timeout_seconds > 30:
            raise ValueError("timeout_seconds is outside the allowed range")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if self.max_requests_per_identity <= 0:
            raise ValueError("max_requests_per_identity must be positive")


@dataclass
class LiveResponse:
    status_code: int
    headers: dict[str, str]
    content: bytes
    json_body: Any
    url: str

    @property
    def successful(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def content_type(self) -> str | None:
        return self.headers.get("content-type")


class AuthorizedHttpClient:
    """Synchronous HTTP client with a fixed local target and bounded responses."""

    def __init__(
        self,
        target: str,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
        max_requests: int,
        transport: httpx.BaseTransport | None = None,
    ):
        self.target = TargetPolicy.validate_base_url(target)
        self.max_response_bytes = max_response_bytes
        self.max_requests = max_requests
        self.request_count = 0
        self.client = httpx.Client(
            base_url=self.target,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 3.0)),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
            cookies=None,
            transport=transport,
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: Mapping[str, str] | None = None,
        json_body: Any = None,
    ) -> LiveResponse:
        if self.request_count >= self.max_requests:
            raise LiveRequestError("request_limit")
        self.request_count += 1
        url = f"{self.target}{path}"
        TargetPolicy.validate_request_url(url)
        request = self.client.build_request(
            method,
            url,
            headers=dict(headers or {}),
            data=dict(data) if data is not None else None,
            json=json_body,
        )
        try:
            response = self.client.send(request, stream=True)
        except httpx.TimeoutException as error:
            raise LiveRequestError("timeout") from error
        except httpx.RequestError as error:
            raise LiveRequestError("network_error") from error

        try:
            if 300 <= response.status_code < 400:
                raise LiveRequestError("redirect_rejected")
            content = bytearray()
            for chunk in response.iter_bytes():
                if len(content) + len(chunk) > self.max_response_bytes:
                    raise LiveRequestError("response_too_large")
                content.extend(chunk)
            body_bytes = bytes(content)
            response_headers = {
                str(key): str(value) for key, value in response.headers.items()
            }
            response_url = str(response.url)
        finally:
            response.close()

        json_body: Any = None
        content_type = response_headers.get("content-type", "")
        if "json" in content_type.lower() and body_bytes:
            try:
                json_body = json.loads(body_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                json_body = None
        return LiveResponse(
            status_code=response.status_code,
            headers=response_headers,
            content=body_bytes,
            json_body=json_body,
            url=response_url,
        )

    def close(self) -> None:
        self.client.close()


class SandboxSession:
    """One isolated bearer-token context for one synthetic sandbox identity."""

    def __init__(self, label: str, credentials: LiveCredentials, config: LiveScanConfig):
        self.label = label
        self.credentials = credentials
        self.config = config
        self.client = AuthorizedHttpClient(
            config.target_base_url,
            timeout_seconds=config.timeout_seconds,
            max_response_bytes=config.max_response_bytes,
            max_requests=config.max_requests_per_identity,
        )
        self.token: str | None = None
        self.user_id: str | None = None
        self.username: str | None = None

    def login(self) -> None:
        try:
            response = self.client.request(
                "POST",
                "/v1/auth/token",
                data={
                    "grant_type": "password",
                    "username": self.credentials.username,
                    "password": self.credentials.password,
                },
            )
        except LiveRequestError:
            raise
        if not response.successful or not isinstance(response.json_body, dict):
            raise AuthenticationError("token_authentication_failed")
        token = response.json_body.get("access_token")
        if not isinstance(token, str) or not token:
            raise AuthenticationError("token_authentication_failed")
        self.token = token

        try:
            identity_response = self.client.request(
                "GET",
                "/v1/auth/me",
                headers=self.auth_headers(),
            )
        except LiveRequestError:
            raise
        if not identity_response.successful or not isinstance(identity_response.json_body, dict):
            raise AuthenticationError("identity_verification_failed")
        if identity_response.json_body.get("username") != self.credentials.username:
            raise AuthenticationError("identity_verification_failed")
        self.user_id = identity_response.json_body.get("user_id")
        self.username = identity_response.json_body.get("username")

    def auth_headers(self) -> dict[str, str]:
        if not self.token:
            raise AuthenticationError("session_missing")
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }

    def request(self, method: str, path: str) -> LiveResponse:
        return self.client.request(method, path, headers=self.auth_headers())

    def logout(self) -> None:
        if self.token:
            try:
                self.client.request(
                    "POST",
                    "/v1/auth/logout",
                    headers=self.auth_headers(),
                )
            except LiveRequestError:
                pass
        self.token = None
        self.user_id = None
        self.username = None

    def close(self) -> None:
        self.client.close()


@dataclass
class LiveCheckResult:
    finding_type: str
    method: str
    path: str
    base_url: str
    classification: str
    request_evidence: dict[str, Any]
    response_evidence: dict[str, Any]
    details: dict[str, Any]
    poc_text: str
    title: str
    severity: str
    confidence: float
    explanation: str
    impact: str
    remediation: str
    endpoint_id: int | None = None
    error_code: str | None = None

    @property
    def endpoint_key(self) -> tuple[str, str, str, str]:
        return (self.method, self.path, self.base_url, self.finding_type)


def _schema_fields(schema: Any) -> set[str]:
    fields: set[str] = set()
    if isinstance(schema, Mapping):
        properties = schema.get("properties")
        if isinstance(properties, Mapping):
            fields.update(str(key) for key in properties)
        for key in ("items", "not"):
            if key in schema:
                fields.update(_schema_fields(schema[key]))
        for key in ("allOf", "oneOf", "anyOf"):
            values = schema.get(key)
            if isinstance(values, list):
                for value in values:
                    fields.update(_schema_fields(value))
        additional = schema.get("additionalProperties")
        if isinstance(additional, Mapping):
            fields.update(_schema_fields(additional))
    return fields


def _find_endpoint(
    endpoints: list[Mapping[str, Any]],
    method: str,
    path: str,
    target: str,
) -> Mapping[str, Any] | None:
    matches = [
        endpoint
        for endpoint in endpoints
        if str(endpoint.get("method", "")).upper() == method
        and endpoint.get("path") == path
        and (not endpoint.get("base_url") or endpoint.get("base_url") == target)
    ]
    return matches[0] if len(matches) == 1 else None


def _list_item_id(response: LiveResponse, id_field: str) -> str | None:
    if not response.successful or not isinstance(response.json_body, Mapping):
        return None
    items = response.json_body.get("items")
    if not isinstance(items, list):
        return None
    for item in items:
        if not isinstance(item, Mapping):
            continue
        value = item.get(id_field)
        if isinstance(value, str) and _ID_PATTERN.fullmatch(value):
            return value
    return None


def _concrete_path(template: str, object_id: str) -> str:
    return template.replace("{order_id}", object_id).replace("{report_id}", object_id)


def _matches_object(response: LiveResponse, id_field: str, object_id: str) -> bool:
    return (
        response.successful
        and isinstance(response.json_body, Mapping)
        and response.json_body.get(id_field) == object_id
    )


def _runtime_failure_status(status_code: int) -> bool:
    return status_code in {401, 403} or status_code >= 500


def _inconclusive(
    finding_type: str,
    endpoint: Mapping[str, Any] | None,
    target: str,
    error_code: str,
) -> LiveCheckResult:
    method = str(endpoint.get("method", "GET")) if endpoint else "GET"
    path = str(endpoint.get("path", "")) if endpoint else ""
    details = {
        "classification": "inconclusive",
        "analysis_basis": "authorized_runtime_http",
        "live_test": {"status": "inconclusive", "error_code": error_code},
    }
    return LiveCheckResult(
        finding_type=finding_type,
        method=method,
        path=path,
        base_url=target,
        classification="inconclusive",
        request_evidence={"source": "authorized_runtime_http", "status": "not_run"},
        response_evidence={"source": "authorized_runtime_http", "status": "not_run"},
        details=details,
        poc_text=make_poc_text("Live check could not complete safely."),
        title=f"Live check inconclusive for {method} {path}",
        severity="info",
        confidence=0.0,
        explanation="The authorized live check did not produce conclusive evidence.",
        impact="No confirmed runtime vulnerability was established.",
        remediation="Review the target configuration and rerun the authorized local test.",
        error_code=error_code,
    )


def _secure_not_confirmed(
    finding_type: str,
    endpoint: Mapping[str, Any],
    target: str,
    details: dict[str, Any],
    request_evidence: dict[str, Any],
    response_evidence: dict[str, Any],
    poc_text: str,
) -> LiveCheckResult:
    details = dict(details)
    details["classification"] = "secure/not confirmed"
    details.setdefault("analysis_basis", "authorized_runtime_http")
    return LiveCheckResult(
        finding_type=finding_type,
        method=str(endpoint.get("method", "GET")),
        path=str(endpoint.get("path", "")),
        base_url=target,
        classification="secure/not confirmed",
        request_evidence=request_evidence,
        response_evidence=response_evidence,
        details=details,
        poc_text=make_poc_text(poc_text),
        title=f"Secure control verified for {endpoint.get('method', 'GET')} {endpoint.get('path', '')}",
        severity="info",
        confidence=1.0,
        explanation="The authorized runtime check demonstrated the expected ownership or response control.",
        impact="No confirmed vulnerability was observed for this check.",
        remediation="Keep the ownership and response allow-list controls in place.",
    )


def _run_bola(
    endpoints: list[Mapping[str, Any]],
    target: str,
    session_a: SandboxSession,
    session_b: SandboxSession,
) -> LiveCheckResult:
    order_list = _find_endpoint(endpoints, "GET", ORDER_LIST_PATH, target)
    order_object = _find_endpoint(endpoints, "GET", ORDER_OBJECT_PATH, target)
    order_secure = _find_endpoint(endpoints, "GET", ORDER_SECURE_PATH, target)
    if not order_list or not order_object or not order_secure:
        return _inconclusive("BOLA_IDOR", order_object or order_list, target, "endpoint_not_found")

    try:
        list_response = session_a.request("GET", ORDER_LIST_PATH)
        object_id = _list_item_id(list_response, "order_id")
        if not object_id:
            return _inconclusive("BOLA_IDOR", order_object, target, "owner_object_not_found")

        object_path = _concrete_path(ORDER_OBJECT_PATH, object_id)
        secure_path = _concrete_path(ORDER_SECURE_PATH, object_id)
        baseline_response = session_a.request("GET", object_path)
        cross_response = session_b.request("GET", object_path)
        secure_response = session_b.request("GET", secure_path)
    except LiveRequestError as error:
        return _inconclusive("BOLA_IDOR", order_object, target, error.code)

    request_evidence = {
        "source": "authorized_runtime_http",
        "owner_list": make_request_evidence(
            method="GET",
            url=f"{target}{ORDER_LIST_PATH}",
            identity="user_a",
            object_id=None,
            status_code=list_response.status_code,
            headers=list_response.headers,
        ),
        "baseline": make_request_evidence(
            method="GET",
            url=f"{target}{object_path}",
            identity="user_a",
            object_id=object_id,
            status_code=baseline_response.status_code,
            headers=baseline_response.headers,
        ),
        "cross_user": make_request_evidence(
            method="GET",
            url=f"{target}{object_path}",
            identity="user_b",
            object_id=object_id,
            status_code=cross_response.status_code,
            headers=cross_response.headers,
        ),
        "secure_control": make_request_evidence(
            method="GET",
            url=f"{target}{secure_path}",
            identity="user_b",
            object_id=object_id,
            status_code=secure_response.status_code,
            headers=secure_response.headers,
        ),
    }
    response_evidence = {
        "source": "authorized_runtime_http",
        "owner_list": make_response_evidence(
            status_code=list_response.status_code,
            content_type=list_response.content_type,
            body=list_response.json_body,
        ),
        "baseline": make_response_evidence(
            status_code=baseline_response.status_code,
            content_type=baseline_response.content_type,
            body=baseline_response.json_body,
        ),
        "cross_user": make_response_evidence(
            status_code=cross_response.status_code,
            content_type=cross_response.content_type,
            body=cross_response.json_body,
        ),
        "secure_control": make_response_evidence(
            status_code=secure_response.status_code,
            content_type=secure_response.content_type,
            body=secure_response.json_body,
        ),
    }
    if any(
        _runtime_failure_status(response.status_code)
        for response in (baseline_response, cross_response, secure_response)
    ):
        return _inconclusive("BOLA_IDOR", order_object, target, "runtime_response_failure")

    details = {
        "classification": "confirmed",
        "analysis_basis": "authorized_runtime_http",
        "object_parameter": "order_id",
        "owner_identity": "user_a",
        "cross_user_identity": "user_b",
        "victim_object_id": object_id,
        "baseline_status": baseline_response.status_code,
        "cross_user_status": cross_response.status_code,
        "secure_control_status": secure_response.status_code,
        "secure_control_path": ORDER_SECURE_PATH,
        "cross_user_returned_same_object": _matches_object(
            cross_response, "order_id", object_id
        ),
    }
    poc = (
        "Authenticate as User A, obtain an owned order ID from /v1/orders, "
        "request that ID as User A, then request the same ID as User B. "
        "The secure control must return 404 for User B."
    )
    if (
        _matches_object(baseline_response, "order_id", object_id)
        and _matches_object(cross_response, "order_id", object_id)
        and secure_response.status_code == 404
    ):
        return LiveCheckResult(
            finding_type="BOLA_IDOR",
            method="GET",
            path=ORDER_OBJECT_PATH,
            base_url=target,
            classification="confirmed",
            request_evidence=request_evidence,
            response_evidence=response_evidence,
            details=details,
            poc_text=make_poc_text(poc),
            title="Confirmed BOLA/IDOR on order lookup",
            severity="high",
            confidence=0.97,
            explanation="User B received User A's object through the object-level endpoint while the secure control returned 404.",
            impact="An authenticated user can read another user's order object.",
            remediation="Enforce current-user ownership before returning an order.",
        )
    return _secure_not_confirmed(
        "BOLA_IDOR",
        order_object,
        target,
        details | {"classification": "secure/not confirmed"},
        request_evidence,
        response_evidence,
        poc,
    )


def _run_excessive_data(
    endpoints: list[Mapping[str, Any]],
    target: str,
    session_a: SandboxSession,
) -> LiveCheckResult:
    report_list = _find_endpoint(endpoints, "GET", REPORT_LIST_PATH, target)
    report_object = _find_endpoint(endpoints, "GET", REPORT_OBJECT_PATH, target)
    report_secure = _find_endpoint(endpoints, "GET", REPORT_SECURE_PATH, target)
    if not report_list or not report_object or not report_secure:
        return _inconclusive(
            "EXCESSIVE_DATA_EXPOSURE", report_object or report_list, target, "endpoint_not_found"
        )

    expected_fields = _schema_fields(report_object.get("response_schema"))
    if not expected_fields:
        return _inconclusive(
            "EXCESSIVE_DATA_EXPOSURE", report_object, target, "expected_schema_missing"
        )

    try:
        list_response = session_a.request("GET", REPORT_LIST_PATH)
        report_id = _list_item_id(list_response, "report_id")
        if not report_id:
            return _inconclusive(
                "EXCESSIVE_DATA_EXPOSURE", report_object, target, "owner_object_not_found"
            )
        object_path = _concrete_path(REPORT_OBJECT_PATH, report_id)
        secure_path = _concrete_path(REPORT_SECURE_PATH, report_id)
        actual_response = session_a.request("GET", object_path)
        secure_response = session_a.request("GET", secure_path)
    except LiveRequestError as error:
        return _inconclusive(
            "EXCESSIVE_DATA_EXPOSURE", report_object, target, error.code
        )

    if _runtime_failure_status(actual_response.status_code) or _runtime_failure_status(
        secure_response.status_code
    ):
        return _inconclusive(
            "EXCESSIVE_DATA_EXPOSURE", report_object, target, "runtime_response_failure"
        )

    actual_fields = set(body_fields(actual_response.json_body))
    unexpected_fields = sorted(actual_fields - expected_fields)
    secure_fields = set(body_fields(secure_response.json_body))
    request_evidence = {
        "source": "authorized_runtime_http",
        "owner_list": make_request_evidence(
            method="GET",
            url=f"{target}{REPORT_LIST_PATH}",
            identity="user_a",
            object_id=None,
            status_code=list_response.status_code,
            headers=list_response.headers,
        ),
        "actual": make_request_evidence(
            method="GET",
            url=f"{target}{object_path}",
            identity="user_a",
            object_id=report_id,
            status_code=actual_response.status_code,
            headers=actual_response.headers,
        ),
        "secure_control": make_request_evidence(
            method="GET",
            url=f"{target}{secure_path}",
            identity="user_a",
            object_id=report_id,
            status_code=secure_response.status_code,
            headers=secure_response.headers,
        ),
    }
    response_evidence = {
        "source": "authorized_runtime_http",
        "owner_list": make_response_evidence(
            status_code=list_response.status_code,
            content_type=list_response.content_type,
            body=list_response.json_body,
        ),
        "actual": make_response_evidence(
            status_code=actual_response.status_code,
            content_type=actual_response.content_type,
            body=actual_response.json_body,
            expected_fields=sorted(expected_fields),
            actual_fields=sorted(actual_fields),
            unexpected_fields=unexpected_fields,
            comparison="unexpected_fields_present" if unexpected_fields else "contract_match",
        ),
        "secure_control": make_response_evidence(
            status_code=secure_response.status_code,
            content_type=secure_response.content_type,
            body=secure_response.json_body,
            expected_fields=sorted(expected_fields),
            actual_fields=sorted(secure_fields),
            unexpected_fields=sorted(secure_fields - expected_fields),
            comparison="contract_match" if secure_fields <= expected_fields else "unexpected_fields_present",
        ),
    }
    details = {
        "classification": "confirmed" if unexpected_fields else "secure/not confirmed",
        "analysis_basis": "authorized_runtime_http",
        "expected_fields": sorted(expected_fields),
        "actual_fields": sorted(actual_fields),
        "unexpected_fields": unexpected_fields,
        "secure_control_status": secure_response.status_code,
        "secure_control_fields": sorted(secure_fields),
    }
    poc = (
        "Authenticate as User A, obtain a report ID from /v1/reports, request "
        "that report, and compare its top-level fields with the OpenAPI "
        "ReportClient contract. The secure control should return only the contract fields."
    )
    if unexpected_fields and actual_response.successful:
        return LiveCheckResult(
            finding_type="EXCESSIVE_DATA_EXPOSURE",
            method="GET",
            path=REPORT_OBJECT_PATH,
            base_url=target,
            classification="confirmed",
            request_evidence=request_evidence,
            response_evidence=response_evidence,
            details=details,
            poc_text=make_poc_text(poc),
            title="Confirmed excessive data exposure on report response",
            severity="high",
            confidence=0.98,
            explanation="The runtime response contains fields outside the intended ReportClient contract.",
            impact="Clients receive synthetic internal and sensitive fields that should not be exposed.",
            remediation="Serialize reports through an allow-listed client response model.",
        )
    return _secure_not_confirmed(
        "EXCESSIVE_DATA_EXPOSURE",
        report_object,
        target,
        details,
        request_evidence,
        response_evidence,
        poc,
    )


def fetch_local_openapi(
    target: str,
    *,
    timeout_seconds: float = 5.0,
    max_response_bytes: int = 1_048_576,
) -> dict[str, Any]:
    """Fetch only the explicitly allowlisted local OpenAPI document."""

    client = AuthorizedHttpClient(
        target,
        timeout_seconds=timeout_seconds,
        max_response_bytes=max_response_bytes,
        max_requests=1,
    )
    try:
        response = client.request("GET", "/openapi.json")
    finally:
        client.close()
    if not response.successful or not isinstance(response.json_body, dict):
        raise LiveRequestError("openapi_fetch_failed")
    return response.json_body


def inconclusive_results(
    endpoints: list[Mapping[str, Any]],
    target: str,
    error_code: str,
) -> list[LiveCheckResult]:
    """Create safe, non-persisted placeholders for a failed live phase."""

    order_endpoint = _find_endpoint(endpoints, "GET", ORDER_OBJECT_PATH, target)
    report_endpoint = _find_endpoint(endpoints, "GET", REPORT_OBJECT_PATH, target)
    return [
        _inconclusive("BOLA_IDOR", order_endpoint, target, error_code),
        _inconclusive(
            "EXCESSIVE_DATA_EXPOSURE", report_endpoint, target, error_code
        ),
    ]


def run_authorized_live_scan(
    spec: Mapping[str, Any],
    endpoints: list[Mapping[str, Any]],
    config: LiveScanConfig,
) -> list[LiveCheckResult]:
    """Run the two controlled sandbox checks without writing to the target."""

    target = TargetPolicy.validate_base_url(config.target_base_url)
    TargetPolicy.validate_spec_servers(spec)

    order_endpoint = _find_endpoint(endpoints, "GET", ORDER_OBJECT_PATH, target)
    report_endpoint = _find_endpoint(endpoints, "GET", REPORT_OBJECT_PATH, target)
    session_a = SandboxSession("user_a", config.user_a, config)
    session_b = SandboxSession("user_b", config.user_b, config)
    results: list[LiveCheckResult] = []
    runtime_error: str | None = None
    try:
        session_a.login()
        session_b.login()
        results.append(_run_bola(endpoints, target, session_a, session_b))
        results.append(_run_excessive_data(endpoints, target, session_a))
    except AuthenticationError:
        runtime_error = "authentication_failed"
    except LiveRequestError as error:
        runtime_error = error.code
    finally:
        session_a.logout()
        session_b.logout()
        session_a.close()
        session_b.close()

    if runtime_error:
        if not any(result.finding_type == "BOLA_IDOR" for result in results):
            results.append(_inconclusive("BOLA_IDOR", order_endpoint, target, runtime_error))
        if not any(result.finding_type == "EXCESSIVE_DATA_EXPOSURE" for result in results):
            results.append(
                _inconclusive(
                    "EXCESSIVE_DATA_EXPOSURE", report_endpoint, target, runtime_error
                )
            )
    return results


__all__ = [
    "ALLOWED_TARGET",
    "AuthenticationError",
    "AuthorizedHttpClient",
    "LiveCheckResult",
    "LiveCredentials",
    "LiveRequestError",
    "LiveResponse",
    "LiveScanConfig",
    "LiveScanError",
    "SandboxSession",
    "TargetPolicy",
    "TargetValidationError",
    "fetch_local_openapi",
    "inconclusive_results",
    "run_authorized_live_scan",
]
