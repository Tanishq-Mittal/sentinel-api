"""Tests for live evidence sanitization and bounded persistence helpers."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evidence import (  # noqa: E402
    bounded_json,
    make_request_evidence,
    make_response_evidence,
    poc_text,
    sanitize_headers,
    sanitize_url,
    sanitize_value,
)


def test_request_evidence_redacts_credentials_and_preserves_safe_headers() -> None:
    evidence = make_request_evidence(
        method="GET",
        url="http://127.0.0.1:5601/v1/orders/ord_a_1001?token=raw-query",
        identity="user_b",
        object_id="ord_a_1001",
        status_code=200,
        headers={
            "Authorization": "Bearer raw-bearer-token",
            "Cookie": "session=raw-cookie",
            "Set-Cookie": "session=raw-cookie",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    rendered = json.dumps(evidence)
    assert "raw-bearer-token" not in rendered
    assert "raw-cookie" not in rendered
    assert "raw-query" not in rendered
    assert evidence["headers"]["Authorization"] == "[REDACTED]"
    assert evidence["headers"]["Accept"] == "application/json"
    assert evidence["object_id"] == "ord_a_1001"


def test_response_evidence_redacts_sensitive_values_but_keeps_field_names() -> None:
    evidence = make_response_evidence(
        status_code=200,
        content_type="application/json",
        body={
            "report_id": "rep_a_3001",
            "owner_email": "user-a@sandbox.invalid",
            "internal_risk_score": 87,
            "payment_processor_reference": "SYNTHETIC-PAY-A-3001",
            "internal_audit_note": "raw internal note",
        },
        expected_fields=["report_id"],
        actual_fields=[
            "report_id",
            "owner_email",
            "internal_risk_score",
            "payment_processor_reference",
            "internal_audit_note",
        ],
        unexpected_fields=[
            "owner_email",
            "internal_risk_score",
            "payment_processor_reference",
            "internal_audit_note",
        ],
    )
    rendered = json.dumps(evidence)
    assert "user-a@sandbox.invalid" not in rendered
    assert "SYNTHETIC-PAY-A-3001" not in rendered
    assert "raw internal note" not in rendered
    assert set(evidence["field_names"]) == {
        "report_id",
        "owner_email",
        "internal_risk_score",
        "payment_processor_reference",
        "internal_audit_note",
    }
    assert evidence["unexpected_fields"] == [
        "internal_audit_note",
        "internal_risk_score",
        "owner_email",
        "payment_processor_reference",
    ]


def test_sanitize_value_redacts_nested_credentials() -> None:
    value = sanitize_value(
        {
            "password": "raw-password",
            "nested": {"api_key": "raw-key", "safe": "visible"},
            "items": [{"token": "raw-token"}],
        }
    )
    rendered = json.dumps(value)
    assert "raw-password" not in rendered
    assert "raw-key" not in rendered
    assert "raw-token" not in rendered
    assert value["nested"]["safe"] == "visible"


def test_bounded_json_remains_valid_and_does_not_leak_values() -> None:
    value = {"body": "x" * 10_000, "password": "raw-password"}
    rendered = bounded_json(value, max_chars=200)
    parsed = json.loads(rendered)
    assert isinstance(parsed, dict)
    assert "raw-password" not in rendered
    assert len(rendered) < 500


def test_url_and_poc_helpers_remove_query_credentials_and_tokens() -> None:
    assert sanitize_url("http://user:pass@127.0.0.1:5601/v1/orders?token=raw") == (
        "http://[REDACTED]@127.0.0.1:5601/v1/orders"
    )
    safe_poc = poc_text("Use Bearer raw-token with password=raw-password")
    assert "raw-token" not in safe_poc
    assert "raw-password" not in safe_poc


def test_safe_headers_only_contain_allowlisted_or_redacted_names() -> None:
    headers = sanitize_headers(
        {
            "Authorization": "Bearer token",
            "X-Internal-Debug": "secret",
            "Accept": "application/json",
        }
    )
    assert headers == {
        "Authorization": "[REDACTED]",
        "Accept": "application/json",
    }
