"""Unit and local-sandbox tests for the authorized live scanner adapter."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import sys
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import server  # noqa: E402
from evidence import make_request_evidence, make_response_evidence  # noqa: E402
from live_scanner import (  # noqa: E402
    AuthorizedHttpClient,
    LiveCheckResult,
    LiveCredentials,
    LiveRequestError,
    LiveScanConfig,
    SandboxSession,
    inconclusive_results,
    run_authorized_live_scan,
)


TARGET = "http://127.0.0.1:5601"
USER_A = LiveCredentials("sandbox-user-a", "local-sandbox-a-only!")
USER_B = LiveCredentials("sandbox-user-b", "local-sandbox-b-only!")


def local_config(**overrides) -> LiveScanConfig:
    values = {
        "target_base_url": TARGET,
        "user_a": USER_A,
        "user_b": USER_B,
    }
    values.update(overrides)
    return LiveScanConfig(**values)


def local_spec_and_endpoints():
    try:
        with httpx.Client(trust_env=False, timeout=5.0) as client:
            response = client.get(f"{TARGET}/openapi.json")
    except httpx.RequestError as error:
        pytest.skip(f"Local sandbox is unavailable: {type(error).__name__}")
    if response.status_code != 200:
        pytest.skip("Local sandbox OpenAPI is unavailable")
    return response.json(), server.extract_endpoints(response.json())


def test_local_sandbox_authenticates_both_users_with_separate_tokens() -> None:
    config = local_config()
    session_a = SandboxSession("user_a", config.user_a, config)
    session_b = SandboxSession("user_b", config.user_b, config)
    try:
        session_a.login()
        session_b.login()
        assert session_a.token
        assert session_b.token
        assert session_a.token != session_b.token
        assert session_a.username == "sandbox-user-a"
        assert session_b.username == "sandbox-user-b"
    finally:
        session_a.logout()
        session_b.logout()
        session_a.close()
        session_b.close()


def test_local_sandbox_confirms_bola_and_excessive_data() -> None:
    spec, endpoints = local_spec_and_endpoints()
    results = run_authorized_live_scan(spec, endpoints, local_config())
    by_type = {result.finding_type: result for result in results}

    assert by_type["BOLA_IDOR"].classification == "confirmed"
    assert by_type["BOLA_IDOR"].details["analysis_basis"] == "authorized_runtime_http"
    assert by_type["BOLA_IDOR"].details["secure_control_status"] == 404
    assert by_type["BOLA_IDOR"].details["victim_object_id"].startswith("ord_a_")

    excessive = by_type["EXCESSIVE_DATA_EXPOSURE"]
    assert excessive.classification == "confirmed"
    assert set(excessive.details["unexpected_fields"]) == {
        "owner_email",
        "internal_risk_score",
        "payment_processor_reference",
        "internal_audit_note",
    }
    assert set(excessive.details["secure_control_fields"]) == {
        "report_id",
        "title",
        "status",
        "period",
        "summary",
    }


def test_secure_controls_are_not_separate_vulnerability_findings() -> None:
    spec, endpoints = local_spec_and_endpoints()
    results = run_authorized_live_scan(spec, endpoints, local_config())
    assert len([result for result in results if result.classification == "confirmed"]) == 2
    assert all(result.finding_type in {"BOLA_IDOR", "EXCESSIVE_DATA_EXPOSURE"} for result in results)


def test_save_live_scan_uses_existing_tables_without_credentials(monkeypatch) -> None:
    spec, _ = local_spec_and_endpoints()
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    schema_path = Path(__file__).resolve().parents[2] / "database" / "schema.sql"
    connection.executescript(schema_path.read_text(encoding="utf-8"))

    @contextlib.contextmanager
    def in_memory_session(write=False):
        if write:
            with connection:
                yield connection
        else:
            yield connection

    monkeypatch.setattr(server, "database_session", in_memory_session)
    try:
        result = server.save_live_scan(
            {
                "spec": spec,
                "target_base_url": TARGET,
                "user_a": {
                    "username": USER_A.username,
                    "password": USER_A.password,
                },
                "user_b": {
                    "username": USER_B.username,
                    "password": USER_B.password,
                },
            }
        )
        assert result["status"] == "completed"
        confirmed = [
            finding
            for finding in result["findings"]
            if finding["details"].get("classification") == "confirmed"
        ]
        assert {finding["finding_type"] for finding in confirmed} == {
            "BOLA_IDOR",
            "EXCESSIVE_DATA_EXPOSURE",
        }
        assert not any(
            finding["path"] == "/v1/me/orders/{order_id}"
            and finding["finding_type"] == "BOLA_IDOR"
            for finding in result["findings"]
        )
        assert not any(
            finding["path"] == "/v1/me/reports/{report_id}"
            and finding["finding_type"] == "EXCESSIVE_DATA_EXPOSURE"
            for finding in result["findings"]
        )
        rows = connection.execute(
            "SELECT endpoint_id, finding_type, COUNT(*) AS count "
            "FROM findings GROUP BY endpoint_id, finding_type HAVING COUNT(*) > 1"
        ).fetchall()
        assert rows == []
        stored_text = "\n".join(
            str(value)
            for row in connection.execute(
                "SELECT request_evidence_json, response_evidence_json, poc_text, details_json "
                "FROM findings"
            ).fetchall()
            for value in row
        )
        assert USER_A.password not in stored_text
        assert USER_B.password not in stored_text
        assert "Bearer sandbox_" not in stored_text
    finally:
        connection.close()


def make_mock_client(handler, *, max_response_bytes: int = 1024) -> AuthorizedHttpClient:
    return AuthorizedHttpClient(
        TARGET,
        timeout_seconds=1,
        max_response_bytes=max_response_bytes,
        max_requests=5,
        transport=httpx.MockTransport(handler),
    )


def test_redirects_are_rejected_without_following() -> None:
    def handler(request):
        return httpx.Response(
            302,
            headers={"location": "https://external.example/steal"},
            request=request,
        )

    client = make_mock_client(handler)
    try:
        with pytest.raises(LiveRequestError) as error:
            client.request("GET", "/health")
        assert error.value.code == "redirect_rejected"
    finally:
        client.close()


def test_timeout_is_reported_as_a_live_request_error() -> None:
    def handler(request):
        raise httpx.ReadTimeout("simulated timeout", request=request)

    client = make_mock_client(handler)
    try:
        with pytest.raises(LiveRequestError) as error:
            client.request("GET", "/health")
        assert error.value.code == "timeout"
    finally:
        client.close()


def test_response_size_limit_is_enforced() -> None:
    def handler(request):
        return httpx.Response(
            200,
            content=b"x" * 100,
            headers={"content-type": "application/json"},
            request=request,
        )

    client = make_mock_client(handler, max_response_bytes=10)
    try:
        with pytest.raises(LiveRequestError) as error:
            client.request("GET", "/health")
        assert error.value.code == "response_too_large"
    finally:
        client.close()


def test_proxy_environment_is_ignored(monkeypatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://external.example:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://external.example:8080")

    def handler(request):
        return httpx.Response(200, json={"status": "ok"}, request=request)

    client = make_mock_client(handler)
    try:
        assert client.client.trust_env is False
        response = client.request("GET", "/health")
        assert response.status_code == 200
    finally:
        client.close()


def create_findings_table() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        """
        CREATE TABLE findings (
            finding_id INTEGER PRIMARY KEY,
            scan_id INTEGER NOT NULL,
            endpoint_id INTEGER,
            finding_type TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            request_evidence_json TEXT,
            response_evidence_json TEXT,
            poc_text TEXT,
            details_json TEXT,
            explanation TEXT,
            impact TEXT,
            remediation TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    return connection


def sample_heuristic_item() -> dict:
    return {
        "endpoint_id": 1,
        "finding_type": "BOLA_IDOR",
        "title": "Object-level authorization requires review",
        "severity": "medium",
        "confidence": 0.66,
        "request_evidence": {"source": "OpenAPI specification"},
        "response_evidence": {"source": "OpenAPI specification"},
        "poc_text": "Static review",
        "details": {"analysis_basis": "OpenAPI path parameter"},
        "explanation": "Static explanation",
        "impact": "Static impact",
        "remediation": "Static remediation",
    }


def sample_endpoint() -> dict:
    return {
        "endpoint_id": 1,
        "method": "GET",
        "path": "/v1/orders/{order_id}",
        "base_url": TARGET,
    }


def test_merging_confirmed_result_does_not_duplicate_finding() -> None:
    connection = create_findings_table()
    result = LiveCheckResult(
        finding_type="BOLA_IDOR",
        method="GET",
        path="/v1/orders/{order_id}",
        base_url=TARGET,
        classification="confirmed",
        request_evidence=make_request_evidence(
            method="GET",
            url=f"{TARGET}/v1/orders/ord_a_1001",
            identity="user_b",
            object_id="ord_a_1001",
            status_code=200,
            headers={"Authorization": "Bearer raw-token"},
        ),
        response_evidence=make_response_evidence(
            status_code=200,
            content_type="application/json",
            body={"order_id": "ord_a_1001"},
        ),
        details={
            "classification": "confirmed",
            "analysis_basis": "authorized_runtime_http",
        },
        poc_text="Authorized local reproduction",
        title="Confirmed BOLA/IDOR",
        severity="high",
        confidence=0.97,
        explanation="Confirmed",
        impact="Impact",
        remediation="Fix ownership",
    )
    try:
        server._persist_live_findings(
            connection,
            1,
            [sample_endpoint()],
            [sample_heuristic_item()],
            [result],
            "2026-01-01T00:00:00Z",
        )
        rows = connection.execute(
            "SELECT finding_type, confidence, request_evidence_json, details_json FROM findings"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "BOLA_IDOR"
        assert rows[0][1] == 0.97
        assert "raw-token" not in rows[0][2]
        assert json.loads(rows[0][3])["classification"] == "confirmed"
    finally:
        connection.close()


def test_inconclusive_runtime_preserves_heuristic_without_claiming_confirmation() -> None:
    connection = create_findings_table()
    result = inconclusive_results([sample_endpoint()], TARGET, "timeout")[0]
    try:
        server._persist_live_findings(
            connection,
            1,
            [sample_endpoint()],
            [sample_heuristic_item()],
            [result],
            "2026-01-01T00:00:00Z",
        )
        row = connection.execute(
            "SELECT confidence, details_json FROM findings"
        ).fetchone()
        assert row[0] == 0.66
        details = json.loads(row[1])
        assert details["classification"] == "heuristic"
        assert details["live_test"]["status"] == "inconclusive"
    finally:
        connection.close()


def start_handler_server() -> tuple[ThreadingHTTPServer, threading.Thread]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.SentinelHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread


def stop_handler_server(httpd: ThreadingHTTPServer, thread: threading.Thread) -> None:
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)


def test_existing_static_post_route_still_calls_static_save() -> None:
    httpd, thread = start_handler_server()
    try:
        boundary = "----sentinel-test-boundary"
        body = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="spec"; filename="test.json"\r\n'
            "Content-Type: application/json\r\n\r\n"
            "{}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        with patch.object(server, "save_scan", return_value={"scan_id": 123}) as save_mock:
            connection = HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=5)
            connection.request(
                "POST",
                "/api/scans",
                body=body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
            response = connection.getresponse()
            assert response.status == 201
            assert json.loads(response.read()) == {"scan_id": 123}
            save_mock.assert_called_once()
            connection.close()
    finally:
        stop_handler_server(httpd, thread)


def test_live_route_is_separate_opt_in_endpoint() -> None:
    httpd, thread = start_handler_server()
    try:
        payload = {
            "target_base_url": TARGET,
            "spec": {"openapi": "3.0.3", "paths": {}},
            "user_a": {"username": "a", "password": "a"},
            "user_b": {"username": "b", "password": "b"},
        }
        with patch.object(server, "save_live_scan", return_value={"scan_id": 456}) as live_mock:
            connection = HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=5)
            connection.request(
                "POST",
                "/api/scans/live",
                body=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            assert response.status == 201
            assert json.loads(response.read()) == {"scan_id": 456}
            live_mock.assert_called_once()
            connection.close()
    finally:
        stop_handler_server(httpd, thread)
