"""Excessive-data-exposure behavior tests for the local sandbox."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


BASE_URL = "http://127.0.0.1:5601"
USER_A = ("sandbox-user-a", "local-sandbox-a-only!")
USER_B = ("sandbox-user-b", "local-sandbox-b-only!")
EXPECTED_FIELDS = {"report_id", "title", "status", "period", "summary"}
EXTRA_FIELDS = {
    "owner_email",
    "internal_risk_score",
    "payment_processor_reference",
    "internal_audit_note",
}


def token(client: TestClient, credentials: tuple[str, str]) -> str:
    response = client.post(
        "/v1/auth/token",
        data={"username": credentials[0], "password": credentials[1]},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def auth_headers(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


def test_report_list_is_owner_scoped() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        response_a = client.get("/v1/reports", headers=auth_headers(token(client, USER_A)))
        response_b = client.get("/v1/reports", headers=auth_headers(token(client, USER_B)))

        assert {item["report_id"] for item in response_a.json()["items"]} == {"rep_a_3001"}
        assert {item["report_id"] for item in response_b.json()["items"]} == {"rep_b_4001"}


def test_vulnerable_report_contains_all_extra_synthetic_fields() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        response = client.get(
            "/v1/reports/rep_a_3001",
            headers=auth_headers(token(client, USER_A)),
        )

        assert response.status_code == 200
        body = response.json()
        assert EXPECTED_FIELDS.issubset(body)
        assert EXTRA_FIELDS.issubset(body)
        assert set(body) == EXPECTED_FIELDS | EXTRA_FIELDS
        assert body["owner_email"] == "user-a@sandbox.invalid"
        assert body["internal_risk_score"] == 87
        assert body["payment_processor_reference"].startswith("SYNTHETIC-")


def test_secure_report_contains_only_intended_fields() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        response = client.get(
            "/v1/me/reports/rep_a_3001",
            headers=auth_headers(token(client, USER_A)),
        )

        assert response.status_code == 200
        assert set(response.json()) == EXPECTED_FIELDS


def test_user_b_cannot_read_user_a_report() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        response = client.get(
            "/v1/reports/rep_a_3001",
            headers=auth_headers(token(client, USER_B)),
        )
        assert response.status_code == 404
