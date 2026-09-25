"""Local-only, method, and persistence-boundary tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import ConfigurationError, Settings
from app.main import create_app


BASE_URL = "http://127.0.0.1:5601"
SANDBOX_ROOT = Path(__file__).resolve().parents[1]


def login(client: TestClient) -> str:
    response = client.post(
        "/v1/auth/token",
        data={
            "username": "sandbox-user-a",
            "password": "local-sandbox-a-only!",
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_non_loopback_host_configuration_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="must be exactly 127.0.0.1"):
        Settings(host="0.0.0.0")


def test_invalid_host_header_is_rejected() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        response = client.get("/health", headers={"Host": "evil.example"})
        assert response.status_code == 400


def test_cors_allows_only_the_local_sentinel_origin() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        allowed = client.get(
            "/health",
            headers={"Origin": "http://127.0.0.1:5500"},
        )
        denied = client.get(
            "/health",
            headers={"Origin": "https://external.example"},
        )

        assert allowed.headers.get("access-control-allow-origin") == "http://127.0.0.1:5500"
        assert "access-control-allow-origin" not in denied.headers


def test_resource_mutating_methods_are_rejected() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        headers = {"Authorization": f"Bearer {login(client)}"}
        for method in ("put", "patch"):
            response = getattr(client, method)(
                "/v1/orders/ord_a_1001",
                headers=headers,
                json={"status": "changed"},
            )
            assert response.status_code == 405
        assert client.delete(
            "/v1/orders/ord_a_1001", headers=headers
        ).status_code == 405


def test_oversized_request_is_rejected() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        response = client.post(
            "/v1/auth/token",
            content=b"x" * (16 * 1024 + 1),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code == 413


def test_oversized_response_is_rejected() -> None:
    with TestClient(
        create_app(Settings(max_response_bytes=1024)),
        base_url=BASE_URL,
    ) as client:
        response = client.get("/openapi.json")
        assert response.status_code == 500
        assert response.json() == {"detail": "Response exceeds configured size limit"}


def test_sandbox_tree_contains_no_database_files() -> None:
    database_files = [
        path
        for path in SANDBOX_ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}
    ]
    assert database_files == []
