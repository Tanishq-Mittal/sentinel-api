"""Authentication and session tests for the local sandbox."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


BASE_URL = "http://127.0.0.1:5601"
USER_A = ("sandbox-user-a", "local-sandbox-a-only!")
USER_B = ("sandbox-user-b", "local-sandbox-b-only!")


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value


def make_client(clock: FakeClock | None = None, **overrides) -> TestClient:
    settings = Settings(**overrides)
    return TestClient(
        create_app(settings, clock=clock or FakeClock()),
        base_url=BASE_URL,
    )


def login(client: TestClient, credentials: tuple[str, str]) -> str:
    response = client.post(
        "/v1/auth/token",
        data={
            "grant_type": "password",
            "username": credentials[0],
            "password": credentials[1],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def test_both_users_authenticate_with_distinct_tokens() -> None:
    with make_client() as client:
        token_a = login(client, USER_A)
        token_b = login(client, USER_B)

        assert token_a != token_b
        assert not client.cookies
        assert client.post(
            "/v1/auth/token",
            data={"username": USER_A[0], "password": "wrong-password"},
        ).status_code == 401


def test_me_returns_the_correct_identity() -> None:
    with make_client() as client:
        token_a = login(client, USER_A)
        token_b = login(client, USER_B)

        response_a = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token_a}"})
        response_b = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token_b}"})

        assert response_a.status_code == 200
        assert response_a.json()["user_id"] == "usr_a"
        assert response_b.status_code == 200
        assert response_b.json()["user_id"] == "usr_b"


def test_invalid_token_is_generic_401() -> None:
    with make_client() as client:
        response = client.get(
            "/v1/auth/me",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid or expired authentication"}
        assert response.headers["www-authenticate"] == "Bearer"


def test_expired_token_is_rejected() -> None:
    clock = FakeClock()
    with make_client(clock=clock, session_ttl_seconds=10) as client:
        token = login(client, USER_A)
        assert client.get(
            "/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
        ).status_code == 200

        clock.value = 111.0
        response = client.get(
            "/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid or expired authentication"}


def test_logout_invalidates_only_its_own_session() -> None:
    with make_client() as client:
        token_a = login(client, USER_A)
        token_b = login(client, USER_B)
        headers_a = {"Authorization": f"Bearer {token_a}"}
        headers_b = {"Authorization": f"Bearer {token_b}"}

        assert client.post("/v1/auth/logout", headers=headers_a).status_code == 204
        assert client.get("/v1/auth/me", headers=headers_a).status_code == 401
        assert client.get("/v1/auth/me", headers=headers_b).status_code == 200


def test_sessions_are_in_memory_and_not_reused_by_a_new_app() -> None:
    with make_client() as first_client:
        token = login(first_client, USER_A)

    with make_client() as second_client:
        response = second_client.get(
            "/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401


def test_protected_routes_require_bearer_authentication() -> None:
    with make_client() as client:
        assert client.get("/v1/orders").status_code == 401
        assert client.get("/v1/reports").status_code == 401
