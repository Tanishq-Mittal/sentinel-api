"""BOLA/IDOR behavior tests for the local sandbox."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


BASE_URL = "http://127.0.0.1:5601"
USER_A = ("sandbox-user-a", "local-sandbox-a-only!")
USER_B = ("sandbox-user-b", "local-sandbox-b-only!")


def token(client: TestClient, credentials: tuple[str, str]) -> str:
    response = client.post(
        "/v1/auth/token",
        data={"username": credentials[0], "password": credentials[1]},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def auth_headers(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


def test_lists_are_owner_scoped() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        token_a = token(client, USER_A)
        token_b = token(client, USER_B)

        response_a = client.get("/v1/orders", headers=auth_headers(token_a))
        response_b = client.get("/v1/orders", headers=auth_headers(token_b))

        assert response_a.status_code == 200
        assert response_b.status_code == 200
        assert {item["order_id"] for item in response_a.json()["items"]} == {
            "ord_a_1001",
            "ord_a_1002",
        }
        assert {item["order_id"] for item in response_b.json()["items"]} == {
            "ord_b_2001",
            "ord_b_2002",
        }


def test_user_a_can_access_own_order() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        headers = auth_headers(token(client, USER_A))
        response = client.get("/v1/orders/ord_a_1001", headers=headers)

        assert response.status_code == 200
        assert response.json()["order_id"] == "ord_a_1001"
        assert "owner_id" not in response.json()


def test_user_b_can_access_user_a_order_through_vulnerable_endpoint() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        headers = auth_headers(token(client, USER_B))
        response = client.get("/v1/orders/ord_a_1001", headers=headers)

        assert response.status_code == 200
        assert response.json()["order_id"] == "ord_a_1001"


def test_secure_order_endpoint_hides_foreign_order() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        headers = auth_headers(token(client, USER_B))
        response = client.get("/v1/me/orders/ord_a_1001", headers=headers)

        assert response.status_code == 404
        assert response.json() == {"detail": "Order not found"}


def test_secure_order_endpoint_allows_own_order() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        headers = auth_headers(token(client, USER_A))
        response = client.get("/v1/me/orders/ord_a_1001", headers=headers)

        assert response.status_code == 200
        assert response.json()["order_id"] == "ord_a_1001"
