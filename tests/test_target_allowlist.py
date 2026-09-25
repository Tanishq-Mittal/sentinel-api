"""Tests for the exact local target and OpenAPI server allowlist."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from live_scanner import (  # noqa: E402
    LiveCredentials,
    LiveScanConfig,
    TargetPolicy,
    TargetValidationError,
)


VALID_TARGET = "http://127.0.0.1:5601"


def credentials() -> tuple[LiveCredentials, LiveCredentials]:
    return (
        LiveCredentials("sandbox-user-a", "local-sandbox-a-only!"),
        LiveCredentials("sandbox-user-b", "local-sandbox-b-only!"),
    )


def test_exact_target_is_allowed() -> None:
    assert TargetPolicy.validate_base_url(VALID_TARGET) == VALID_TARGET
    assert TargetPolicy.validate_base_url(VALID_TARGET + "/") == VALID_TARGET


def test_other_ports_are_rejected() -> None:
    with pytest.raises(TargetValidationError):
        TargetPolicy.validate_base_url("http://127.0.0.1:5602")


def test_localhost_is_rejected() -> None:
    with pytest.raises(TargetValidationError):
        TargetPolicy.validate_base_url("http://localhost:5601")


def test_https_is_rejected() -> None:
    with pytest.raises(TargetValidationError):
        TargetPolicy.validate_base_url("https://127.0.0.1:5601")


@pytest.mark.parametrize(
    "target",
    [
        "http://[::1]:5601",
        "http://2130706433:5601",
        "http://127.1:5601",
        "http://127.0.0.1.:5601",
    ],
)
def test_alternate_loopback_forms_are_rejected(target: str) -> None:
    with pytest.raises(TargetValidationError):
        TargetPolicy.validate_base_url(target)


@pytest.mark.parametrize(
    "target",
    [
        "http://user:password@127.0.0.1:5601",
        "http://127.0.0.1:5601?x=1",
        "http://127.0.0.1:5601?",
        "http://127.0.0.1:5601#fragment",
        "http://127.0.0.1:5601#",
    ],
)
def test_url_credentials_query_and_fragment_are_rejected(target: str) -> None:
    with pytest.raises(TargetValidationError):
        TargetPolicy.validate_base_url(target)


def test_external_operation_server_is_rejected() -> None:
    spec = {
        "openapi": "3.0.3",
        "servers": [{"url": VALID_TARGET}],
        "paths": {
            "/v1/orders": {
                "get": {"responses": {"200": {"description": "ok"}}},
                "post": {
                    "servers": [{"url": "https://external.example"}],
                    "responses": {"200": {"description": "ok"}},
                },
            }
        },
    }
    with pytest.raises(TargetValidationError):
        TargetPolicy.validate_spec_servers(spec)


def test_invalid_target_does_not_construct_http_client(monkeypatch) -> None:
    import live_scanner

    constructed = []
    original_client = live_scanner.httpx.Client

    def tracking_client(*args, **kwargs):
        constructed.append(True)
        return original_client(*args, **kwargs)

    monkeypatch.setattr(live_scanner.httpx, "Client", tracking_client)
    user_a, user_b = credentials()
    with pytest.raises(TargetValidationError):
        LiveScanConfig("http://localhost:5601", user_a, user_b)
    assert constructed == []


def test_external_openapi_url_is_rejected_before_fetch(monkeypatch) -> None:
    import server

    called = []
    monkeypatch.setattr(
        server,
        "fetch_local_openapi",
        lambda *args, **kwargs: called.append(True),
    )
    with pytest.raises(ValueError):
        server.save_live_scan(
            {
                "openapi_url": "https://external.example/openapi.json",
                "target_base_url": VALID_TARGET,
                "user_a": {"username": "a", "password": "a"},
                "user_b": {"username": "b", "password": "b"},
            }
        )
    assert called == []


def test_only_known_local_request_paths_are_allowed() -> None:
    TargetPolicy.validate_request_url(VALID_TARGET + "/v1/orders")
    TargetPolicy.validate_request_url(VALID_TARGET + "/v1/orders/ord_a_1001")
    with pytest.raises(TargetValidationError):
        TargetPolicy.validate_request_url(VALID_TARGET + "/external")
