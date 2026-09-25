"""OpenAPI and response-contract tests for the local sandbox."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


BASE_URL = "http://127.0.0.1:5601"


def test_openapi_declares_exact_local_server_and_bearer_security() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        response = client.get("/openapi.json")

    assert response.status_code == 200
    document = response.json()
    assert document["servers"] == [
        {
            "url": "http://127.0.0.1:5601",
            "description": "Explicit local sandbox server",
        }
    ]

    security_schemes = document["components"]["securitySchemes"]
    assert security_schemes["bearerAuth"]["type"] == "http"
    assert security_schemes["bearerAuth"]["scheme"] == "bearer"

    order_operation = document["paths"]["/v1/orders/{order_id}"]["get"]
    report_operation = document["paths"]["/v1/reports/{report_id}"]["get"]
    assert order_operation["x-sentinel-test-intent"] == "bola-idor"
    assert order_operation["x-sentinel-ownership-check"] == "none"
    assert report_operation["x-sentinel-test-intent"] == "excessive-data-exposure"
    assert report_operation["x-sentinel-actual-extra-fields"] == [
        "owner_email",
        "internal_risk_score",
        "payment_processor_reference",
        "internal_audit_note",
    ]

    report_schema = document["components"]["schemas"]["ReportClient"]
    assert report_schema["additionalProperties"] is False
    assert set(report_schema["properties"]) == {
        "report_id",
        "title",
        "status",
        "period",
        "summary",
    }


def test_documentation_routes_are_local_only() -> None:
    with TestClient(create_app(), base_url=BASE_URL) as client:
        docs = client.get("/docs")
        redoc = client.get("/redoc")
        assert docs.status_code == 200
        assert redoc.status_code == 200
        assert "https://" not in docs.text
        assert "https://" not in redoc.text
        assert "/openapi.json" in docs.text
        assert "/openapi.json" in redoc.text
        assert client.get("/docs/swagger-ui-bundle.js").status_code == 200
        assert client.get("/docs/redoc.standalone.js").status_code == 200
