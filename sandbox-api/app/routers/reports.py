"""Synthetic report endpoints for excessive-data-exposure testing."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, status
from fastapi.responses import JSONResponse

from ..auth import UserAccount, get_current_user
from ..fixtures import (
    FixtureStore,
    client_report,
    excessive_report,
    get_fixture_store,
)
from ..schemas import ReportClient, ReportListResponse


router = APIRouter(tags=["reports"])


def _report_or_404(store: FixtureStore, report_id: str):
    record = store.reports.get(report_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    return record


@router.get(
    "/v1/reports",
    response_model=ReportListResponse,
    operation_id="list_reports_for_current_user",
    summary="List the current user's reports",
    responses={401: {"description": "Invalid or expired authentication"}},
)
def list_reports_for_current_user(
    user: UserAccount = Depends(get_current_user),
    store: FixtureStore = Depends(get_fixture_store),
) -> ReportListResponse:
    records = store.reports_for_user(user.user_id)
    items = [ReportClient(**client_report(record)) for record in records]
    return ReportListResponse(items=items, count=len(items))


@router.get(
    "/v1/reports/{report_id}",
    response_model=ReportClient,
    operation_id="get_report_excessive_data_fixture",
    summary="Get a report (intentional excessive-data fixture)",
    description=(
        "Authorized local fixture only. The OpenAPI contract documents ReportClient, "
        "but this endpoint intentionally returns four additional synthetic internal fields."
    ),
    responses={
        200: {"description": "Current user's report with intentional extra fields"},
        401: {"description": "Invalid or expired authentication"},
        404: {"description": "Report does not exist or is not owned by the current user"},
    },
    openapi_extra={
        "x-sentinel-test-intent": "excessive-data-exposure",
        "x-sentinel-expected-response-schema": "#/components/schemas/ReportClient",
        "x-sentinel-actual-extra-fields": [
            "owner_email",
            "internal_risk_score",
            "payment_processor_reference",
            "internal_audit_note",
        ],
    },
)
def get_report_excessive_data_fixture(
    report_id: str = Path(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"),
    user: UserAccount = Depends(get_current_user),
    store: FixtureStore = Depends(get_fixture_store),
):
    record = _report_or_404(store, report_id)
    if record.owner_user_id != user.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    # Return a raw response so the extra fields intentionally escape response filtering.
    return JSONResponse(content=excessive_report(record))


@router.get(
    "/v1/me/reports/{report_id}",
    response_model=ReportClient,
    operation_id="get_owned_report_secure",
    summary="Get the current user's report by ID",
    description=(
        "Secure control endpoint. It returns exactly the intended ReportClient fields "
        "and returns 404 for another user's report."
    ),
    responses={
        200: {"description": "Current user's contract-only report"},
        401: {"description": "Invalid or expired authentication"},
        404: {"description": "Report does not exist or is not owned by the current user"},
    },
    openapi_extra={
        "x-sentinel-test-intent": "excessive-data-secure-control",
        "x-sentinel-ownership-check": "current-user",
        "x-sentinel-expected-response-schema": "#/components/schemas/ReportClient",
    },
)
def get_owned_report_secure(
    report_id: str = Path(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"),
    user: UserAccount = Depends(get_current_user),
    store: FixtureStore = Depends(get_fixture_store),
) -> ReportClient:
    record = _report_or_404(store, report_id)
    if record.owner_user_id != user.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    return ReportClient(**client_report(record))
