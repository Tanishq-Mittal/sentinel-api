"""Synthetic order endpoints for BOLA/IDOR testing."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, status
from fastapi.responses import JSONResponse

from ..auth import UserAccount, get_current_user
from ..fixtures import FixtureStore, get_fixture_store, public_order
from ..schemas import OrderClient, OrderListResponse


router = APIRouter(tags=["orders"])


def _order_or_404(store: FixtureStore, order_id: str):
    record = store.orders.get(order_id)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Order not found",
        )
    return record


@router.get(
    "/v1/orders",
    response_model=OrderListResponse,
    operation_id="list_orders_for_current_user",
    summary="List the current user's orders",
    responses={401: {"description": "Invalid or expired authentication"}},
)
def list_orders_for_current_user(
    user: UserAccount = Depends(get_current_user),
    store: FixtureStore = Depends(get_fixture_store),
) -> OrderListResponse:
    records = store.orders_for_user(user.user_id)
    items = [OrderClient(**public_order(record)) for record in records]
    return OrderListResponse(items=items, count=len(items))


@router.get(
    "/v1/orders/{order_id}",
    response_model=OrderClient,
    operation_id="get_order_by_id_vulnerable",
    summary="Get an order by ID (intentional BOLA fixture)",
    description=(
        "Authorized local fixture only. This operation intentionally looks up an order "
        "by ID without checking ownership so SentinelAPI can verify BOLA detection."
    ),
    responses={
        200: {"description": "Existing order, regardless of owner"},
        401: {"description": "Invalid or expired authentication"},
        404: {"description": "Order does not exist"},
    },
    openapi_extra={
        "x-sentinel-test-intent": "bola-idor",
        "x-sentinel-ownership-check": "none",
        "x-sentinel-object-id-field": "order_id",
    },
)
def get_order_by_id_vulnerable(
    order_id: str = Path(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"),
    user: UserAccount = Depends(get_current_user),
    store: FixtureStore = Depends(get_fixture_store),
):
    del user  # Authentication is required; ownership is intentionally not checked.
    record = _order_or_404(store, order_id)
    # Return a Response so FastAPI does not filter the intentionally returned object.
    return JSONResponse(content=public_order(record))


@router.get(
    "/v1/me/orders/{order_id}",
    response_model=OrderClient,
    operation_id="get_owned_order_secure",
    summary="Get the current user's order by ID",
    description=(
        "Secure control endpoint. It returns an order only when it belongs to the "
        "authenticated user and returns 404 for another user's order."
    ),
    responses={
        200: {"description": "Current user's order"},
        401: {"description": "Invalid or expired authentication"},
        404: {"description": "Order does not exist or is not owned by the current user"},
    },
    openapi_extra={
        "x-sentinel-test-intent": "bola-idor-secure-control",
        "x-sentinel-ownership-check": "current-user",
        "x-sentinel-object-id-field": "order_id",
    },
)
def get_owned_order_secure(
    order_id: str = Path(..., min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"),
    user: UserAccount = Depends(get_current_user),
    store: FixtureStore = Depends(get_fixture_store),
) -> OrderClient:
    record = _order_or_404(store, order_id)
    if record.owner_user_id != user.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Order not found",
        )
    return OrderClient(**public_order(record))
