"""Public response contracts used by the sandbox OpenAPI document."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserIdentity(StrictModel):
    user_id: str
    username: str
    display_name: str


class TokenResponse(StrictModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class OrderClient(StrictModel):
    order_id: str
    status: Literal["paid", "pending", "shipped"]
    total_cents: int = Field(ge=0)
    currency: str
    item_count: int = Field(ge=0)
    placed_at: str


class OrderListResponse(StrictModel):
    items: list[OrderClient]
    count: int = Field(ge=0)


class ReportClient(StrictModel):
    report_id: str
    title: str
    status: Literal["ready", "pending"]
    period: str
    summary: str


class ReportListResponse(StrictModel):
    items: list[ReportClient]
    count: int = Field(ge=0)
