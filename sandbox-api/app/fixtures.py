"""Immutable, synthetic in-memory fixtures for the local sandbox."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request


@dataclass(frozen=True)
class UserSeed:
    user_id: str
    username: str
    display_name: str
    email: str


@dataclass(frozen=True)
class OrderRecord:
    order_id: str
    owner_user_id: str
    status: str
    total_cents: int
    currency: str
    item_count: int
    placed_at: str


@dataclass(frozen=True)
class ReportRecord:
    report_id: str
    owner_user_id: str
    title: str
    status: str
    period: str
    summary: str
    owner_email: str
    internal_risk_score: int
    payment_processor_reference: str
    internal_audit_note: str


USER_SEEDS: tuple[UserSeed, ...] = (
    UserSeed(
        user_id="usr_a",
        username="sandbox-user-a",
        display_name="Synthetic User A",
        email="user-a@sandbox.invalid",
    ),
    UserSeed(
        user_id="usr_b",
        username="sandbox-user-b",
        display_name="Synthetic User B",
        email="user-b@sandbox.invalid",
    ),
)


ORDER_FIXTURES: tuple[OrderRecord, ...] = (
    OrderRecord(
        order_id="ord_a_1001",
        owner_user_id="usr_a",
        status="paid",
        total_cents=2599,
        currency="USD",
        item_count=2,
        placed_at="2026-01-10T12:00:00Z",
    ),
    OrderRecord(
        order_id="ord_a_1002",
        owner_user_id="usr_a",
        status="shipped",
        total_cents=1499,
        currency="USD",
        item_count=1,
        placed_at="2026-01-11T12:00:00Z",
    ),
    OrderRecord(
        order_id="ord_b_2001",
        owner_user_id="usr_b",
        status="pending",
        total_cents=4999,
        currency="USD",
        item_count=3,
        placed_at="2026-01-12T12:00:00Z",
    ),
    OrderRecord(
        order_id="ord_b_2002",
        owner_user_id="usr_b",
        status="paid",
        total_cents=3299,
        currency="USD",
        item_count=1,
        placed_at="2026-01-13T12:00:00Z",
    ),
)


REPORT_FIXTURES: tuple[ReportRecord, ...] = (
    ReportRecord(
        report_id="rep_a_3001",
        owner_user_id="usr_a",
        title="Synthetic User A Report",
        status="ready",
        period="2026-Q1",
        summary="Synthetic report for User A",
        owner_email="user-a@sandbox.invalid",
        internal_risk_score=87,
        payment_processor_reference="SYNTHETIC-PAY-A-3001",
        internal_audit_note="SYNTHETIC INTERNAL RECORD",
    ),
    ReportRecord(
        report_id="rep_b_4001",
        owner_user_id="usr_b",
        title="Synthetic User B Report",
        status="ready",
        period="2026-Q1",
        summary="Synthetic report for User B",
        owner_email="user-b@sandbox.invalid",
        internal_risk_score=42,
        payment_processor_reference="SYNTHETIC-PAY-B-4001",
        internal_audit_note="SYNTHETIC INTERNAL RECORD",
    ),
)


class FixtureStore:
    """Read-only fixture lookup object; it has no persistence or mutation API."""

    def __init__(self) -> None:
        self.users = {user.user_id: user for user in USER_SEEDS}
        self.orders = {order.order_id: order for order in ORDER_FIXTURES}
        self.reports = {report.report_id: report for report in REPORT_FIXTURES}

    def orders_for_user(self, user_id: str) -> list[OrderRecord]:
        return [
            order
            for order in ORDER_FIXTURES
            if order.owner_user_id == user_id
        ]

    def reports_for_user(self, user_id: str) -> list[ReportRecord]:
        return [
            report
            for report in REPORT_FIXTURES
            if report.owner_user_id == user_id
        ]


def get_fixture_store(request: Request) -> FixtureStore:
    return request.app.state.fixtures


def public_order(record: OrderRecord) -> dict[str, object]:
    return {
        "order_id": record.order_id,
        "status": record.status,
        "total_cents": record.total_cents,
        "currency": record.currency,
        "item_count": record.item_count,
        "placed_at": record.placed_at,
    }


def client_report(record: ReportRecord) -> dict[str, object]:
    return {
        "report_id": record.report_id,
        "title": record.title,
        "status": record.status,
        "period": record.period,
        "summary": record.summary,
    }


def excessive_report(record: ReportRecord) -> dict[str, object]:
    payload = client_report(record)
    payload.update(
        {
            "owner_email": record.owner_email,
            "internal_risk_score": record.internal_risk_score,
            "payment_processor_reference": record.payment_processor_reference,
            "internal_audit_note": record.internal_audit_note,
        }
    )
    return payload
