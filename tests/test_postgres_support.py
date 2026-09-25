"""Tests for the SQLite fallback and PostgreSQL adapter surface."""

from __future__ import annotations

import contextlib
import os
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import server  # noqa: E402
from db import Database, DatabaseError, Session, adapt_sql  # noqa: E402


def sqlite_schema() -> str:
    return (Path(__file__).resolve().parents[2] / "database" / "schema.sql").read_text(
        encoding="utf-8"
    )


def test_database_url_selects_postgres_backend_without_connecting(monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:password@db.example/sentinel")
    database = Database.from_env()
    assert database.backend == "postgres"
    assert database.database_url is not None


def test_missing_database_url_uses_sqlite_fallback(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    path = tmp_path / "local.db"
    database = Database("sqlite", sqlite_path=path)
    assert database.backend == "sqlite"
    assert database.sqlite_path == path


def test_portable_sql_translation_preserves_quoted_question_mark() -> None:
    translated = adapt_sql(
        "SELECT * FROM findings WHERE title = ? AND note = '?'",
        "postgres",
    )
    assert "%s" in translated
    assert translated.count("%s") == 1
    assert "'?'" in translated
    assert adapt_sql("SELECT ?", "sqlite") == "SELECT ?"


class FakePostgresCursor:
    def __init__(self) -> None:
        self.sql = ""
        self.params = None
        self.closed = False

    def execute(self, sql, params=None):
        self.sql = sql
        self.params = params
        return self

    def fetchone(self):
        return {"spec_id": 42}

    def close(self):
        self.closed = True


class FakePostgresConnection:
    def __init__(self) -> None:
        self.cursor_instance = FakePostgresCursor()

    def cursor(self, row_factory=None):
        return self.cursor_instance


class SQLitePostgresCursor:
    """Execute portable SQL against SQLite while exposing psycopg-shaped rows."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.cursor: sqlite3.Cursor | None = None

    def execute(self, sql, params=None):
        if self.cursor is not None:
            raise AssertionError("cursor was reused before it was closed")
        self.cursor = self.connection.execute(sql.replace("%s", "?"), params or ())
        return self

    def fetchone(self):
        assert self.cursor is not None
        row = self.cursor.fetchone()
        self.close()
        return dict(row) if row is not None else None

    def fetchall(self):
        assert self.cursor is not None
        rows = self.cursor.fetchall()
        self.close()
        return [dict(row) for row in rows]

    def close(self):
        if self.cursor is not None:
            self.cursor.close()
            self.cursor = None


class SQLitePostgresConnection:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def cursor(self, row_factory=None):
        return SQLitePostgresCursor(self.connection)


def test_postgres_session_uses_returning_and_percent_placeholders() -> None:
    connection = FakePostgresConnection()
    session = Session(connection, "postgres")
    assert session.insert_id(
        "INSERT INTO openapi_specs (title) VALUES (?)",
        ("Example",),
        "spec_id",
    ) == 42
    assert "%s" in connection.cursor_instance.sql
    assert "?" not in connection.cursor_instance.sql
    assert connection.cursor_instance.params == ("Example",)


def test_sqlite_session_health_and_returning_insert(tmp_path) -> None:
    path = tmp_path / "fallback.db"
    connection = sqlite3.connect(path)
    connection.executescript(sqlite_schema())
    connection.close()

    database = Database("sqlite", sqlite_path=path)
    with database.session() as session:
        assert session.foreign_keys_enabled() is True
        assert "findings" in session.table_names()
        spec_id = session.insert_id(
            """
            INSERT INTO openapi_specs
                (source_type, source_url, title, spec_format, api_version, raw_content, content_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("upload", None, "Test", "openapi", "3.0.3", "{}", "hash", "2026-01-01T00:00:00Z"),
            "spec_id",
        )
        assert spec_id == 1
        health = session.health()
        assert health["backend"] == "sqlite"
        assert health["foreign_keys"] == 1


def test_sqlite_foreign_key_constraints_remain_enforced(tmp_path) -> None:
    path = tmp_path / "fk.db"
    connection = sqlite3.connect(path)
    connection.executescript(sqlite_schema())
    connection.close()
    database = Database("sqlite", sqlite_path=path)
    with database.session(write=True) as session:
        with pytest.raises(DatabaseError):
            session.execute(
                """
                INSERT INTO api_scans
                    (spec_id, scan_name, target_base_url, status, started_at, created_at)
                VALUES (?, ?, ?, 'running', ?, ?)
                """,
                (999, "Invalid", "target", "2026-01-01", "2026-01-01"),
            )
        assert session.execute("PRAGMA foreign_key_check").fetchall() == []


def test_sqlite_api_flow_keeps_existing_response_shapes(monkeypatch) -> None:
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.executescript(sqlite_schema())

    @contextlib.contextmanager
    def in_memory_session(write=False):
        if write:
            with connection:
                yield connection
        else:
            yield connection

    monkeypatch.setattr(server, "database_session", in_memory_session)
    try:
        scan = server.save_scan(
            "test-openapi.json",
            (Path(__file__).resolve().parents[2] / "test-openapi.json").read_bytes(),
        )
        assert scan["status"] == "completed"
        assert scan["endpoints"]
        assert scan["findings"]
        dashboard = server.dashboard_data()
        assert dashboard["latest"]["id"] == scan["id"]
        assert dashboard["totals"]["scans"] == 1
        report = server.report_data()
        assert report["scan"]["id"] == scan["id"]
        assert report["summary"]["finding_count"] == scan["finding_count"]
    finally:
        connection.close()


def test_dashboard_data_works_with_postgres_result_rows(monkeypatch) -> None:
    """Exercise dashboard COUNT rows and grouped rows with psycopg-shaped results."""
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(sqlite_schema())
    connection.execute(
        """
        INSERT INTO openapi_specs
            (spec_id, source_type, title, spec_format, api_version, raw_content, content_hash, created_at)
        VALUES (1, 'upload', 'Postgres regression', 'openapi', '3.0.3', '{}', 'hash', '2026-01-01T00:00:00Z')
        """
    )
    connection.execute(
        """
        INSERT INTO api_scans
            (scan_id, spec_id, scan_name, target_base_url, status, started_at, created_at)
        VALUES (1, 1, 'postgres-regression', 'http://example.test', 'completed',
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')
        """
    )
    connection.execute(
        """
        INSERT INTO api_endpoints
            (endpoint_id, scan_id, method, path, base_url, created_at)
        VALUES (1, 1, 'GET', '/health', 'http://example.test', '2026-01-01T00:00:00Z')
        """
    )
    connection.execute(
        """
        INSERT INTO findings
            (finding_id, scan_id, endpoint_id, finding_type, title, severity, confidence, created_at)
        VALUES (1, 1, 1, 'OTHER_SECURITY', 'Regression finding', 'low', 0.5,
                '2026-01-01T00:00:00Z')
        """
    )
    connection.commit()

    @contextlib.contextmanager
    def postgres_session(write=False):
        yield Session(SQLitePostgresConnection(connection), "postgres")

    monkeypatch.setattr(server, "database_session", postgres_session)
    try:
        dashboard = server.dashboard_data()
    finally:
        connection.close()

    assert dashboard["latest"]["id"] == 1
    assert dashboard["totals"] == {"scans": 1, "endpoints": 1, "findings": 1}
    assert dashboard["severity_distribution"]["low"] == 1
    assert dashboard["finding_type_distribution"]["OTHER_SECURITY"] == 1


def test_postgres_diagnostics_redact_connection_secrets(capsys) -> None:
    class Pool:
        @contextlib.contextmanager
        def connection(self):
            yield object()

    database = Database(
        "postgres",
        database_url="postgresql://diagnostic-user:diagnostic-password@db.example/sentinel",
    )
    database._pool = Pool()
    with pytest.raises(DatabaseError, match="PostgreSQL connection failed"):
        with database.session():
            raise RuntimeError(
                "password=diagnostic-password for user \"diagnostic-user\" "
                "postgresql://diagnostic-user:diagnostic-password@db.example/sentinel"
            )

    diagnostic = capsys.readouterr().err
    assert "RuntimeError" in diagnostic
    assert "diagnostic-user" not in diagnostic
    assert "diagnostic-password" not in diagnostic


@pytest.mark.skipif(
    not os.getenv("TEST_DATABASE_URL"),
    reason="Set TEST_DATABASE_URL to run PostgreSQL integration tests",
)
def test_postgres_connection_smoke() -> None:
    database = Database("postgres", database_url=os.environ["TEST_DATABASE_URL"])
    try:
        with database.session() as session:
            assert session.execute("SELECT 1").fetchone()[0] == 1
    finally:
        database.close()


@pytest.mark.skipif(
    not os.getenv("TEST_DATABASE_URL"),
    reason="Set TEST_DATABASE_URL to run PostgreSQL integration tests",
)
def test_postgres_api_routes_smoke(monkeypatch) -> None:
    database = Database("postgres", database_url=os.environ["TEST_DATABASE_URL"])

    @contextlib.contextmanager
    def postgres_session(write=False):
        with database.session(write=write) as session:
            yield session

    monkeypatch.setattr(server, "DB", database)
    monkeypatch.setattr(server, "database_session", postgres_session)
    try:
        server.init_database()
        scan = server.save_scan(
            "postgres-test-openapi.json",
            (Path(__file__).resolve().parents[2] / "test-openapi.json").read_bytes(),
        )
        assert scan["status"] == "completed"
        assert server.health_data()["ok"] is True
        assert server.dashboard_data()["latest"]["id"] == scan["id"]
        assert server.get_scan(scan["id"])["findings"]
        assert server.report_data()["summary"]["finding_count"] == scan["finding_count"]
    finally:
        database.close()
