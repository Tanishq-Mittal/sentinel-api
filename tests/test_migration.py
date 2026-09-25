"""Tests for the SQLite-to-PostgreSQL migration utility."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from migrate_sqlite_to_postgres import TABLE_COLUMNS, TABLE_IDS, MigrationError  # noqa: E402


def test_migration_order_and_id_columns_are_preserved() -> None:
    assert list(TABLE_COLUMNS) == [
        "openapi_specs",
        "api_scans",
        "api_endpoints",
        "findings",
    ]
    assert TABLE_IDS == {
        "openapi_specs": "spec_id",
        "api_scans": "scan_id",
        "api_endpoints": "endpoint_id",
        "findings": "finding_id",
    }


def test_migration_requires_database_url(tmp_path) -> None:
    from migrate_sqlite_to_postgres import migrate_database

    source = tmp_path / "source.db"
    source.touch()
    with pytest.raises(MigrationError, match="DATABASE_URL"):
        migrate_database(source, "")


def test_migration_rejects_missing_source(tmp_path) -> None:
    from migrate_sqlite_to_postgres import migrate_database

    with pytest.raises(MigrationError, match="source does not exist"):
        migrate_database(tmp_path / "missing.db", "postgresql://configured")


@pytest.mark.skipif(
    not os.getenv("TEST_DATABASE_URL"),
    reason="Set TEST_DATABASE_URL to run destructive migration integration tests",
)
def test_migration_imports_ids_and_relationships(tmp_path) -> None:
    from migrate_sqlite_to_postgres import migrate_database

    source = tmp_path / "source.db"
    connection = sqlite3.connect(source)
    connection.executescript(
        (Path(__file__).resolve().parents[2] / "database" / "schema.sql").read_text(
            encoding="utf-8"
        )
    )
    connection.execute(
        """
        INSERT INTO openapi_specs
            (spec_id, source_type, source_url, title, spec_format, api_version, raw_content, content_hash, created_at)
        VALUES (7, 'upload', NULL, 'Migration Test', 'openapi', '3.0.3', '{}', 'hash', '2026-01-01T00:00:00Z')
        """
    )
    connection.commit()
    connection.close()

    counts = migrate_database(
        source,
        os.environ["TEST_DATABASE_URL"],
        truncate=True,
    )
    assert counts == {
        "openapi_specs": 1,
        "api_scans": 0,
        "api_endpoints": 0,
        "findings": 0,
    }
