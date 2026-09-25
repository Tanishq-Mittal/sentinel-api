"""Import the existing SQLite data into the PostgreSQL schema.

The utility preserves the four logical tables, explicit primary-key IDs, foreign-key
relationships, JSON/TEXT evidence, and timestamps. It refuses a non-empty destination
unless --truncate is explicitly supplied.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
from pathlib import Path
from typing import Any


TABLE_COLUMNS: dict[str, tuple[str, ...]] = {
    "openapi_specs": (
        "spec_id",
        "source_type",
        "source_url",
        "title",
        "spec_format",
        "api_version",
        "raw_content",
        "content_hash",
        "created_at",
    ),
    "api_scans": (
        "scan_id",
        "spec_id",
        "scan_name",
        "target_base_url",
        "status",
        "started_at",
        "completed_at",
        "error_message",
        "created_at",
    ),
    "api_endpoints": (
        "endpoint_id",
        "scan_id",
        "method",
        "path",
        "base_url",
        "operation_id",
        "parameters_json",
        "response_schema_json",
        "created_at",
    ),
    "findings": (
        "finding_id",
        "scan_id",
        "endpoint_id",
        "finding_type",
        "title",
        "severity",
        "confidence",
        "request_evidence_json",
        "response_evidence_json",
        "poc_text",
        "details_json",
        "explanation",
        "impact",
        "remediation",
        "created_at",
    ),
}
TABLE_IDS = {
    "openapi_specs": "spec_id",
    "api_scans": "scan_id",
    "api_endpoints": "endpoint_id",
    "findings": "finding_id",
}


class MigrationError(RuntimeError):
    """Raised when the source or destination cannot be migrated safely."""


def _require_psycopg() -> Any:
    try:
        import psycopg  # type: ignore
    except ImportError as error:
        raise MigrationError(
            "psycopg is required; install psycopg[binary,pool] before migrating"
        ) from error
    return psycopg


def _source_connection(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise MigrationError(f"SQLite source does not exist: {path}")
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    return connection


def _table_exists(cursor: Any, table: str) -> bool:
    cursor.execute(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = %s
              AND table_type = 'BASE TABLE'
        )
        """,
        (table,),
    )
    return bool(cursor.fetchone()[0])


def _reset_identity(cursor: Any, table: str, id_column: str, has_rows: bool) -> None:
    cursor.execute(
        "SELECT pg_get_serial_sequence(%s, %s)",
        (table, id_column),
    )
    sequence = cursor.fetchone()[0]
    if not sequence:
        return
    cursor.execute(
        f"""
        SELECT setval(
            %s::regclass,
            COALESCE((SELECT MAX({id_column}) FROM {table}), 1),
            %s
        )
        """,
        (sequence, has_rows),
    )


def migrate_database(
    sqlite_path: str | Path,
    database_url: str,
    *,
    truncate: bool = False,
) -> dict[str, int]:
    """Migrate data in foreign-key order and return inserted row counts."""

    if not database_url:
        raise MigrationError("DATABASE_URL is required")
    source = _source_connection(Path(sqlite_path))
    psycopg = _require_psycopg()
    target = None
    inserted: dict[str, int] = {}
    try:
        target = psycopg.connect(database_url)
        with target.transaction():
            with target.cursor() as cursor:
                for table in TABLE_COLUMNS:
                    if not _table_exists(cursor, table):
                        raise MigrationError(
                            f"PostgreSQL table is missing: {table}; run postgres_schema.sql first"
                        )
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = int(cursor.fetchone()[0])
                    if count and not truncate:
                        raise MigrationError(
                            f"PostgreSQL table {table} is not empty; use --truncate to replace it"
                        )

                if truncate:
                    cursor.execute(
                        "TRUNCATE TABLE findings, api_endpoints, api_scans, "
                        "openapi_specs RESTART IDENTITY CASCADE"
                    )

                for table, columns in TABLE_COLUMNS.items():
                    id_column = TABLE_IDS[table]
                    select_sql = (
                        f"SELECT {', '.join(columns)} FROM {table} ORDER BY {id_column}"
                    )
                    insert_sql = (
                        f"INSERT INTO {table} ({', '.join(columns)}) "
                        f"VALUES ({', '.join(['%s'] * len(columns))})"
                    )
                    rows = source.execute(select_sql).fetchall()
                    for row in rows:
                        cursor.execute(insert_sql, tuple(row[column] for column in columns))
                    inserted[table] = len(rows)
                    _reset_identity(cursor, table, id_column, bool(rows))
        target.commit()
        return inserted
    except Exception:
        if target is not None:
            target.rollback()
        raise
    finally:
        if target is not None:
            target.close()
        source.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sqlite-path",
        default=str(Path(__file__).resolve().parent.parent / "database" / "sentinelapi.db"),
        help="Path to the existing SQLite database",
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("DATABASE_URL"),
        help="PostgreSQL DATABASE_URL; defaults to the environment variable",
    )
    parser.add_argument(
        "--truncate",
        action="store_true",
        help="Replace existing destination table contents before importing",
    )
    args = parser.parse_args()
    if not args.database_url:
        parser.error("--database-url or DATABASE_URL is required")
    counts = migrate_database(
        args.sqlite_path,
        args.database_url,
        truncate=args.truncate,
    )
    print("Imported: " + ", ".join(f"{table}={count}" for table, count in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
