"""SQLite/PostgreSQL persistence adapter for SentinelAPI.

SQLite remains the local-development fallback. When DATABASE_URL is present, the
application uses a PostgreSQL connection pool through psycopg. The adapter keeps
SQLite-only details out of the API and migration code.
"""

from __future__ import annotations

import os
import re
import sqlite3
import sys
from contextlib import contextmanager, nullcontext
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable

try:  # Optional in local SQLite development.
    import psycopg  # type: ignore
    from psycopg.rows import dict_row  # type: ignore
except ImportError:  # pragma: no cover - exercised only without production dependency
    psycopg = None
    dict_row = None

try:  # Optional in local SQLite development.
    from psycopg_pool import ConnectionPool  # type: ignore
except ImportError:  # pragma: no cover - exercised only without production dependency
    ConnectionPool = None


DEFAULT_SQLITE_PATH = Path(__file__).resolve().parent.parent / "database" / "sentinelapi.db"
CANONICAL_TABLES = ("openapi_specs", "api_scans", "api_endpoints", "findings")
_DATABASE_DIAGNOSTIC_LIMIT = 1000
_DATABASE_URL_PATTERN = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s]+")
_DATABASE_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|authorization|cookie|credential|user|username|database_url)"
    r"\s*=\s*(?:'[^']*'|\"[^\"]*\"|[^\s,;)]+)"
)
_DATABASE_AUTH_PATTERN = re.compile(r"(?i)\b(?:Bearer|Basic)\s+[^\s,;]+")
_DATABASE_USER_TEXT_PATTERN = re.compile(
    r"(?i)(\b(?:user|username)\s+)(?:'[^']*'|\"[^\"]*\"|[^\s,;]+)"
)
_DATABASE_JWT_PATTERN = re.compile(
    r"\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b"
)
_DATABASE_SECRET_KEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")


class DatabaseError(RuntimeError):
    """A sanitized persistence error safe to expose through the API layer."""


def _redact_database_diagnostic(value: Any) -> str:
    """Make a database exception safe to print in the server terminal."""

    text = str(value)
    text = _DATABASE_URL_PATTERN.sub("[REDACTED_DATABASE_URL]", text)
    text = _DATABASE_SECRET_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group(1)}=[REDACTED]", text
    )
    text = _DATABASE_AUTH_PATTERN.sub("[REDACTED_AUTH]", text)
    text = _DATABASE_USER_TEXT_PATTERN.sub(r"\1[REDACTED]", text)
    text = _DATABASE_JWT_PATTERN.sub("[REDACTED_TOKEN]", text)
    text = _DATABASE_SECRET_KEY_PATTERN.sub("[REDACTED_TOKEN]", text)
    text = re.sub(
        r"(?i)(\bfor\s+user\s+)(?:'[^']*'|\"[^\"]*\"|[^\s,;]+)",
        r"\1[REDACTED]",
        text,
    )
    return " ".join(text.split())[:_DATABASE_DIAGNOSTIC_LIMIT]


def _log_database_exception(stage: str, error: BaseException) -> None:
    """Log the original exception type/message without connection secrets."""

    diagnostic = getattr(error, "diag", None)
    message = getattr(diagnostic, "message_primary", None) or str(error)
    exception_name = f"{type(error).__module__}.{type(error).__name__}"
    sqlstate = getattr(error, "sqlstate", None) or getattr(diagnostic, "sqlstate", None)
    suffix = f" sqlstate={_redact_database_diagnostic(sqlstate)}" if sqlstate else ""
    print(
        f"[database] {stage}: {exception_name}{suffix}: "
        f"{_redact_database_diagnostic(message)}",
        file=sys.stderr,
        flush=True,
    )


def legacy_sqlite_table_names(connection: Any) -> set[str]:
    """Read table names when a legacy test/consumer supplies raw sqlite3."""
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {str(row["name"]) for row in rows}


def legacy_sqlite_foreign_keys_enabled(connection: Any) -> bool:
    """Read SQLite FK state for legacy raw-connection callers."""
    return bool(connection.execute("PRAGMA foreign_keys").fetchone()[0])


def adapt_sql(sql: str, backend: str) -> str:
    """Translate portable ``?`` parameters to psycopg's ``%s`` parameters.

    Question marks inside quoted SQL literals are preserved. The application SQL
    uses ``?`` as a backend-neutral notation; only the PostgreSQL adapter sees the
    translated form.
    """

    if backend != "postgres" or "?" not in sql:
        return sql
    output: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote:
            output.append(char)
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    output.append(sql[index + 1])
                    index += 1
                else:
                    quote = None
        elif char in ("'", '"'):
            quote = char
            output.append(char)
        elif char == "?":
            output.append("%s")
        else:
            output.append(char)
        index += 1
    return "".join(output)


def _normalize_value(value: Any) -> Any:
    """Keep API response values stable across SQLite and psycopg."""

    if isinstance(value, datetime):
        normalized = value
        if normalized.tzinfo is None:
            normalized = normalized.replace(tzinfo=timezone.utc)
        return normalized.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, dict):
        return {str(key): _normalize_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_value(item) for item in value]
    return value


class ResultRow(dict[str, Any]):
    """Dictionary row with the positional access used by legacy SQL callers."""

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, (int, slice)):
            return tuple(self.values())[key]
        return super().__getitem__(key)


def _normalize_row(row: Any) -> Any:
    if row is None:
        return None
    if isinstance(row, dict):
        return ResultRow(
            (str(key), _normalize_value(value)) for key, value in row.items()
        )
    try:
        return ResultRow(
            (str(key), _normalize_value(row[key])) for key in row.keys()
        )
    except (AttributeError, TypeError):
        return row


class PostgresResult:
    """Small result wrapper that owns and closes a psycopg cursor."""

    def __init__(self, cursor: Any) -> None:
        self._cursor: Any | None = cursor

    def _close_cursor(self) -> None:
        cursor = self._cursor
        self._cursor = None
        if cursor is not None:
            try:
                cursor.close()
            except Exception as error:
                _log_database_exception("PostgreSQL cursor close", error)

    def fetchone(self) -> Any:
        if self._cursor is None:
            raise DatabaseError("Database result has already been consumed")
        try:
            row = self._cursor.fetchone()
        except Exception as error:
            _log_database_exception("PostgreSQL result read", error)
            raise DatabaseError("Database result read failed") from None
        finally:
            self._close_cursor()
        return _normalize_row(row)

    def fetchall(self) -> list[Any]:
        if self._cursor is None:
            raise DatabaseError("Database result has already been consumed")
        try:
            rows = self._cursor.fetchall()
        except Exception as error:
            _log_database_exception("PostgreSQL result read", error)
            raise DatabaseError("Database result read failed") from None
        finally:
            self._close_cursor()
        return [_normalize_row(row) for row in rows]

    def __iter__(self):
        return iter(self.fetchall())


class Session:
    """Uniform connection/session surface used by server.py."""

    def __init__(self, connection: Any, backend: str, *, sqlite_path: Path | None = None) -> None:
        self.connection = connection
        self.backend = backend
        self.sqlite_path = sqlite_path

    def execute(self, sql: str, params: Iterable[Any] | None = None) -> Any:
        statement = adapt_sql(sql, self.backend)
        values = tuple(params) if params is not None else ()
        if self.backend == "sqlite":
            try:
                return self.connection.execute(statement, values)
            except Exception as error:
                raise DatabaseError("Database operation failed") from error

        cursor = None
        try:
            cursor = self.connection.cursor(row_factory=dict_row)
            cursor.execute(statement, values or None)
            return PostgresResult(cursor)
        except Exception as error:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception:
                    pass
            _log_database_exception("PostgreSQL query", error)
            raise DatabaseError("Database operation failed") from None

    def insert_id(self, sql: str, params: Iterable[Any], id_column: str) -> int:
        result = self.execute(f"{sql.rstrip()} RETURNING {id_column}", params)
        row = result.fetchone()
        if not row:
            raise DatabaseError("Database insert did not return an identifier")
        try:
            return int(row[id_column])
        except (KeyError, IndexError, TypeError) as error:
            raise DatabaseError("Database insert did not return an identifier") from error

    def table_names(self) -> set[str]:
        if self.backend == "sqlite":
            rows = self.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        else:
            rows = self.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'
                """
            ).fetchall()
        if self.backend == "sqlite":
            return {str(row["name"]) for row in rows}
        return {str(row["table_name"]) for row in rows}

    def foreign_keys_enabled(self) -> bool:
        if self.backend == "sqlite":
            row = self.execute("PRAGMA foreign_keys").fetchone()
            return bool(row[0])
        # PostgreSQL enforces declared foreign keys transactionally.
        return True

    def describe(self) -> dict[str, Any]:
        if self.backend == "sqlite":
            path = self.sqlite_path or DEFAULT_SQLITE_PATH
            return {
                "backend": "sqlite",
                "database": path.name,
                "path": str(path),
            }
        row = self.execute(
            "SELECT current_database() AS database_name, current_user AS database_user"
        ).fetchone()
        return {
            "backend": "postgresql",
            "database": str(row["database_name"]),
            "path": "postgresql",
            "user": str(row["database_user"]),
        }

    def health(self) -> dict[str, Any]:
        self.execute("SELECT 1").fetchone()
        info = self.describe()
        info["foreign_keys"] = 1 if self.foreign_keys_enabled() else 0
        info["tables"] = sorted(self.table_names())
        return info


class Database:
    """Select PostgreSQL when configured, otherwise use the local SQLite file."""

    def __init__(
        self,
        backend: str,
        *,
        sqlite_path: Path | None = None,
        database_url: str | None = None,
    ) -> None:
        if backend not in {"sqlite", "postgres"}:
            raise ValueError(f"Unsupported database backend: {backend}")
        self.backend = backend
        self.sqlite_path = sqlite_path
        self.database_url = database_url
        self._pool: Any = None

    @classmethod
    def from_env(cls) -> "Database":
        database_url = os.getenv("DATABASE_URL")
        if database_url and database_url.strip():
            return cls("postgres", database_url=database_url)
        configured_path = os.getenv("SENTINEL_DB_PATH")
        path = Path(configured_path) if configured_path else DEFAULT_SQLITE_PATH
        return cls("sqlite", sqlite_path=path)

    @property
    def backend_label(self) -> str:
        return "PostgreSQL" if self.backend == "postgres" else "SQLite"

    def _open_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        if self.backend != "postgres":
            raise DatabaseError("PostgreSQL pool requested for SQLite backend")
        if psycopg is None or ConnectionPool is None:
            raise DatabaseError(
                "DATABASE_URL is set but psycopg[binary,pool] is not installed"
            )
        try:
            self._pool = ConnectionPool(
                self.database_url,
                min_size=1,
                max_size=10,
                open=False,
            )
            self._pool.open()
        except Exception as error:
            _log_database_exception("PostgreSQL pool setup", error)
            raise DatabaseError("PostgreSQL connection configuration failed") from None
        return self._pool

    @contextmanager
    def session(self, write: bool = False):
        if self.backend == "sqlite":
            path = self.sqlite_path or DEFAULT_SQLITE_PATH
            if not path.is_file():
                raise DatabaseError(f"SQLite database does not exist: {path}")
            connection = sqlite3.connect(str(path), timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            session = Session(connection, "sqlite", sqlite_path=path)
            try:
                if write:
                    with connection:
                        yield session
                else:
                    yield session
            finally:
                connection.close()
            return

        pool = self._open_pool()
        try:
            with pool.connection() as connection:
                transaction = connection.transaction() if write else nullcontext()
                with transaction:
                    yield Session(connection, "postgres")
        except DatabaseError:
            raise
        except Exception as error:
            _log_database_exception("PostgreSQL session", error)
            raise DatabaseError("PostgreSQL connection failed") from None

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
            self._pool = None


__all__ = [
    "CANONICAL_TABLES",
    "DEFAULT_SQLITE_PATH",
    "Database",
    "DatabaseError",
    "PostgresResult",
    "ResultRow",
    "Session",
    "adapt_sql",
    "legacy_sqlite_foreign_keys_enabled",
    "legacy_sqlite_table_names",
]
