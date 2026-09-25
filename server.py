import hashlib
import json
import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

try:
    from db import (
        Database,
        DatabaseError,
        legacy_sqlite_foreign_keys_enabled,
        legacy_sqlite_table_names,
    )
except ImportError:  # pragma: no cover - package-style import fallback
    from .db import (  # type: ignore
        Database,
        DatabaseError,
        legacy_sqlite_foreign_keys_enabled,
        legacy_sqlite_table_names,
    )

try:
    import yaml
except ImportError:
    yaml = None

try:
    from live_scanner import (
        LiveCredentials,
        LiveScanConfig,
        TargetPolicy,
        fetch_local_openapi,
        inconclusive_results,
        run_authorized_live_scan,
    )
except ImportError:  # pragma: no cover - package-style import fallback
    from .live_scanner import (  # type: ignore
        LiveCredentials,
        LiveScanConfig,
        TargetPolicy,
        fetch_local_openapi,
        inconclusive_results,
        run_authorized_live_scan,
    )


APP_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = APP_ROOT.parent
DB = Database.from_env()
DATABASE = DB.sqlite_path or Path("postgresql")
CANONICAL_TABLES = ("openapi_specs", "api_scans", "api_endpoints", "findings")
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 1}
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|authorization|cookie|credential|private[_-]?key|oauth)",
    re.IGNORECASE,
)
SENSITIVE_FIELD_PATTERN = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|"
    r"ssn|social[_-]?security|credit[_-]?card|card[_-]?number|email|phone|"
    r"internal|debug|balance|owner[_-]?id|account[_-]?status)",
    re.IGNORECASE,
)
OBJECT_PARAMETER_NAMES = {
    "id",
    "uuid",
    "account",
    "accountid",
    "user",
    "userid",
    "tenant",
    "tenantid",
    "order",
    "orderid",
    "report",
    "reportid",
    "customer",
    "customerid",
    "resource",
    "resourceid",
    "object",
    "objectid",
    "item",
    "itemid",
    "transaction",
    "transactionid",
    "project",
    "projectid",
    "invoice",
    "invoiceid",
    "document",
    "documentid",
}


class SentinelDatabaseError(RuntimeError):
    """Raised when the canonical database is unavailable or incomplete."""


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def redact_text(value):
    """Redact common credential forms before content reaches SQLite."""
    if not isinstance(value, str):
        return value
    value = re.sub(
        r"(?i)\b(Bearer|Basic)\s+[^\s,;]+",
        r"\1 [REDACTED]",
        value,
    )
    value = re.sub(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|"
        r"client[_-]?secret|authorization|cookie|credential)\s*([:=])\s*([^\s,;]+)",
        r"\1\2[REDACTED]",
        value,
    )
    value = re.sub(
        r"(?i)([?&](?:password|passwd|secret|token|api[_-]?key|access[_-]?key|"
        r"client[_-]?secret|authorization|cookie)=)[^&#\s]+",
        r"\1[REDACTED]",
        value,
    )
    value = re.sub(r"\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b", "[REDACTED]", value)
    value = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "[REDACTED]", value)
    value = re.sub(r"(?i)(https?://)[^/\s:@]+:[^@/\s]+@", r"\1[REDACTED]@", value)
    return value


def redact_value(value, key=None):
    """Recursively redact sensitive object members and credential-looking strings."""
    if key is not None and SENSITIVE_KEY_PATTERN.search(str(key)):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): redact_value(item_value, item_key) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def json_text(value):
    if value is None:
        return None
    return json.dumps(redact_value(value), ensure_ascii=False, sort_keys=True, default=str)


def decode_json(value):
    if not value:
        return None
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return value


def connection():
    """Return the configured database manager for legacy callers."""
    return DB


@contextmanager
def database_session(write=False):
    """Use a request-scoped SQLite or PostgreSQL session."""
    with DB.session(write=write) as db:
        yield db


def _table_names(db):
    if hasattr(db, "table_names"):
        return set(db.table_names())
    return legacy_sqlite_table_names(db)


def _foreign_keys_enabled(db):
    if hasattr(db, "foreign_keys_enabled"):
        return bool(db.foreign_keys_enabled())
    return legacy_sqlite_foreign_keys_enabled(db)


def _database_info(db):
    if hasattr(db, "describe"):
        return db.describe()
    return {
        "backend": "sqlite",
        "database": DATABASE.name,
        "path": str(DATABASE),
    }


def insert_returning_id(db, sql, params, id_column):
    """Insert a row portably and obtain its generated/explicit identifier."""
    row = db.execute(f"{sql.rstrip()} RETURNING {id_column}", params).fetchone()
    if not row:
        raise SentinelDatabaseError("Database insert did not return an identifier")
    try:
        return int(row[id_column])
    except (KeyError, IndexError, TypeError) as error:
        raise SentinelDatabaseError("Database insert did not return an identifier") from error


def init_database():
    """Validate the existing schema for the configured backend."""
    with database_session() as db:
        table_names = _table_names(db)
        missing = [table for table in CANONICAL_TABLES if table not in table_names]
        if missing:
            raise SentinelDatabaseError(
                "Canonical database is missing required tables: " + ", ".join(missing)
            )
        if not _foreign_keys_enabled(db):
            raise SentinelDatabaseError("Database foreign-key enforcement is disabled.")


def parse_spec(filename, content):
    suffix = Path(filename).suffix.lower()
    try:
        if suffix == ".json" or content.lstrip().startswith((b"{", b"[")):
            spec = json.loads(content.decode("utf-8"))
            file_format = "JSON"
        else:
            if yaml is None:
                raise ValueError("YAML support is unavailable. Install dependencies first.")
            spec = yaml.safe_load(content.decode("utf-8"))
            file_format = "YAML"
    except Exception as error:
        raise ValueError(f"Could not parse OpenAPI file: {error}") from error

    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        raise ValueError("The file must be a valid Swagger/OpenAPI document with a paths object.")

    if "openapi" in spec:
        spec_format = "openapi"
        api_version = str(spec.get("openapi") or "Unknown")
    elif "swagger" in spec:
        spec_format = "swagger"
        api_version = str(spec.get("swagger") or "Unknown")
    else:
        raise ValueError("The file must contain an openapi or swagger version.")

    info = spec.get("info") or {}
    title = redact_text(str(info.get("title") or Path(filename).stem))
    redacted_spec = redact_value(spec)
    raw_content = json.dumps(redacted_spec, ensure_ascii=False, indent=2, sort_keys=True)
    return spec, {
        "file_format": file_format,
        "spec_format": spec_format,
        "api_version": api_version,
        "title": title,
        "raw_content": raw_content,
    }


def get_base_url(spec, path_item=None, operation=None):
    """Return the effective declared base URL, or an empty string if none is declared."""
    for source in (operation, path_item, spec):
        if not isinstance(source, dict):
            continue
        servers = source.get("servers")
        if isinstance(servers, list):
            for server in servers:
                if isinstance(server, dict) and server.get("url"):
                    return str(redact_text(server["url"])).rstrip("/")

    for source in (operation, path_item, spec):
        if not isinstance(source, dict):
            continue
        host = source.get("host")
        if host:
            schemes = source.get("schemes")
            scheme = schemes[0] if isinstance(schemes, list) and schemes else "https"
            base_path = str(source.get("basePath") or "")
            return f"{scheme}://{host}{base_path}".rstrip("/")
        if source.get("basePath"):
            return str(source["basePath"]).rstrip("/")
    return ""


def resolve_schema(schema, spec, seen=None):
    """Resolve local OpenAPI references sufficiently for endpoint metadata and analysis."""
    if not isinstance(schema, dict):
        return schema
    seen = set() if seen is None else seen
    reference = schema.get("$ref")
    if isinstance(reference, str) and reference.startswith("#/") and reference not in seen:
        current = spec
        try:
            for part in reference[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                current = current[part]
        except (KeyError, TypeError):
            return schema
        seen.add(reference)
        resolved = resolve_schema(current, spec, seen)
        siblings = {key: value for key, value in schema.items() if key != "$ref"}
        if isinstance(resolved, dict):
            resolved.update(siblings)
        return resolved
    return {
        key: [resolve_schema(item, spec, seen) for item in value]
        if isinstance(value, list)
        else resolve_schema(value, spec, seen)
        if isinstance(value, dict)
        else value
        for key, value in schema.items()
    }


def extract_parameters(path_item, operation):
    parameters = []
    for source in (path_item, operation):
        if not isinstance(source, dict):
            continue
        values = source.get("parameters")
        if isinstance(values, list):
            parameters.extend(value for value in values if isinstance(value, dict))
    return redact_value(parameters)


def extract_response_schema(spec, operation):
    responses = operation.get("responses") if isinstance(operation, dict) else None
    if not isinstance(responses, dict):
        return None
    response_keys = sorted(
        [key for key in responses if str(key).isdigit() and 200 <= int(key) < 300],
        key=int,
    )
    response_keys.extend(key for key in ("default",) if key in responses)
    for response_key in response_keys:
        response = responses[response_key]
        if not isinstance(response, dict):
            continue
        content = response.get("content")
        if isinstance(content, dict):
            for media_type, media in content.items():
                if "json" not in str(media_type).lower() or not isinstance(media, dict):
                    continue
                if media.get("schema") is not None:
                    return resolve_schema(media["schema"], spec)
        if response.get("schema") is not None:
            return resolve_schema(response["schema"], spec)
    return None


def extract_endpoints(spec):
    endpoints = []
    methods = HTTP_METHODS
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            method_name = str(method).lower()
            if method_name not in methods:
                continue
            operation = operation if isinstance(operation, dict) else {}
            parameters = extract_parameters(item, operation)
            response_schema = extract_response_schema(spec, operation)
            security = operation.get("security", item.get("security", spec.get("security")))
            security_declared = (
                "security" in operation
                or "security" in item
                or "security" in spec
                or bool((spec.get("components") or {}).get("securitySchemes"))
                or bool(spec.get("securityDefinitions"))
            )
            endpoints.append(
                {
                    "path": str(path),
                    "method": method_name.upper(),
                    "operation_id": redact_text(operation.get("operationId")) if operation.get("operationId") else None,
                    "base_url": get_base_url(spec, item, operation),
                    "parameters_json": json_text(parameters),
                    "response_schema_json": json_text(response_schema),
                    "parameters": parameters,
                    "response_schema": response_schema,
                    "security_declared": security_declared,
                    "security_required": bool(security),
                }
            )
    return endpoints


def schema_fields(schema):
    fields = set()
    if isinstance(schema, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict):
            fields.update(str(key) for key in properties)
        for key in ("items", "not"):
            if key in schema:
                fields.update(schema_fields(schema[key]))
        for key in ("allOf", "oneOf", "anyOf"):
            values = schema.get(key)
            if isinstance(values, list):
                for value in values:
                    fields.update(schema_fields(value))
        if isinstance(schema.get("additionalProperties"), dict):
            fields.update(schema_fields(schema["additionalProperties"]))
    return fields


def object_parameter(endpoint):
    for name in re.findall(r"\{([^{}]+)\}", endpoint["path"]):
        normalized = re.sub(r"[^a-z0-9]", "", name.lower())
        if (
            normalized in OBJECT_PARAMETER_NAMES
            or normalized.endswith("id")
            or normalized.endswith("uuid")
            or re.search(r"(?:Id|ID|UUID)$", name)
            or re.search(r"(?:^|[_-])(id|uuid)(?:$|[_-])", name, re.IGNORECASE)
        ):
            return name
    return None


def request_evidence(endpoint):
    return {
        "source": "OpenAPI specification",
        "method": endpoint["method"],
        "url": f"{endpoint['base_url']}{endpoint['path']}" if endpoint["base_url"] else endpoint["path"],
        "parameters": endpoint["parameters"],
        "security_declared": endpoint["security_declared"],
        "security_required": endpoint["security_required"],
    }


def response_evidence(endpoint):
    return {
        "source": "OpenAPI specification",
        "method": endpoint["method"],
        "path": endpoint["path"],
        "response_schema": endpoint["response_schema"],
    }


def finding(
    endpoint,
    finding_type,
    title,
    severity,
    confidence,
    details,
    poc_text,
    explanation,
    impact,
    remediation,
):
    return {
        "endpoint_id": endpoint.get("endpoint_id"),
        "finding_type": finding_type,
        "title": redact_text(title),
        "severity": severity,
        "confidence": max(0.0, min(1.0, float(confidence))),
        "request_evidence": request_evidence(endpoint),
        "response_evidence": response_evidence(endpoint),
        "poc_text": redact_text(poc_text),
        "details": details,
        "explanation": redact_text(explanation),
        "impact": redact_text(impact),
        "remediation": redact_text(remediation),
    }


def build_findings(spec, endpoints):
    """Analyze parsed specification evidence and return canonical finding records."""
    findings = []
    for endpoint in endpoints:
        path = endpoint["path"]
        method = endpoint["method"]
        object_name = object_parameter(endpoint)
        if object_name:
            if endpoint["security_required"]:
                severity = "medium"
                confidence = 0.66
            else:
                severity = "high"
                confidence = 0.88 if not endpoint["security_declared"] else 0.76
            findings.append(
                finding(
                    endpoint,
                    "BOLA_IDOR",
                    f"Object-level authorization requires review for {method} {path}",
                    severity,
                    confidence,
                    {
                        "analysis_basis": "OpenAPI path parameter and security declarations",
                        "object_parameter": object_name,
                        "security_declared": endpoint["security_declared"],
                        "security_required": endpoint["security_required"],
                    },
                    f"Using an authorized test account, request {method} {path} with controlled values for {object_name} and verify that object ownership is enforced before data is returned.",
                    "The operation accepts an object identifier in its path, but the specification does not prove that ownership is checked.",
                    "A caller may be able to request another user's object if the implementation does not enforce object-level authorization.",
                    "Verify the authenticated principal against the requested object and return only resources the principal is authorized to access.",
                )
            )

        exposed_fields = sorted(
            field for field in schema_fields(endpoint["response_schema"]) if SENSITIVE_FIELD_PATTERN.search(field)
        )
        if exposed_fields:
            high_risk = any(
                re.search(r"password|secret|token|api[_-]?key|authorization|credit[_-]?card|ssn", field, re.IGNORECASE)
                for field in exposed_fields
            )
            findings.append(
                finding(
                    endpoint,
                    "EXCESSIVE_DATA_EXPOSURE",
                    f"Response schema exposes sensitive fields for {method} {path}",
                    "high" if high_risk else "medium",
                    min(0.95, 0.72 + 0.04 * len(exposed_fields)),
                    {
                        "analysis_basis": "OpenAPI response schema field names",
                        "exposed_fields": exposed_fields,
                    },
                    f"Review the documented response model for {method} {path} and compare the fields {', '.join(exposed_fields)} with the client-facing contract using authorized test data.",
                    "The documented response schema contains fields that may expose personal, internal, or credential-related data to clients.",
                    "A client may receive sensitive or unnecessary data that should not be part of the public response contract.",
                    "Use an allow-listed response model and remove internal or sensitive fields before serialization.",
                )
            )

        if re.search(r"(?:^|/)(?:admin|internal)(?:/|$)", path, re.IGNORECASE):
            findings.append(
                finding(
                    endpoint,
                    "OTHER_SECURITY",
                    f"Sensitive route requires access-control review: {method} {path}",
                    "medium",
                    0.72,
                    {
                        "analysis_basis": "OpenAPI path naming",
                        "route_class": "admin/internal",
                    },
                    f"Verify that {method} {path} is protected by authentication and role-based authorization before allowing an authorized test user to invoke it.",
                    "The route name suggests an administrative or internal surface, so its declared access-control requirements should be reviewed.",
                    "An exposed administrative route could provide broader access than intended.",
                    "Require strong authentication and role-based authorization, and restrict the route to the intended administrative audience.",
                )
            )
    return findings[:25]


def save_scan(filename, content):
    spec, metadata = parse_spec(filename, content)
    endpoints = extract_endpoints(spec)
    created_at = utc_now()
    target_base_url = get_base_url(spec)
    scan_name = redact_text(Path(filename).name)
    content_hash = hashlib.sha256(metadata["raw_content"].encode("utf-8")).hexdigest()

    with database_session(write=True) as db:
        spec_id = insert_returning_id(
            db,
            """
            INSERT INTO openapi_specs
                (source_type, source_url, title, spec_format, api_version, raw_content, content_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "upload",
                None,
                metadata["title"],
                metadata["spec_format"],
                metadata["api_version"],
                metadata["raw_content"],
                content_hash,
                created_at,
            ),
            "spec_id",
        )

        scan_id = insert_returning_id(
            db,
            """
            INSERT INTO api_scans
                (spec_id, scan_name, target_base_url, status, started_at, created_at)
            VALUES (?, ?, ?, 'running', ?, ?)
            """,
            (spec_id, scan_name, target_base_url, created_at, created_at),
            "scan_id",
        )

        stored_endpoints = []
        for endpoint in endpoints:
            endpoint_id = insert_returning_id(
                db,
                """
                INSERT INTO api_endpoints
                    (scan_id, method, path, base_url, operation_id, parameters_json, response_schema_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    endpoint["method"],
                    endpoint["path"],
                    endpoint["base_url"],
                    endpoint["operation_id"],
                    endpoint["parameters_json"],
                    endpoint["response_schema_json"],
                    created_at,
                ),
                "endpoint_id",
            )
            stored_endpoint = dict(endpoint)
            stored_endpoint["endpoint_id"] = endpoint_id
            stored_endpoints.append(stored_endpoint)

        findings = build_findings(spec, stored_endpoints)
        for item in findings:
            db.execute(
                """
                INSERT INTO findings
                    (scan_id, endpoint_id, finding_type, title, severity, confidence,
                     request_evidence_json, response_evidence_json, poc_text, details_json,
                     explanation, impact, remediation, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    item["endpoint_id"],
                    item["finding_type"],
                    item["title"],
                    item["severity"],
                    item["confidence"],
                    json_text(item["request_evidence"]),
                    json_text(item["response_evidence"]),
                    item["poc_text"],
                    json_text(item["details"]),
                    item["explanation"],
                    item["impact"],
                    item["remediation"],
                    created_at,
                ),
            )

        db.execute(
            "UPDATE api_scans SET status = 'completed', completed_at = ? WHERE scan_id = ?",
            (utc_now(), scan_id),
        )

    return get_scan(scan_id)


LIVE_SCAN_SPEC_NAME = "authorized-live-sandbox.json"
LIVE_REQUEST_MAX_BYTES = 2 * 1024 * 1024


def _live_credentials(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} credentials are required")
    username = value.get("username")
    password = value.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError(f"{label} credentials are required")
    return LiveCredentials(username=username, password=password)


def live_config_from_payload(payload):
    """Build an in-memory live profile without persisting credentials."""

    if not isinstance(payload, dict):
        raise ValueError("A JSON live-scan request is required")
    target = payload.get("target_base_url")
    if not isinstance(target, str):
        raise ValueError("target_base_url is required")
    return LiveScanConfig(
        target_base_url=target,
        user_a=_live_credentials(payload.get("user_a"), "User A"),
        user_b=_live_credentials(payload.get("user_b"), "User B"),
    )


def _live_endpoint_key(result):
    return (
        str(result.method).upper(),
        str(result.path),
        str(result.base_url).rstrip("/"),
        result.finding_type,
    )


def _live_endpoint_maps(stored_endpoints):
    by_key = {}
    by_id = {}
    for endpoint in stored_endpoints:
        key = (
            str(endpoint.get("method", "")).upper(),
            str(endpoint.get("path", "")),
            str(endpoint.get("base_url", "")).rstrip("/"),
        )
        by_key[key] = endpoint
        if endpoint.get("endpoint_id") is not None:
            by_id[endpoint["endpoint_id"]] = endpoint
    return by_key, by_id


def _live_finding_item(result):
    return {
        "endpoint_id": result.endpoint_id,
        "finding_type": result.finding_type,
        "title": redact_text(result.title),
        "severity": result.severity,
        "confidence": max(0.0, min(1.0, float(result.confidence))),
        "request_evidence": result.request_evidence,
        "response_evidence": result.response_evidence,
        "poc_text": redact_text(result.poc_text),
        "details": result.details,
        "explanation": redact_text(result.explanation),
        "impact": redact_text(result.impact),
        "remediation": redact_text(result.remediation),
    }


def _heuristic_item_with_live_status(item, result=None):
    updated = dict(item)
    details = dict(item.get("details") or {})
    details["classification"] = "heuristic"
    if result is None:
        details["live_test"] = {"status": "not_run"}
    else:
        details["live_test"] = {
            "status": "inconclusive",
            "error_code": result.error_code,
        }
        updated["request_evidence"] = result.request_evidence
        updated["response_evidence"] = result.response_evidence
        updated["poc_text"] = redact_text(result.poc_text)
    updated["details"] = details
    return updated


def _insert_finding_item(db, scan_id, item, created_at):
    db.execute(
        """
        INSERT INTO findings
            (scan_id, endpoint_id, finding_type, title, severity, confidence,
             request_evidence_json, response_evidence_json, poc_text, details_json,
             explanation, impact, remediation, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            item["endpoint_id"],
            item["finding_type"],
            item["title"],
            item["severity"],
            item["confidence"],
            json_text(item["request_evidence"]),
            json_text(item["response_evidence"]),
            item["poc_text"],
            json_text(item["details"]),
            item["explanation"],
            item["impact"],
            item["remediation"],
            created_at,
        ),
    )


def _persist_live_findings(db, scan_id, stored_endpoints, heuristic_findings, live_results, created_at):
    endpoint_by_key, endpoint_by_id = _live_endpoint_maps(stored_endpoints)
    result_by_key = {}
    for result in live_results:
        endpoint = endpoint_by_key.get(
            (
                str(result.method).upper(),
                str(result.path),
                str(result.base_url).rstrip("/"),
            )
        )
        if endpoint is not None:
            result.endpoint_id = endpoint.get("endpoint_id")
            result_by_key[_live_endpoint_key(result)] = result

    persisted_keys = set()
    secure_control_keys = set()
    for result in live_results:
        if (
            result.finding_type == "BOLA_IDOR"
            and result.details.get("secure_control_status") == 404
            and result.details.get("secure_control_path")
        ):
            secure_control_keys.add(
                (
                    str(result.method).upper(),
                    str(result.details["secure_control_path"]),
                    str(result.base_url).rstrip("/"),
                )
            )
    output = []
    for item in heuristic_findings:
        endpoint = endpoint_by_id.get(item.get("endpoint_id"))
        result = None
        if endpoint is not None:
            endpoint_key = (
                str(endpoint.get("method", "")).upper(),
                str(endpoint.get("path", "")),
                str(endpoint.get("base_url", "")).rstrip("/"),
            )
            if item["finding_type"] == "BOLA_IDOR" and endpoint_key in secure_control_keys:
                continue
            key = endpoint_key + (item["finding_type"],)
            result = result_by_key.get(key)
        live_key = None
        if result is not None:
            live_key = (
                str(endpoint.get("method", "")).upper(),
                str(endpoint.get("path", "")),
                str(endpoint.get("base_url", "")).rstrip("/"),
                item["finding_type"],
            )
        if result is not None and result.classification == "confirmed":
            output.append(_live_finding_item(result))
            persisted_keys.add(live_key)
        elif result is not None and result.classification == "secure/not confirmed":
            continue
        else:
            output.append(_heuristic_item_with_live_status(item, result))

    for result in live_results:
        if result.classification != "confirmed" or result.endpoint_id is None:
            continue
        live_key = (
            str(result.method).upper(),
            str(result.path),
            str(result.base_url).rstrip("/"),
            result.finding_type,
        )
        if live_key in persisted_keys:
            continue
        output.append(_live_finding_item(result))
        persisted_keys.add(live_key)

    for item in output:
        _insert_finding_item(db, scan_id, item, created_at)


def save_live_scan(payload):
    """Persist a live scan in short transactions and run HTTP checks between them."""

    config = live_config_from_payload(payload)
    target = TargetPolicy.validate_base_url(config.target_base_url)
    spec_value = payload.get("spec")
    source_type = "upload"
    source_url = None
    openapi_url = payload.get("openapi_url")
    if openapi_url is not None:
        if not isinstance(openapi_url, str):
            raise ValueError("openapi_url must be a string")
        TargetPolicy.validate_request_url(openapi_url)
    if spec_value is None:
        if not isinstance(openapi_url, str):
            raise ValueError("An OpenAPI spec object or local openapi_url is required")
        spec_value = fetch_local_openapi(
            target,
            timeout_seconds=config.timeout_seconds,
            max_response_bytes=config.max_response_bytes,
        )
        source_type = "url"
        source_url = f"{target}/openapi.json"
    if not isinstance(spec_value, dict):
        raise ValueError("An OpenAPI spec object is required")
    spec_content = json.dumps(spec_value, ensure_ascii=False).encode("utf-8")
    spec, metadata = parse_spec(LIVE_SCAN_SPEC_NAME, spec_content)
    TargetPolicy.validate_spec_servers(spec)
    endpoints = extract_endpoints(spec)
    created_at = utc_now()
    content_hash = hashlib.sha256(metadata["raw_content"].encode("utf-8")).hexdigest()

    with database_session(write=True) as db:
        spec_id = insert_returning_id(
            db,
            """
            INSERT INTO openapi_specs
                (source_type, source_url, title, spec_format, api_version, raw_content, content_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_type,
                source_url,
                metadata["title"],
                metadata["spec_format"],
                metadata["api_version"],
                metadata["raw_content"],
                content_hash,
                created_at,
            ),
            "spec_id",
        )
        scan_id = insert_returning_id(
            db,
            """
            INSERT INTO api_scans
                (spec_id, scan_name, target_base_url, status, started_at, created_at)
            VALUES (?, ?, ?, 'running', ?, ?)
            """,
            (spec_id, LIVE_SCAN_SPEC_NAME, target, created_at, created_at),
            "scan_id",
        )
        stored_endpoints = []
        for endpoint in endpoints:
            endpoint_id = insert_returning_id(
                db,
                """
                INSERT INTO api_endpoints
                    (scan_id, method, path, base_url, operation_id, parameters_json, response_schema_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    endpoint["method"],
                    endpoint["path"],
                    endpoint["base_url"],
                    endpoint["operation_id"],
                    endpoint["parameters_json"],
                    endpoint["response_schema_json"],
                    created_at,
                ),
                "endpoint_id",
            )
            stored_endpoint = dict(endpoint)
            stored_endpoint["endpoint_id"] = endpoint_id
            stored_endpoints.append(stored_endpoint)

    live_error = None
    try:
        live_results = run_authorized_live_scan(spec, stored_endpoints, config)
        if any(result.classification == "inconclusive" for result in live_results):
            live_error = "live_scan_inconclusive"
    except Exception:
        # Runtime failures must not discard successful static analysis or expose
        # exception text. The adapter turns these into heuristic/inconclusive rows.
        live_results = inconclusive_results(stored_endpoints, target, "runtime_error")
        live_error = "live_scan_inconclusive"

    heuristic_findings = build_findings(spec, stored_endpoints)
    with database_session(write=True) as db:
        _persist_live_findings(
            db,
            scan_id,
            stored_endpoints,
            heuristic_findings,
            live_results,
            created_at,
        )
        db.execute(
            """
            UPDATE api_scans
            SET status = 'completed', completed_at = ?, error_message = ?
            WHERE scan_id = ?
            """,
            (utc_now(), live_error, scan_id),
        )
    return get_scan(scan_id)


def _read_live_payload(handler):
    raw_length = handler.headers.get("Content-Length", "0")
    try:
        length = int(raw_length)
    except ValueError as error:
        raise ValueError("Invalid Content-Length") from error
    if length < 0 or length > LIVE_REQUEST_MAX_BYTES:
        raise ValueError("Live request body is too large")
    try:
        payload = json.loads(handler.rfile.read(length).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Live request body must be valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("Live request body must be a JSON object")
    return payload


def severity_counts(db, scan_id=None):
    counts = {severity: 0 for severity in SEVERITIES}
    if scan_id is None:
        rows = db.execute("SELECT severity, COUNT(*) AS count FROM findings GROUP BY severity")
    else:
        rows = db.execute(
            "SELECT severity, COUNT(*) AS count FROM findings WHERE scan_id = ? GROUP BY severity",
            (scan_id,),
        )
    for row in rows:
        counts[row["severity"]] = row["count"]
    return counts


def calculate_score(counts):
    return max(0, 100 - sum(SEVERITY_WEIGHTS[severity] * count for severity, count in counts.items()))


def scan_row(db, scan_id):
    return db.execute(
        """
        SELECT s.scan_id, s.spec_id, s.scan_name, s.target_base_url, s.status,
               s.started_at, s.completed_at, s.error_message, s.created_at,
               o.title, o.spec_format, o.api_version
        FROM api_scans AS s
        JOIN openapi_specs AS o ON o.spec_id = s.spec_id
        WHERE s.scan_id = ?
        """,
        (scan_id,),
    ).fetchone()


def scan_summary(db, row):
    scan_id = row["scan_id"]
    endpoint_count = db.execute(
        "SELECT COUNT(*) FROM api_endpoints WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]
    finding_count = db.execute(
        "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]
    distribution = severity_counts(db, scan_id)
    result = dict(row)
    result.update(
        {
            "id": scan_id,
            "filename": row["scan_name"],
            "format": str(row["spec_format"] or "").upper(),
            "version": row["api_version"],
            "endpoint_count": endpoint_count,
            "finding_count": finding_count,
            "score": calculate_score(distribution),
            "critical_count": distribution["critical"],
            "severity_distribution": distribution,
        }
    )
    return result


def get_scan(scan_id):
    with database_session() as db:
        row = scan_row(db, scan_id)
        if row is None:
            return None
        result = scan_summary(db, row)
        result["endpoints"] = []
        for endpoint in db.execute(
            """
            SELECT endpoint_id, scan_id, method, path, base_url, operation_id,
                   parameters_json, response_schema_json, created_at
            FROM api_endpoints WHERE scan_id = ? ORDER BY endpoint_id
            """,
            (scan_id,),
        ):
            item = dict(endpoint)
            item["parameters"] = decode_json(item["parameters_json"])
            item["response_schema"] = decode_json(item["response_schema_json"])
            result["endpoints"].append(item)

        result["findings"] = []
        for finding_row in db.execute(
            """
            SELECT f.finding_id, f.scan_id, f.endpoint_id, f.finding_type, f.title,
                   f.severity, f.confidence, f.request_evidence_json,
                   f.response_evidence_json, f.poc_text, f.details_json,
                   f.explanation, f.impact, f.remediation, f.created_at,
                   e.path, e.method
            FROM findings AS f
            LEFT JOIN api_endpoints AS e ON e.endpoint_id = f.endpoint_id
            WHERE f.scan_id = ? ORDER BY f.finding_id DESC
            """,
            (scan_id,),
        ):
            item = dict(finding_row)
            item["id"] = item["finding_id"]
            item["description"] = item["explanation"] or ""
            item["request_evidence"] = decode_json(item["request_evidence_json"])
            item["response_evidence"] = decode_json(item["response_evidence_json"])
            item["details"] = decode_json(item["details_json"])
            result["findings"].append(item)
        return result


def dashboard_data():
    with database_session() as db:
        rows = db.execute(
            """
            SELECT s.scan_id, s.spec_id, s.scan_name, s.target_base_url, s.status,
                   s.started_at, s.completed_at, s.error_message, s.created_at,
                   o.title, o.spec_format, o.api_version
            FROM api_scans AS s
            JOIN openapi_specs AS o ON o.spec_id = s.spec_id
            ORDER BY s.scan_id DESC LIMIT 10
            """
        ).fetchall()
        scans = [scan_summary(db, row) for row in rows]
        totals = {
            "scans": db.execute("SELECT COUNT(*) FROM api_scans").fetchone()[0],
            "endpoints": db.execute("SELECT COUNT(*) FROM api_endpoints").fetchone()[0],
            "findings": db.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
        }
        distribution = severity_counts(db)
        type_distribution = finding_type_distribution(db)
    latest = scans[0] if scans else {
        "score": calculate_score(distribution),
        "endpoint_count": 0,
        "finding_count": 0,
        "critical_count": 0,
        "severity_distribution": distribution,
    }
    return {
        "latest": latest,
        "totals": totals,
        "scans": scans,
        "severity_distribution": distribution,
        "finding_type_distribution": type_distribution,
    }


def finding_type_distribution(db, scan_id=None):
    counts = {"BOLA_IDOR": 0, "EXCESSIVE_DATA_EXPOSURE": 0, "OTHER_SECURITY": 0}
    if scan_id is None:
        rows = db.execute("SELECT finding_type, COUNT(*) AS count FROM findings GROUP BY finding_type")
    else:
        rows = db.execute(
            "SELECT finding_type, COUNT(*) AS count FROM findings WHERE scan_id = ? GROUP BY finding_type",
            (scan_id,),
        )
    for row in rows:
        counts[row["finding_type"]] = row["count"]
    return counts


def recent_findings(db, limit=8):
    findings = []
    for row in db.execute(
        """
        SELECT f.finding_id, f.scan_id, f.endpoint_id, f.finding_type, f.title,
               f.severity, f.confidence, f.explanation, e.path, e.method
        FROM findings AS f
        LEFT JOIN api_endpoints AS e ON e.endpoint_id = f.endpoint_id
        ORDER BY f.finding_id DESC LIMIT ?
        """,
        (limit,),
    ):
        item = dict(row)
        item["description"] = item["explanation"] or ""
        findings.append(item)
    return findings


def database_data():
    with database_session() as db:
        info = _database_info(db)
        tables = []
        for table in CANONICAL_TABLES:
            count = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            tables.append({"name": table, "rows": count})
        return {
            "database": info["database"],
            "path": info["path"],
            "tables": tables,
            "recent_findings": recent_findings(db),
            "severity_distribution": severity_counts(db),
            "finding_type_distribution": finding_type_distribution(db),
        }


def chat_reply(message):
    question = message.strip().lower()
    data = dashboard_data()
    latest = data["latest"]
    with database_session() as db:
        info = _database_info(db)
        findings = recent_findings(db, limit=8)
        endpoints = [
            dict(row)
            for row in db.execute(
                "SELECT method, path, operation_id FROM api_endpoints ORDER BY endpoint_id DESC LIMIT 8"
            )
        ]

    backend_label = "PostgreSQL" if info.get("backend") == "postgres" else "SQLite"
    if not data["totals"]["scans"]:
        answer = f"No scan is stored yet. Upload a Swagger or OpenAPI JSON/YAML file from API Scans and I will analyze its endpoints and persist the results in {backend_label}."
    elif any(word in question for word in ("database", "sqlite", "postgres", "postgresql", "stored", "save", "saved")):
        answer = f"{backend_label} is healthy. The database currently contains {data['totals']['scans']} scan(s), {data['totals']['endpoints']} endpoint(s), and {data['totals']['findings']} finding(s)."
    elif any(word in question for word in ("endpoint", "route", "api")):
        endpoint_text = ", ".join(f"{item['method']} {item['path']}" for item in endpoints[:5]) or "none"
        answer = f"The latest scan contains {latest['endpoint_count']} endpoint(s). Recent routes include: {endpoint_text}."
    elif any(word in question for word in ("fix", "remediat", "recommend", "secure", "solution")):
        if findings:
            top = findings[0]
            answer = f"Start with {top['severity']} priority: {top['title']} on {top['path'] or 'the API'}. {top['description']}"
        else:
            answer = "No findings were generated for the latest scan. Keep authentication, authorization, schema validation, and rate limiting enabled in production."
    elif any(word in question for word in ("risk", "vulnerab", "finding", "issue", "score")):
        top = findings[0] if findings else None
        answer = f"The latest security score is {latest['score']}/100 with {latest['finding_count']} finding(s)."
        if top:
            answer += f" Highest priority: {top['severity']} {top['title']} at {top['path']}."
    else:
        answer = f"I am Sentinel Copilot, grounded in your {backend_label} data. Latest scan score: {latest['score']}/100, {latest['endpoint_count']} endpoints, {latest['finding_count']} findings. Ask me about risks, endpoints, fixes, or stored database data."
    return {"answer": answer, "source": f"{backend_label} + latest scan", "timestamp": utc_now()}


def health_data():
    with database_session() as db:
        db.execute("SELECT 1").fetchone()
        info = _database_info(db)
        foreign_keys = 1 if _foreign_keys_enabled(db) else 0
        tables = _table_names(db)
    missing = [table for table in CANONICAL_TABLES if table not in tables]
    if missing:
        raise SentinelDatabaseError("Missing canonical tables: " + ", ".join(missing))
    if foreign_keys != 1:
        raise SentinelDatabaseError("Foreign-key enforcement is disabled.")
    return {
        "ok": True,
        "database": info["database"],
        "path": info["path"],
        "foreign_keys": foreign_keys,
    }


def report_data():
    with database_session() as db:
        row = db.execute(
            """
            SELECT s.scan_id, s.spec_id, s.scan_name, s.target_base_url, s.status,
                   s.started_at, s.completed_at, s.error_message, s.created_at,
                   o.title, o.spec_format, o.api_version
            FROM api_scans AS s
            JOIN openapi_specs AS o ON o.spec_id = s.spec_id
            ORDER BY s.scan_id DESC LIMIT 1
            """
        ).fetchone()
    if row is None:
        return {
            "scan": None,
            "summary": {
                "score": calculate_score({severity: 0 for severity in SEVERITIES}),
                "endpoint_count": 0,
                "finding_count": 0,
                "severity_distribution": {severity: 0 for severity in SEVERITIES},
                "finding_type_distribution": {
                    "BOLA_IDOR": 0,
                    "EXCESSIVE_DATA_EXPOSURE": 0,
                    "OTHER_SECURITY": 0,
                },
            },
            "findings": [],
            "generated_at": utc_now(),
        }
    scan = get_scan(row["scan_id"])
    with database_session() as db:
        type_distribution = finding_type_distribution(db, row["scan_id"])
    return {
        "scan": scan,
        "summary": {
            "score": scan["score"],
            "endpoint_count": scan["endpoint_count"],
            "finding_count": scan["finding_count"],
            "severity_distribution": scan["severity_distribution"],
            "finding_type_distribution": type_distribution,
        },
        "findings": scan["findings"],
        "generated_at": utc_now(),
    }


class SentinelHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        kwargs["directory"] = str(APP_ROOT)
        super().__init__(*args, **kwargs)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            try:
                self.send_json(health_data())
            except Exception as error:
                self.send_json({"ok": False, "error": str(error)}, 503)
        elif path == "/api/dashboard":
            self.send_json(dashboard_data())
        elif path == "/api/scans":
            self.send_json(dashboard_data()["scans"])
        elif path == "/api/database":
            self.send_json(database_data())
        elif path == "/api/report":
            self.send_json(report_data())
        elif path.startswith("/api/scans/"):
            try:
                scan_id = int(path.rsplit("/", 1)[-1])
            except ValueError:
                self.send_json({"error": "Scan not found"}, 404)
                return
            scan = get_scan(scan_id)
            self.send_json(scan or {"error": "Scan not found"}, 200 if scan else 404)
        else:
            super().do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/chat":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                message = payload.get("message", "")
                if not isinstance(message, str) or not message.strip():
                    raise ValueError("Message is required.")
                self.send_json(chat_reply(message))
            except (ValueError, json.JSONDecodeError) as error:
                self.send_json({"error": str(error)}, 400)
            except Exception as error:
                self.send_json({"error": str(error)}, 500)
            return
        if path == "/api/scans/live":
            origin = self.headers.get("Origin")
            if origin and origin != "http://127.0.0.1:5500":
                self.send_json({"error": "Live scan origin is not allowed"}, 403)
                return
            try:
                payload = _read_live_payload(self)
                scan = save_live_scan(payload)
                self.send_json(scan, 201)
            except (KeyError, ValueError):
                self.send_json({"error": "Invalid live scan request"}, 400)
            except DatabaseError:
                self.send_json({"error": "Database error"}, 500)
            except Exception:
                self.send_json({"error": "Live scan failed"}, 500)
            return
        if path != "/api/scans":
            self.send_json({"error": "Not found"}, 404)
            return
        try:
            content_type = self.headers.get("Content-Type", "")
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            message = BytesParser(policy=default).parsebytes(
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
            )
            upload = next(
                (
                    part
                    for part in message.iter_attachments()
                    if part.get_param("name", header="content-disposition") == "spec"
                ),
                None,
            )
            filename = upload.get_filename() if upload else None
            if not filename:
                raise ValueError("Attach an OpenAPI JSON or YAML file using the spec field.")
            scan = save_scan(Path(str(filename)).name, upload.get_payload(decode=True) or b"")
            self.send_json(scan, 201)
        except (KeyError, ValueError) as error:
            self.send_json({"error": str(error)}, 400)
        except DatabaseError:
            self.send_json({"error": "Database error"}, 500)
        except Exception as error:
            self.send_json({"error": f"Unable to save scan: {error}"}, 500)

    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    init_database()
    server = ThreadingHTTPServer(("127.0.0.1", int(os.getenv("PORT", "5500"))), SentinelHandler)
    print(f"Sentinel API running at http://127.0.0.1:{server.server_port}")
    try:
        server.serve_forever()
    finally:
        DB.close()
