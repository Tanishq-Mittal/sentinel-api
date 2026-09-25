# SentinelAPI Database

This directory contains the minimal SQLite database framework for the SentinelAPI MVP.

The database is intentionally limited to four tables:

- `openapi_specs`
- `api_scans`
- `api_endpoints`
- `findings`

No backend or frontend code is stored or modified here. No `sentinelapi.db` file is created by these files.

## Files

- `schema.sql` — table definitions, constraints, foreign keys, and indexes.
- `seed.sql` — synthetic demo/test records for local development.
- `README.md` — schema and integration notes.

## Table purposes

### `openapi_specs`

Stores one OpenAPI or Swagger specification input.

Important columns:

- `spec_id` — integer primary key.
- `source_type` — `url` or `upload`.
- `source_url` — source URL, when the specification was loaded from a URL.
- `spec_format` and `api_version` — specification metadata.
- `raw_content` — optional exact specification content for reproducibility.
- `content_hash` — optional hash for caching or deduplication.
- `created_at` — UTC ISO-8601 timestamp.

The specification is stored once and can be referenced by multiple scans.

### `api_scans`

Stores one execution of an authorized scan.

Important columns:

- `scan_id` — integer primary key.
- `spec_id` — required reference to `openapi_specs`.
- `target_base_url` — authorized target being scanned.
- `status` — `queued`, `running`, `completed`, or `failed`.
- `started_at`, `completed_at`, and `error_message` — execution information.
- `created_at` — UTC ISO-8601 timestamp.

A specification can have many scans, which allows a rescan of the same API.

### `api_endpoints`

Stores one operation discovered from a specification for a particular scan.

Important columns:

- `endpoint_id` — integer primary key.
- `scan_id` — required reference to `api_scans`.
- `method`, `path`, and `base_url` — endpoint identity.
- `operation_id` — OpenAPI operation identifier, if present.
- `parameters_json` — parameter definitions serialized as JSON text.
- `response_schema_json` — response schema serialized as JSON text.
- `created_at` — UTC ISO-8601 timestamp.

A scan can have many endpoints. The same logical endpoint may be stored separately for different historical scans.

### `findings`

Stores one security finding for a scan.

Important columns:

- `finding_id` — integer primary key.
- `scan_id` — required reference to `api_scans`.
- `endpoint_id` — optional reference to `api_endpoints`; null means the finding is scan-wide.
- `finding_type` — one of `BOLA_IDOR`, `EXCESSIVE_DATA_EXPOSURE`, or `OTHER_SECURITY`.
- `severity` — `info`, `low`, `medium`, `high`, or `critical`.
- `confidence` — numeric value from `0.0` to `1.0`.
- `request_evidence_json` — redacted request evidence.
- `response_evidence_json` — redacted response evidence.
- `poc_text` — reproduction steps or PoC text.
- `details_json` — optional type-specific structured details.
- `explanation`, `impact`, and `remediation` — AI-generated output.
- `created_at` — UTC ISO-8601 timestamp.

BOLA/IDOR and excessive data exposure share the `findings` table because they share the same reporting fields. The `finding_type` column provides the primary category, while `details_json` stores specialized values such as object IDs or exposed field names.

## Relationships

```text
openapi_specs 1 ────< api_scans 1 ────< api_endpoints
                                  │
                                  └────< findings >──── optional api_endpoint
```

Foreign keys are enforced with `ON DELETE RESTRICT` or `ON DELETE CASCADE` as appropriate:

- Deleting a scan cascades to its endpoints and findings.
- Deleting an endpoint leaves its scan-level finding rows intact by setting `endpoint_id` to null.
- A specification referenced by a scan cannot be deleted.

SQLite foreign-key enforcement must be enabled on every connection. `schema.sql` enables it for its own connection; the Python backend should also execute:

```sql
PRAGMA foreign_keys = ON;
```

## How OpenAPI/Swagger connects to the database

The backend should follow this flow:

1. Receive the authorized specification from a URL or upload.
2. Redact any secrets in the specification before storing it.
3. Insert one `openapi_specs` row and retain its `spec_id`.
4. Insert an `api_scans` row referencing that `spec_id` and the authorized `target_base_url`.
5. Parse the specification and insert one `api_endpoints` row per operation, referencing the scan.
6. Run the analysis and insert `findings` rows referencing the scan and, when applicable, an endpoint.
7. Store AI explanation, impact, and remediation when analysis completes.

The backend should use parameterized SQL statements and transactions when inserting related records.

## Example backend insert flow

The following illustrates the data flow without requiring a particular Python framework:

```python
# 1. Save the parsed/raw specification first.
cursor = connection.execute(
    """
    INSERT INTO openapi_specs
        (source_type, source_url, spec_format, api_version, raw_content)
    VALUES (?, ?, ?, ?, ?)
    """,
    ("url", spec_url, "openapi", "3.0.3", redacted_spec),
)
spec_id = cursor.lastrowid

# 2. Create the scan record.
cursor = connection.execute(
    """
    INSERT INTO api_scans (spec_id, target_base_url, status)
    VALUES (?, ?, ?)
    """,
    (spec_id, authorized_base_url, "running"),
)
scan_id = cursor.lastrowid

# 3. Store a discovered operation.
cursor = connection.execute(
    """
    INSERT INTO api_endpoints
        (scan_id, method, path, base_url, operation_id,
         parameters_json, response_schema_json)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
    (
        scan_id,
        "GET",
        "/v1/accounts/{accountId}",
        authorized_base_url,
        "getAccount",
        json.dumps(parameters),
        json.dumps(response_schema),
    ),
)
endpoint_id = cursor.lastrowid

# 4. Store a finding. Evidence must already be redacted.
connection.execute(
    """
    INSERT INTO findings
        (scan_id, endpoint_id, finding_type, title, severity, confidence,
         request_evidence_json, response_evidence_json, poc_text, details_json,
         explanation, impact, remediation)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    (
        scan_id,
        endpoint_id,
        "BOLA_IDOR",
        "BOLA/IDOR on account lookup",
        "high",
        0.94,
        json.dumps(redacted_request_evidence),
        json.dumps(redacted_response_evidence),
        poc_text,
        json.dumps({"object_parameter": "accountId"}),
        ai_explanation,
        ai_impact,
        ai_remediation,
    ),
)

connection.commit()
```

The endpoint ID is optional for a finding that applies to the whole scan.

## How the frontend will receive the data

The React frontend should not connect directly to SQLite. The Python backend will query the four tables, join a scan to its endpoints and findings as needed, deserialize the `*_json` TEXT fields, and return API responses to the frontend.

Typical read paths are:

1. List scans from `api_scans`.
2. Load a scan's specification summary from `openapi_specs`.
3. Load discovered endpoints for a selected `scan_id`.
4. Load findings for a selected scan, optionally filtered by `finding_type`, `severity`, or `endpoint_id`.
5. Return a JSON-shaped response containing the scan summary, endpoint list, and findings.

The frontend can then display the AI explanation, impact, remediation, evidence, and PoC without knowing the SQLite file location.

## Security and redaction rules

The database layer cannot reliably detect every secret. Redaction must happen in the backend before any insert.

Never store:

- Raw passwords or password fields.
- API keys or access keys.
- `Authorization` header values.
- Bearer tokens or session cookies.
- OAuth client secrets or refresh tokens.
- Private keys or other credentials.
- Unnecessary personal or regulated data.

For request and response evidence:

- Replace sensitive values with a marker such as `[REDACTED]`.
- Redact credentials in URLs, query parameters, headers, bodies, and response payloads.
- Prefer storing only the evidence needed to demonstrate the finding.
- Truncate very large response bodies.
- Never use real credentials in `seed.sql` or demo data.

`request_evidence_json`, `response_evidence_json`, `poc_text`, and `details_json` are application-managed text. They do not automatically sanitize input; the Python backend must sanitize them before insertion.

## Creating the database later

When implementation moves to the database setup step, a new database can be initialized from a fresh file with:

```text
sqlite3 sentinelapi.db < database/schema.sql
sqlite3 sentinelapi.db < database/seed.sql
```

The `seed.sql` file is for a fresh demo/test database only. It intentionally uses synthetic `example.test` values and redacted placeholders.
