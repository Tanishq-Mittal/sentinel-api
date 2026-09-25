# SentinelAPI Database Integration

This document defines how the Python/FastAPI backend should use the existing SQLite database. It is an integration contract; it does not require changes to the schema, seed data, or frontend.

## 1. Database location

The database file is:

```text
database/sentinelapi.db
```

Resolve this path from the backend project root, or make it configurable with an environment variable such as `SENTINEL_DB_PATH`. Do not create a second database file for normal application use.

## 2. SQLite connection setup

The backend must enable foreign-key enforcement for **every new connection**:

```python
import sqlite3

connection = sqlite3.connect(db_path)
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
```

`PRAGMA foreign_keys = ON` is a connection setting in SQLite, not a persistent database property. The backend must execute it whenever it opens a connection, including request-scoped and background-worker connections.

Use parameterized SQL statements and transactions for related writes. JSON columns are SQLite `TEXT`; serialize Python values with `json.dumps()` and deserialize with `json.loads()`.

## 3. Tables and fields

### `openapi_specs`

Stores the authorized OpenAPI/Swagger input.

- `spec_id` — generated integer primary key.
- `source_type` — `url` or `upload`.
- `source_url` — source URL, if applicable.
- `title` — API title.
- `spec_format` — `openapi` or `swagger`.
- `api_version` — specification version.
- `raw_content` — optional exact specification content, serialized as text.
- `content_hash` — optional hash for caching or deduplication.
- `created_at` — UTC timestamp.

### `api_scans`

Stores one authorized scan execution.

- `scan_id` — generated integer primary key.
- `spec_id` — required reference to `openapi_specs.spec_id`.
- `scan_name` — display name.
- `target_base_url` — authorized target.
- `status` — `queued`, `running`, `completed`, or `failed`.
- `started_at` — start time in UTC.
- `completed_at` — completion time in UTC.
- `error_message` — failure details, if any.
- `created_at` — UTC timestamp.

### `api_endpoints`

Stores operations discovered during a scan.

- `endpoint_id` — generated integer primary key.
- `scan_id` — required reference to `api_scans.scan_id`.
- `method` — HTTP method.
- `path` — path template.
- `base_url` — effective server/base URL.
- `operation_id` — OpenAPI `operationId`, if present.
- `parameters_json` — parameter definitions serialized as JSON text.
- `response_schema_json` — response schema serialized as JSON text.
- `created_at` — UTC timestamp.

### `findings`

Stores one security issue per row.

- `finding_id` — generated integer primary key.
- `scan_id` — required reference to `api_scans.scan_id`.
- `endpoint_id` — optional reference to `api_endpoints.endpoint_id`; null for a scan-wide finding.
- `finding_type` — `BOLA_IDOR`, `EXCESSIVE_DATA_EXPOSURE`, or `OTHER_SECURITY`.
- `title` — short issue title.
- `severity` — `info`, `low`, `medium`, `high`, or `critical`.
- `confidence` — number from `0.0` to `1.0`.
- `request_evidence_json` — redacted request evidence serialized as text.
- `response_evidence_json` — redacted response evidence serialized as text.
- `poc_text` — reproduction steps or PoC text.
- `details_json` — type-specific details serialized as text.
- `explanation` — AI-generated explanation.
- `impact` — AI-generated impact statement.
- `remediation` — AI-generated remediation guidance.
- `created_at` — UTC timestamp.

## 4. Foreign-key relationships

- `api_scans.spec_id` → `openapi_specs.spec_id` with `ON DELETE RESTRICT`.
- `api_endpoints.scan_id` → `api_scans.scan_id` with `ON DELETE CASCADE`.
- `findings.scan_id` → `api_scans.scan_id` with `ON DELETE CASCADE`.
- `findings.endpoint_id` → `api_endpoints.endpoint_id` with `ON DELETE SET NULL`.

Therefore:

```text
openapi_specs 1 ────< api_scans 1 ────< api_endpoints
                                  │
                                  └────< findings >──── optional api_endpoint
```

When a finding includes both `scan_id` and `endpoint_id`, the backend should verify that the endpoint belongs to that scan. The database uses separate foreign keys rather than a composite constraint.

## 5. Correct insertion flow

### A. Specification received

1. Accept the authorized Swagger/OpenAPI URL or upload.
2. Validate and parse the specification.
3. Redact credentials or secrets from the specification before storing `raw_content`.
4. Insert `openapi_specs` and retain the generated `spec_id`.

### B. Scan starts

1. Insert `api_scans` with the `spec_id`, authorized `target_base_url`, and `status = 'queued'`.
2. Retain the generated `scan_id`.
3. Update the row to `running` when analysis begins.
4. Set `completed_at` and `status = 'completed'` on success, or store `error_message` and set `status = 'failed'`.

### C. Endpoints are discovered

1. Iterate over the parsed paths and HTTP operations.
2. Insert one `api_endpoints` row per operation using the same `scan_id`.
3. Store `parameters_json` and `response_schema_json` with `json.dumps()`.
4. Retain `endpoint_id` values for findings that target a specific operation.

### D. Vulnerabilities are detected

1. Create a `findings` row with `scan_id` and, when applicable, `endpoint_id`.
2. Set `finding_type`, `title`, `severity`, and `confidence`.
3. Put type-specific data such as object IDs or exposed field names in `details_json`.
4. Commit the finding in the same transaction as the associated scan result when practical.

### E. Evidence and PoC are generated

The schema stores evidence and PoC data on the finding:

- `request_evidence_json`
- `response_evidence_json`
- `poc_text`

Redact first, then serialize the evidence and update or insert the finding.

### F. AI output is available

Update the same finding with:

- `explanation`
- `impact`
- `remediation`

AI output is not a separate table. The finding can exist before these fields are populated, allowing the scan to continue if the AI step is delayed or fails.

## 6. Example JSON objects

The following are application-level objects. For columns ending in `_json`, serialize the object with `json.dumps()` before inserting it into SQLite. IDs and `created_at` can normally be omitted on insert and filled by the database.

### OpenAPI specification

```json
{
  "source_type": "url",
  "source_url": "https://spec.example.test/openapi.json",
  "title": "Demo API",
  "spec_format": "openapi",
  "api_version": "3.0.3",
  "raw_content": "{\"openapi\":\"3.0.3\",\"info\":{\"title\":\"Demo API\",\"version\":\"1.0.0\"}}",
  "content_hash": "demo-spec-hash"
}
```

### Scan

```json
{
  "spec_id": 1,
  "scan_name": "Authorized production-like scan",
  "target_base_url": "https://api.example.test",
  "status": "running",
  "started_at": "2026-09-24T10:01:00Z"
}
```

### Endpoint

```json
{
  "scan_id": 1,
  "method": "GET",
  "path": "/v1/accounts/{accountId}",
  "base_url": "https://api.example.test",
  "operation_id": "getAccount",
  "parameters_json": "[{\"name\":\"accountId\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}]",
  "response_schema_json": "{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"},\"owner_id\":{\"type\":\"string\"}}}"
}
```

### BOLA/IDOR finding

```json
{
  "scan_id": 1,
  "endpoint_id": 1,
  "finding_type": "BOLA_IDOR",
  "title": "BOLA/IDOR on account lookup",
  "severity": "high",
  "confidence": 0.94,
  "request_evidence_json": "{\"method\":\"GET\",\"url\":\"https://api.example.test/v1/accounts/demo-account-456\",\"headers\":{\"authorization\":\"[REDACTED]\"}}",
  "response_evidence_json": "{\"status\":200,\"body\":{\"id\":\"demo-account-456\",\"owner_id\":\"demo-user-b\"}}",
  "poc_text": "Use the demo-user-a session and request demo-account-456. A 200 response returns another user's resource.",
  "details_json": "{\"object_parameter\":\"accountId\",\"victim_object_id\":\"demo-account-456\",\"observed_owner_id\":\"demo-user-b\"}",
  "explanation": "The endpoint does not verify ownership of the requested account.",
  "impact": "A user may read another user's account data.",
  "remediation": "Enforce object-level authorization before returning the resource."
}
```

### Excessive data exposure finding

```json
{
  "scan_id": 1,
  "endpoint_id": 2,
  "finding_type": "EXCESSIVE_DATA_EXPOSURE",
  "title": "Report response exposes internal fields",
  "severity": "medium",
  "confidence": 0.89,
  "request_evidence_json": "{\"method\":\"GET\",\"url\":\"https://api.example.test/v1/reports/demo-report-42\",\"headers\":{\"authorization\":\"[REDACTED]\"}}",
  "response_evidence_json": "{\"status\":200,\"body\":{\"report_id\":\"demo-report-42\",\"email\":\"[REDACTED]\",\"internal_score\":87}}",
  "poc_text": "Request the report as demo-user-a and compare its response fields with the documented response model.",
  "details_json": "{\"exposed_fields\":[\"email\",\"internal_score\"],\"documented_fields\":[\"report_id\",\"summary\"]}",
  "explanation": "The response contains fields outside the client-facing report model.",
  "impact": "Internal or sensitive attributes may be disclosed to clients.",
  "remediation": "Use an allow-listed response model before serialization."
}
```

## 7. Evidence, PoC, and secret redaction

Redaction must happen in the backend **before** any database insert or update.

Never store:

- Raw passwords.
- API keys or access keys.
- Authorization header values.
- Bearer tokens, session cookies, or refresh tokens.
- OAuth client secrets or private keys.
- Other credentials or unnecessary sensitive data.

For evidence and PoC data:

- Replace sensitive values with `[REDACTED]`.
- Inspect URLs, query parameters, headers, cookies, request bodies, response headers, and response bodies.
- Store only the evidence needed to demonstrate the finding.
- Truncate very large response bodies.
- Apply redaction to `request_evidence_json`, `response_evidence_json`, `poc_text`, and `details_json` as appropriate.

The database constraints cannot reliably detect secrets; redaction is an application responsibility.

## 8. Frontend integration

The data flow is:

```text
React → FastAPI → SQLite
```

The React frontend must not open, query, or receive the SQLite file directly. FastAPI should:

1. Query scans, specifications, endpoints, and findings.
2. Join records by `spec_id`, `scan_id`, and `endpoint_id`.
3. Deserialize the `*_json` TEXT fields.
4. Return a JSON API response to the React dashboard.

A dashboard response can be shaped like:

```json
{
  "scan": {
    "scan_id": 1,
    "status": "completed",
    "target_base_url": "https://api.example.test"
  },
  "endpoints": [
    {
      "endpoint_id": 1,
      "method": "GET",
      "path": "/v1/accounts/{accountId}"
    }
  ],
  "findings": [
    {
      "finding_id": 1,
      "finding_type": "BOLA_IDOR",
      "severity": "high",
      "confidence": 0.94
    }
  ]
}
```

## 9. End-to-end backend data flow

```text
Swagger upload
    → FastAPI validates and redacts the specification
    → INSERT openapi_specs
    → INSERT api_scans
    → parse paths and operations
    → INSERT api_endpoints
    → run authorized analysis
    → INSERT findings with redacted evidence and PoC
    → update findings with AI explanation, impact, and remediation
    → FastAPI queries the completed scan
    → return JSON to the React dashboard
```

The backend should keep the scan status current, use transactions for related writes, and enable foreign keys on every SQLite connection.
