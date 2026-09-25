-- SentinelAPI MVP SQLite schema
-- The database stores only application data. Python owns parsing, analysis, and
-- all redaction of sensitive values before any INSERT.

PRAGMA foreign_keys = ON;

BEGIN;

-- One row represents one OpenAPI/Swagger specification input.
CREATE TABLE IF NOT EXISTS openapi_specs (
    spec_id INTEGER PRIMARY KEY,
    source_type TEXT NOT NULL
        CHECK (source_type IN ('url', 'upload')),
    source_url TEXT,
    title TEXT,
    spec_format TEXT NOT NULL
        CHECK (spec_format IN ('openapi', 'swagger')),
    api_version TEXT,
    -- Store the exact specification content when available. Remove credentials,
    -- API keys, tokens, passwords, client secrets, and other secrets first.
    raw_content TEXT,
    content_hash TEXT,
    -- UTC ISO-8601 timestamp. SQLite CURRENT_TIMESTAMP is UTC, but the explicit
    -- format keeps stored values consistent with application timestamps.
    created_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- One row represents one execution of an authorized scan.
CREATE TABLE IF NOT EXISTS api_scans (
    scan_id INTEGER PRIMARY KEY,
    spec_id INTEGER NOT NULL,
    scan_name TEXT,
    target_base_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    started_at TEXT,
    completed_at TEXT,
    error_message TEXT,
    created_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    FOREIGN KEY (spec_id) REFERENCES openapi_specs (spec_id)
        ON DELETE RESTRICT
);

-- One row represents an operation discovered in a scan's specification.
CREATE TABLE IF NOT EXISTS api_endpoints (
    endpoint_id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    base_url TEXT NOT NULL,
    operation_id TEXT,
    -- JSON is stored as TEXT. The backend serializes and parses these values.
    parameters_json TEXT,
    response_schema_json TEXT,
    created_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE (scan_id, method, path, base_url),
    FOREIGN KEY (scan_id) REFERENCES api_scans (scan_id)
        ON DELETE CASCADE
);

-- One row represents one security issue. BOLA/IDOR and excessive data exposure
-- share this table and are distinguished by finding_type plus details_json.
CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    -- Null means the finding applies to the whole scan rather than one operation.
    endpoint_id INTEGER,
    finding_type TEXT NOT NULL
        CHECK (finding_type IN (
            'BOLA_IDOR',
            'EXCESSIVE_DATA_EXPOSURE',
            'OTHER_SECURITY'
        )),
    title TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    confidence REAL NOT NULL
        CHECK (confidence >= 0.0 AND confidence <= 1.0),

    -- Evidence must be sanitized before it is written. Never persist raw
    -- passwords, API keys, Authorization headers, cookies, bearer tokens,
    -- client secrets, or other credentials in these TEXT columns.
    request_evidence_json TEXT,
    response_evidence_json TEXT,
    poc_text TEXT,
    -- Type-specific details, for example object IDs or exposed field names.
    details_json TEXT,

    -- AI-generated output. These fields may be populated after initial analysis.
    explanation TEXT,
    impact TEXT,
    remediation TEXT,
    created_at TEXT NOT NULL
        DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    FOREIGN KEY (scan_id) REFERENCES api_scans (scan_id)
        ON DELETE CASCADE,
    FOREIGN KEY (endpoint_id) REFERENCES api_endpoints (endpoint_id)
        ON DELETE SET NULL
);

-- SQLite does not automatically index foreign-key columns. These indexes
-- support the common scan, endpoint, and dashboard queries.
CREATE INDEX IF NOT EXISTS idx_api_scans_spec_id
    ON api_scans (spec_id);

CREATE INDEX IF NOT EXISTS idx_api_endpoints_scan_id
    ON api_endpoints (scan_id);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id
    ON findings (scan_id);

CREATE INDEX IF NOT EXISTS idx_findings_endpoint_id
    ON findings (endpoint_id);

CREATE INDEX IF NOT EXISTS idx_findings_type
    ON findings (finding_type);

CREATE INDEX IF NOT EXISTS idx_findings_severity
    ON findings (severity);

COMMIT;
