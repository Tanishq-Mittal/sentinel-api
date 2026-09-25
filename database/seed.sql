-- DEMO/TEST DATA ONLY.
-- This file is for a fresh demo database. It contains synthetic values only.
-- Do not run it against a production database.
-- All authorization material in evidence is explicitly redacted.

PRAGMA foreign_keys = ON;

BEGIN;

-- DEMO/TEST SPECIFICATION: 1 sample OpenAPI specification.
INSERT INTO openapi_specs (
    spec_id,
    source_type,
    source_url,
    title,
    spec_format,
    api_version,
    raw_content,
    content_hash,
    created_at
) VALUES (
    1,
    'url',
    'https://spec.example.test/openapi.json',
    'SentinelAPI Demo API',
    'openapi',
    '3.0.3',
    '{
        "openapi": "3.0.3",
        "info": {
            "title": "SentinelAPI Demo API",
            "version": "1.0.0"
        },
        "servers": [
            {"url": "https://api.example.test"}
        ],
        "paths": {
            "/v1/accounts/{accountId}": {
                "get": {
                    "operationId": "getAccount",
                    "parameters": [
                        {
                            "name": "accountId",
                            "in": "path",
                            "required": true,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "OK"}
                    }
                }
            },
            "/v1/reports/{reportId}": {
                "get": {
                    "operationId": "getReport",
                    "parameters": [
                        {
                            "name": "reportId",
                            "in": "path",
                            "required": true,
                            "schema": {"type": "string"}
                        }
                    ],
                    "responses": {
                        "200": {"description": "OK"}
                    }
                }
            },
            "/v1/reports": {
                "post": {
                    "operationId": "createReport",
                    "responses": {
                        "201": {"description": "Created"}
                    }
                }
            }
        }
    }',
    'demo-spec-hash-001',
    '2026-09-24T10:00:00Z'
);

-- DEMO/TEST SCAN: 1 sample authorized scan.
INSERT INTO api_scans (
    scan_id,
    spec_id,
    scan_name,
    target_base_url,
    status,
    started_at,
    completed_at,
    error_message,
    created_at
) VALUES (
    1,
    1,
    'DEMO authorized scan',
    'https://api.example.test',
    'completed',
    '2026-09-24T10:01:00Z',
    '2026-09-24T10:02:00Z',
    NULL,
    '2026-09-24T10:00:30Z'
);

-- DEMO/TEST ENDPOINTS: 3 sample discovered operations.
INSERT INTO api_endpoints (
    endpoint_id,
    scan_id,
    method,
    path,
    base_url,
    operation_id,
    parameters_json,
    response_schema_json,
    created_at
) VALUES (
    1,
    1,
    'GET',
    '/v1/accounts/{accountId}',
    'https://api.example.test',
    'getAccount',
    '[{"name":"accountId","in":"path","required":true,"schema":{"type":"string"}}]',
    '{"type":"object","properties":{"id":{"type":"string"},"owner_id":{"type":"string"},"balance":{"type":"number"}}}',
    '2026-09-24T10:01:10Z'
);

INSERT INTO api_endpoints (
    endpoint_id,
    scan_id,
    method,
    path,
    base_url,
    operation_id,
    parameters_json,
    response_schema_json,
    created_at
) VALUES (
    2,
    1,
    'GET',
    '/v1/reports/{reportId}',
    'https://api.example.test',
    'getReport',
    '[{"name":"reportId","in":"path","required":true,"schema":{"type":"string"}}]',
    '{"type":"object","properties":{"report_id":{"type":"string"},"owner_id":{"type":"string"},"email":{"type":"string"},"internal_score":{"type":"integer"}}}',
    '2026-09-24T10:01:11Z'
);

INSERT INTO api_endpoints (
    endpoint_id,
    scan_id,
    method,
    path,
    base_url,
    operation_id,
    parameters_json,
    response_schema_json,
    created_at
) VALUES (
    3,
    1,
    'POST',
    '/v1/reports',
    'https://api.example.test',
    'createReport',
    '[]',
    '{"type":"object","properties":{"report_id":{"type":"string"}}}',
    '2026-09-24T10:01:12Z'
);

-- DEMO/TEST FINDING 1: BOLA/IDOR. Evidence is synthetic and redacted.
INSERT INTO findings (
    finding_id,
    scan_id,
    endpoint_id,
    finding_type,
    title,
    severity,
    confidence,
    request_evidence_json,
    response_evidence_json,
    poc_text,
    details_json,
    explanation,
    impact,
    remediation,
    created_at
) VALUES (
    1,
    1,
    1,
    'BOLA_IDOR',
    'BOLA/IDOR on account lookup',
    'high',
    0.94,
    '{"method":"GET","url":"https://api.example.test/v1/accounts/demo-account-456","headers":{"accept":"application/json","authorization":"[REDACTED]"},"body":null}',
    '{"status":200,"headers":{"content-type":"application/json"},"body":{"id":"demo-account-456","owner_id":"demo-user-b","balance":980,"account_status":"active"}}',
    '1. Use the test session for demo-user-a. 2. Request demo-account-456. 3. The API returns HTTP 200 with data owned by demo-user-b.',
    '{"object_parameter":"accountId","attacker_session":"demo-user-a","victim_object_id":"demo-account-456","observed_owner_id":"demo-user-b","authorization_result":"allowed"}',
    'The endpoint returns an account record without verifying that the authenticated user owns the requested account ID.',
    'An authenticated user could read another user account details, causing cross-account data disclosure.',
    'Enforce object-level authorization on every account lookup and verify the resource owner before returning data.',
    '2026-09-24T10:01:40Z'
);

-- DEMO/TEST FINDING 2: excessive data exposure. Evidence is synthetic and redacted.
INSERT INTO findings (
    finding_id,
    scan_id,
    endpoint_id,
    finding_type,
    title,
    severity,
    confidence,
    request_evidence_json,
    response_evidence_json,
    poc_text,
    details_json,
    explanation,
    impact,
    remediation,
    created_at
) VALUES (
    2,
    1,
    2,
    'EXCESSIVE_DATA_EXPOSURE',
    'Report response exposes internal and account fields',
    'medium',
    0.89,
    '{"method":"GET","url":"https://api.example.test/v1/reports/demo-report-42","headers":{"accept":"application/json","authorization":"[REDACTED]"},"body":null}',
    '{"status":200,"headers":{"content-type":"application/json"},"body":{"report_id":"demo-report-42","owner_id":"demo-user-a","email":"[REDACTED]","internal_score":87,"account_status":"active","debug_source":"demo"}}',
    '1. Use the test session for demo-user-a. 2. Request demo-report-42. 3. Compare the returned fields with the documented client-facing report response.',
    '{"exposed_fields":["email","internal_score","account_status","debug_source"],"sensitive_fields":["email","internal_score"],"documented_fields":["report_id","owner_id","summary"],"redaction_applied":true}',
    'The report response includes internal and account-level fields that are not required for the client-facing report representation.',
    'Downstream clients may receive internal account metadata and sensitive user attributes, increasing the impact of a report access flaw.',
    'Return an allow-listed response model and remove internal fields before serialization.',
    '2026-09-24T10:01:50Z'
);

COMMIT;
