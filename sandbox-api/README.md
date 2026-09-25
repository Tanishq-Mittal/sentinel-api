# SentinelAPI Local Sandbox API

This is a separate, synthetic FastAPI application for explicitly authorized testing of SentinelAPI's BOLA/IDOR and excessive-data-exposure scenarios.

It is intentionally local-only. It does not use SQLite, PostgreSQL, any other persistent database, external services, real credentials, or production data. Fixtures and sessions are held in memory and reset when the process restarts.

## Run locally

From this directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m app.main
```

The default URL is:

```text
http://127.0.0.1:5601
```

The process must bind to `127.0.0.1`. A non-loopback host configuration is rejected at startup.

Useful URLs:

- Health: `http://127.0.0.1:5601/health`
- OpenAPI: `http://127.0.0.1:5601/openapi.json`
- Swagger UI: `http://127.0.0.1:5601/docs`
- ReDoc: `http://127.0.0.1:5601/redoc`

The documentation pages use local assets only and do not load a CDN or other external resource.

## Synthetic accounts

These credentials are local fixtures only:

| User | Username | Password |
|---|---|---|
| User A | `sandbox-user-a` | `local-sandbox-a-only!` |
| User B | `sandbox-user-b` | `local-sandbox-b-only!` |

Obtain an ephemeral bearer token:

```text
POST /v1/auth/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=sandbox-user-a&password=local-sandbox-a-only!
```

Use the returned token as:

```text
Authorization: Bearer <token>
```

Tokens are opaque, expire, are never persisted, and are invalidated by `POST /v1/auth/logout`. Cookies are not used.

## Test scenarios

### BOLA/IDOR

- `GET /v1/orders` lists only the current user's orders.
- `GET /v1/orders/{order_id}` is intentionally vulnerable: an authenticated User B can request User A's existing order ID.
- `GET /v1/me/orders/{order_id}` is the secure control and returns `404` for another user's order.

The primary fixture IDs are:

- User A: `ord_a_1001`, `ord_a_1002`
- User B: `ord_b_2001`, `ord_b_2002`

### Excessive data exposure

- `GET /v1/reports/{report_id}` is owner-checked but intentionally returns the expected `ReportClient` fields plus `owner_email`, `internal_risk_score`, `payment_processor_reference`, and `internal_audit_note`.
- `GET /v1/me/reports/{report_id}` is the secure control and returns only the intended fields.

The primary report IDs are:

- User A: `rep_a_3001`
- User B: `rep_b_4001`

## Tests

With the sandbox dependencies installed:

```powershell
python -m pytest -q
```

The tests cover authentication, token expiry, logout isolation, owner-scoped lists, BOLA behavior, response-contract differences, OpenAPI metadata, host validation, method restrictions, and the absence of sandbox persistence.

## Safety boundaries

- The server binds only to `127.0.0.1`.
- Host headers are restricted to the configured loopback host.
- CORS allows only `http://127.0.0.1:5500` by default.
- There are no outbound HTTP or DNS calls.
- Resource routes are read-only; `PUT`, `PATCH`, and `DELETE` are rejected.
- Request and response sizes are bounded and request handling has a short timeout.
- External redirects are rejected.
- Do not expose this service through a proxy, container port mapping, or tunnel.
