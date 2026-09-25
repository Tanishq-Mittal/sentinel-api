# Sentinel API

SQLite/PostgreSQL-backed OpenAPI/Swagger security dashboard.

## Run locally

```bash
python -m venv .venv

# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# macOS/Linux
# source .venv/bin/activate

python -m pip install -r requirements.txt
python server.py
```

Open `http://127.0.0.1:5500` in a browser. Upload an OpenAPI or Swagger `.json`, `.yaml`, or `.yml` file from **API Scans**. The redacted specification, parsed endpoints, scan metadata, and findings are stored in the canonical `database/sentinelapi.db` file.

Useful endpoints:

- `GET /api/health`
- `GET /api/dashboard`
- `GET /api/scans`
- `POST /api/scans` with multipart field `spec`
- `POST /api/scans/live` with an authorized local JSON live-scan profile
- `GET /api/database` for table counts and recent findings
- `GET /api/report` for the latest scan's actual report data
- `POST /api/chat` with JSON body `{ "message": "What should I fix first?" }`

## Accessing the database

The canonical SQLite file is `database/sentinelapi.db`, resolved from the repository root rather than the current working directory. You can inspect it with any SQLite viewer, or use **API Inventory → SQLite data store → Export data snapshot** in the dashboard. The browser UI never receives the SQLite file directly; it shows safe metadata, endpoint counts, and findings.

The database must already exist before starting the server. The backend validates its four canonical tables and never creates a second SQLite file.

## PostgreSQL production database

Set `DATABASE_URL` in the server environment. When it is present, the application uses PostgreSQL through `psycopg[binary,pool]`; when it is absent, the local SQLite file remains the fallback.

Do not put credentials in source control. For PowerShell, provide the value through the process environment or a secret manager.

Environment variables:

- `DATABASE_URL`: required for production PostgreSQL; never hardcode it.
- `SENTINEL_DB_PATH`: optional local SQLite fallback path when `DATABASE_URL` is absent.
- `PORT`: optional SentinelAPI port; defaults to `5500`.
- `TEST_DATABASE_URL`: optional disposable PostgreSQL URL for integration tests only; never point it at production.

### Initialize PostgreSQL

Initialize the equivalent logical schema before starting the application:

```powershell
psql $env:DATABASE_URL -f ..\database\postgres_schema.sql
```

The PostgreSQL schema preserves the four existing tables, IDs, foreign keys, checks, indexes, JSON/TEXT evidence fields, and timestamps.

### Migrate existing SQLite data

Use the explicit import utility. It refuses a non-empty destination unless truncation is explicitly requested:

```powershell
python migrate_sqlite_to_postgres.py `
  --sqlite-path ..\database\sentinelapi.db `
  --database-url $env:DATABASE_URL
```

For a deliberately empty replacement destination:

```powershell
python migrate_sqlite_to_postgres.py `
  --sqlite-path ..\database\sentinelapi.db `
  --database-url $env:DATABASE_URL `
  --truncate
```

Migration order is `openapi_specs`, `api_scans`, `api_endpoints`, then `findings`. Primary-key IDs and foreign-key relationships are preserved; credentials and bearer tokens are not migrated because they are not stored.

### Local test command

```powershell
python -m pytest -q
```

### Production start command

```powershell
$env:DATABASE_URL = '<provided-by-secret-manager>'
python server.py
```

For a real deployment, provide `DATABASE_URL` through the platform secret store, run the schema/migration steps as a release job, and use a supervised production process. Do not deploy the local SQLite file as the production store.

## Authorized live scanner

The opt-in live scanner is restricted to the local sandbox target:

```text
http://127.0.0.1:5601
```

Use `POST /api/scans/live` with a JSON body containing:

- `spec`: the sandbox OpenAPI document as a JSON object, or `openapi_url`: exactly `http://127.0.0.1:5601/openapi.json`;
- `target_base_url`: exactly `http://127.0.0.1:5601`;
- `user_a` and `user_b`: temporary sandbox username/password objects.

The credentials are held in runtime memory only. They are not written to SQLite, logs, OpenAPI persistence, or browser storage. The adapter authenticates both synthetic users separately, performs only controlled read-only requests, logs out both sessions, and stores sanitized evidence.

The live scanner:

- rejects every target except `http://127.0.0.1:5601`;
- rejects external OpenAPI servers and redirects;
- ignores proxy environment variables;
- uses bounded responses and short timeouts;
- performs baseline, cross-user BOLA, secure-control, and response-contract checks;
- stores `confirmed`, `heuristic`, `inconclusive`, or `secure/not confirmed` classification in `details_json`;
- does not modify the existing static behavior of `POST /api/scans`.

For a local live request, first start the sandbox API, then submit the live scan JSON to SentinelAPI. Do not use browser localStorage for credentials.

Run the scanner tests from the `sentinel-api` directory:

```powershell
python -m pytest -q
```

The live adapter uses the declared `httpx` dependency and makes no requests to any target other than the exact allowlisted sandbox URL.

## Copilot

**Security Insights → Sentinel Copilot** is a local, SQLite-grounded assistant. It answers questions about the latest scan, findings, endpoints, remediation, and stored records without requiring an API key or sending the uploaded specification to a third-party service. For a full LLM later, the `/api/chat` function is the integration point.
