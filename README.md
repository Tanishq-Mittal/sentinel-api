# Sentinel API

SQLite-backed OpenAPI/Swagger security dashboard.

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

Open `http://127.0.0.1:5500` in a browser. Upload an OpenAPI or Swagger `.json`, `.yaml`, or `.yml` file from **API Scans**. The original specification, parsed endpoints, scan score, and findings are stored in `sentinel.db`.

Useful endpoints:

- `GET /api/health`
- `GET /api/dashboard`
- `GET /api/scans`
- `POST /api/scans` with multipart field `spec`
- `GET /api/database` for table counts and recent findings
- `POST /api/chat` with JSON body `{ "message": "What should I fix first?" }`

## Accessing the database

The SQLite file is `sentinel.db` in the project folder. You can inspect it with any SQLite viewer, or use **API Inventory → SQLite data store → Export data snapshot** in the dashboard. The browser UI never exposes the raw uploaded specification directly; it shows safe metadata, endpoint counts, and findings.

The database is created automatically on first server start and is intentionally ignored by Git, so every laptop gets its own local data file.

## Copilot

**Security Insights → Sentinel Copilot** is a local, SQLite-grounded assistant. It answers questions about the latest scan, findings, endpoints, remediation, and stored records without requiring an API key or sending the uploaded specification to a third-party service. For a full LLM later, the `/api/chat` function is the integration point.