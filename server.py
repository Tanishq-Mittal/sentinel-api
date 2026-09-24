import json
import mimetypes
import os
import re
import sqlite3
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    yaml = None


ROOT = Path(__file__).parent
DATABASE = ROOT / "sentinel.db"


def connection():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_database():
    with connection() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                title TEXT NOT NULL,
                version TEXT,
                format TEXT NOT NULL,
                spec BLOB NOT NULL,
                endpoint_count INTEGER NOT NULL DEFAULT 0,
                score INTEGER NOT NULL DEFAULT 0,
                finding_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                operation_id TEXT,
                UNIQUE(scan_id, path, method)
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                path TEXT,
                description TEXT
            );
            """
        )


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
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, yaml.YAMLError if yaml else ValueError) as error:
        raise ValueError(f"Could not parse OpenAPI file: {error}") from error

    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        raise ValueError("The file must be a valid Swagger/OpenAPI document with a paths object.")
    info = spec.get("info") or {}
    return spec, file_format, str(info.get("title") or Path(filename).stem), str(spec.get("openapi") or spec.get("swagger") or "Unknown")


def extract_endpoints(spec):
    endpoints = []
    methods = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in methods:
                continue
            operation = operation if isinstance(operation, dict) else {}
            endpoints.append((str(path), method.upper(), operation.get("operationId")))
    return endpoints


def build_findings(endpoints):
    findings = []
    for path, method, _ in endpoints:
        lower_path = path.lower()
        if re.search(r"\{(id|user.?id|tenant.?id|order.?id)\}", lower_path):
            findings.append(("HIGH", "Object authorization needs review", path, f"Review ownership checks before returning resources from {method} {path}."))
        if "admin" in lower_path or "internal" in lower_path:
            findings.append(("MEDIUM", "Sensitive route exposure", path, "Confirm this route is protected by authentication and role checks."))
    return findings[:25]


def save_scan(filename, content):
    spec, file_format, title, version = parse_spec(filename, content)
    endpoints = extract_endpoints(spec)
    findings = build_findings(endpoints)
    score = max(35, 100 - len(findings) * 8)
    created_at = datetime.now(timezone.utc).isoformat()
    with connection() as db:
        cursor = db.execute(
            "INSERT INTO scans (filename, title, version, format, spec, endpoint_count, score, finding_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (filename, title, version, file_format, content, len(endpoints), score, len(findings), created_at),
        )
        scan_id = cursor.lastrowid
        db.executemany("INSERT INTO endpoints (scan_id, path, method, operation_id) VALUES (?, ?, ?, ?)", [(scan_id, *endpoint) for endpoint in endpoints])
        db.executemany("INSERT INTO findings (scan_id, severity, title, path, description) VALUES (?, ?, ?, ?, ?)", [(scan_id, *finding) for finding in findings])
    return get_scan(scan_id)


def get_scan(scan_id):
    with connection() as db:
        row = db.execute("SELECT id, filename, title, version, format, endpoint_count, score, finding_count, created_at FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["findings"] = [dict(item) for item in db.execute("SELECT severity, title, path, description FROM findings WHERE scan_id = ? ORDER BY id DESC", (scan_id,))]
        return result


def dashboard_data():
    with connection() as db:
        latest = db.execute("SELECT score, endpoint_count, finding_count FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        totals = db.execute("SELECT COUNT(*), COALESCE(SUM(endpoint_count), 0), COALESCE(SUM(finding_count), 0) FROM scans").fetchone()
        scans = [dict(row) for row in db.execute("SELECT id, filename, title, endpoint_count, score, finding_count, created_at FROM scans ORDER BY id DESC LIMIT 10")]
    return {"latest": dict(latest) if latest else {"score": 0, "endpoint_count": 0, "finding_count": 0}, "totals": {"scans": totals[0], "endpoints": totals[1], "findings": totals[2]}, "scans": scans}


def database_data():
    with connection() as db:
        tables = []
        for table in ("scans", "endpoints", "findings"):
            count = db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            tables.append({"name": table, "rows": count})
        recent_findings = [dict(row) for row in db.execute("SELECT severity, title, path, description FROM findings ORDER BY id DESC LIMIT 8")]
    return {"database": DATABASE.name, "tables": tables, "recent_findings": recent_findings}


def chat_reply(message):
    question = message.strip().lower()
    data = dashboard_data()
    latest = data["latest"]
    with connection() as db:
        findings = [dict(row) for row in db.execute("SELECT severity, title, path, description FROM findings ORDER BY id DESC LIMIT 8")]
        endpoints = [dict(row) for row in db.execute("SELECT method, path, operation_id FROM endpoints ORDER BY id DESC LIMIT 8")]

    if not data["totals"]["scans"]:
        answer = "No scan is stored yet. Upload a Swagger or OpenAPI JSON/YAML file from API Scans and I will analyze its endpoints and persist the results in SQLite."
    elif any(word in question for word in ("database", "sqlite", "stored", "save", "saved")):
        answer = f"SQLite is healthy. The database currently contains {data['totals']['scans']} scan(s), {data['totals']['endpoints']} endpoint(s), and {data['totals']['findings']} finding(s). The file is {DATABASE.name}."
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
        answer = f"I am Sentinel Copilot, grounded in your SQLite data. Latest scan score: {latest['score']}/100, {latest['endpoint_count']} endpoints, {latest['finding_count']} findings. Ask me about risks, endpoints, fixes, or stored database data."
    return {"answer": answer, "source": "SQLite + latest scan", "timestamp": datetime.now(timezone.utc).isoformat()}


class SentinelHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            self.send_json({"ok": True, "database": str(DATABASE.name)})
        elif path == "/api/dashboard":
            self.send_json(dashboard_data())
        elif path == "/api/scans":
            self.send_json(dashboard_data()["scans"])
        elif path == "/api/database":
            self.send_json(database_data())
        elif path.startswith("/api/scans/"):
            scan = get_scan(path.rsplit("/", 1)[-1])
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
            return
        if path != "/api/scans":
            self.send_json({"error": "Not found"}, 404)
            return
        try:
            content_type = self.headers.get("Content-Type", "")
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            message = BytesParser(policy=default).parsebytes(f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body)
            upload = next((part for part in message.iter_attachments() if part.get_param("name", header="content-disposition") == "spec"), None)
            filename = upload.get_filename() if upload else None
            if not filename:
                raise ValueError("Attach an OpenAPI JSON or YAML file using the spec field.")
            scan = save_scan(os.path.basename(filename), upload.get_payload(decode=True) or b"")
            self.send_json(scan, 201)
        except (KeyError, ValueError) as error:
            self.send_json({"error": str(error)}, 400)
        except Exception as error:
            self.send_json({"error": f"Unable to save scan: {error}"}, 500)

    def send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    init_database()
    server = ThreadingHTTPServer(("127.0.0.1", int(os.getenv("PORT", "5500"))), SentinelHandler)
    print(f"Sentinel API running at http://127.0.0.1:{server.server_port}")
    server.serve_forever()