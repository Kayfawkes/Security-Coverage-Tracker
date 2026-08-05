from __future__ import annotations

import csv
import hashlib
import io
import os
import secrets
import sqlite3
import sys
import threading
import webbrowser
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

APP_NAME = "Security Coverage Tracker"
APP_VERSION = "0.2.1"
BASE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
RUNTIME_DIR = Path(os.getenv("SCT_DATA_DIR", Path.cwd() / "data")).resolve()
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = RUNTIME_DIR / "security_coverage.db"

app = FastAPI(title=APP_NAME, version=APP_VERSION)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SCT_SESSION_SECRET", secrets.token_hex(32)),
    max_age=28800,
    same_site="strict",
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "static"))


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('super_admin','admin','system_owner','support','read_only')),
                scope_control TEXT,
                owner_ref TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cmdb_id TEXT UNIQUE,
                hostname TEXT NOT NULL,
                fqdn TEXT,
                ip_address TEXT,
                operating_system TEXT,
                owner TEXT,
                business_unit TEXT,
                environment TEXT,
                criticality TEXT NOT NULL DEFAULT 'Medium',
                lifecycle_status TEXT NOT NULL DEFAULT 'Active',
                notes TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS controls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                capability TEXT NOT NULL,
                description TEXT,
                target_coverage INTEGER NOT NULL DEFAULT 100,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS coverage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                control_id INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('Protected','Missing','Unknown','Not Applicable')),
                source TEXT NOT NULL DEFAULT 'CSV',
                agent_version TEXT,
                last_seen TEXT,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(asset_id, control_id),
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
                FOREIGN KEY(control_id) REFERENCES controls(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS import_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                import_type TEXT NOT NULL,
                filename TEXT NOT NULL,
                row_count INTEGER NOT NULL,
                success_count INTEGER NOT NULL,
                failure_count INTEGER NOT NULL,
                imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT NOT NULL,
                entity_type TEXT,
                entity_id TEXT,
                details TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        # Upgrade databases created by v0.1.0.
        control_columns = _column_names(conn, "controls")
        if "target_coverage" not in control_columns:
            conn.execute("ALTER TABLE controls ADD COLUMN target_coverage INTEGER NOT NULL DEFAULT 100")
        if "active" not in control_columns:
            conn.execute("ALTER TABLE controls ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
        if "created_at" not in control_columns:
            conn.execute("ALTER TABLE controls ADD COLUMN created_at TEXT")
            conn.execute("UPDATE controls SET created_at=CURRENT_TIMESTAMP WHERE created_at IS NULL")
        if "updated_at" not in control_columns:
            conn.execute("ALTER TABLE controls ADD COLUMN updated_at TEXT")
            conn.execute("UPDATE controls SET updated_at=CURRENT_TIMESTAMP WHERE updated_at IS NULL")

        if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            conn.execute(
                "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                ("admin", hash_password("ChangeMe123!"), "super_admin"),
            )
        for name, capability in [
            ("EDR", "Endpoint Protection"),
            ("SWG", "Secure Web Gateway"),
            ("Microsegmentation", "Network Segmentation"),
            ("PAM", "Privileged Access Management"),
            ("Vulnerability Management", "Vulnerability Management"),
        ]:
            conn.execute(
                "INSERT OR IGNORE INTO controls(name, capability) VALUES(?,?)",
                (name, capability),
            )


def current_user(request: Request) -> dict[str, Any] | None:
    return request.session.get("user")


def require_user(request: Request, write: bool = False) -> dict[str, Any]:
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    if write and user["role"] == "read_only":
        raise HTTPException(status_code=403, detail="Read-only account")
    return user


def require_control_manager(request: Request) -> dict[str, Any]:
    user = require_user(request, write=True)
    if user["role"] == "super_admin":
        return user
    if user["role"] == "admin" and not user.get("scope_control"):
        return user
    raise HTTPException(status_code=403, detail="Only a super administrator or unscoped administrator can manage control sets")


def audit(username: str | None, action: str, entity_type: str = "", entity_id: str = "", details: str = "") -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit_log(username,action,entity_type,entity_id,details) VALUES(?,?,?,?,?)",
            (username, action, entity_type, entity_id, details),
        )


def scoped_asset_where(user: dict[str, Any]) -> tuple[str, list[Any]]:
    if user["role"] == "system_owner" and user.get("owner_ref"):
        return " WHERE a.owner = ? ", [user["owner_ref"]]
    return "", []


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/me")
def me(request: Request):
    return current_user(request) or JSONResponse({"authenticated": False}, status_code=401)


@app.post("/api/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with db() as conn:
        row = conn.execute(
            "SELECT username, role, scope_control, owner_ref FROM users WHERE username=? AND password_hash=? AND active=1",
            (username, hash_password(password)),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = dict(row)
    request.session["user"] = user
    audit(username, "LOGIN")
    return user


@app.post("/api/logout")
def logout(request: Request):
    user = current_user(request)
    request.session.clear()
    audit(user["username"] if user else None, "LOGOUT")
    return {"ok": True}


@app.get("/api/dashboard")
def dashboard(request: Request):
    user = require_user(request)
    where, params = scoped_asset_where(user)
    control_filter = ""
    control_params: list[Any] = []
    if user["role"] == "admin" and user.get("scope_control"):
        control_filter = " AND c.name = ? "
        control_params.append(user["scope_control"])
    with db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM assets a {where}", params).fetchone()[0]
        query = f"""
            SELECT c.name, c.target_coverage,
                   SUM(CASE WHEN cv.status='Protected' THEN 1 ELSE 0 END) protected,
                   SUM(CASE WHEN cv.status='Missing' THEN 1 ELSE 0 END) missing,
                   SUM(CASE WHEN cv.status='Unknown' THEN 1 ELSE 0 END) unknown,
                   COUNT(cv.id) total
            FROM controls c
            LEFT JOIN coverage cv ON cv.control_id=c.id
            LEFT JOIN assets a ON a.id=cv.asset_id
            {where if where else 'WHERE 1=1'} AND c.active=1 {control_filter}
            GROUP BY c.id, c.name, c.target_coverage ORDER BY c.name
        """
        rows = [dict(r) for r in conn.execute(query, params + control_params).fetchall()]
        missing = conn.execute(
            f"SELECT COUNT(*) FROM coverage cv JOIN assets a ON a.id=cv.asset_id JOIN controls c ON c.id=cv.control_id {where + (' AND ' if where else ' WHERE ')} cv.status='Missing' AND c.active=1",
            params,
        ).fetchone()[0]
    return {"total_assets": total, "missing_gaps": missing, "controls": rows}


@app.get("/api/assets")
def list_assets(request: Request, search: str = ""):
    user = require_user(request)
    where, params = scoped_asset_where(user)
    clauses = []
    if where:
        clauses.append(where.replace(" WHERE ", ""))
    if search:
        clauses.append("(a.hostname LIKE ? OR a.cmdb_id LIKE ? OR a.owner LIKE ? OR a.ip_address LIKE ?)")
        params.extend([f"%{search}%"] * 4)
    sql_where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with db() as conn:
        rows = conn.execute(
            f"SELECT a.* FROM assets a {sql_where} ORDER BY a.hostname LIMIT 1000",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/assets")
def create_asset(request: Request, payload: dict[str, Any]):
    user = require_user(request, write=True)
    hostname = str(payload.get("hostname") or "").strip()
    if not hostname:
        raise HTTPException(status_code=400, detail="Hostname is required")
    with db() as conn:
        cur = conn.execute(
            """INSERT INTO assets(cmdb_id,hostname,fqdn,ip_address,operating_system,owner,business_unit,environment,criticality,lifecycle_status,notes)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            tuple(payload.get(k) for k in ["cmdb_id","hostname","fqdn","ip_address","operating_system","owner","business_unit","environment","criticality","lifecycle_status","notes"]),
        )
        asset_id = cur.lastrowid
    audit(user["username"], "CREATE", "asset", str(asset_id), hostname)
    return {"id": asset_id}


@app.put("/api/assets/{asset_id}")
def update_asset(asset_id: int, request: Request, payload: dict[str, Any]):
    user = require_user(request, write=True)
    allowed = ["cmdb_id","hostname","fqdn","ip_address","operating_system","owner","business_unit","environment","criticality","lifecycle_status","notes"]
    if not str(payload.get("hostname") or "").strip():
        raise HTTPException(status_code=400, detail="Hostname is required")
    values = [payload.get(k) for k in allowed]
    with db() as conn:
        cur = conn.execute(
            f"UPDATE assets SET {','.join(k+'=?' for k in allowed)}, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            values + [asset_id],
        )
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="Asset not found")
    audit(user["username"], "UPDATE", "asset", str(asset_id), str(payload.get("hostname") or ""))
    return {"ok": True}


@app.get("/api/controls")
def list_controls(request: Request, include_inactive: bool = False):
    user = require_user(request)
    clauses: list[str] = []
    params: list[Any] = []
    if user["role"] == "admin" and user.get("scope_control"):
        clauses.append("name=?")
        params.append(user["scope_control"])
    if not include_inactive:
        clauses.append("active=1")
    sql_where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with db() as conn:
        rows = conn.execute(f"SELECT * FROM controls{sql_where} ORDER BY name", params).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/controls")
def create_control(request: Request, payload: dict[str, Any]):
    user = require_control_manager(request)
    name = str(payload.get("name") or "").strip()
    capability = str(payload.get("capability") or "").strip()
    description = str(payload.get("description") or "").strip()
    initialize_status = str(payload.get("initialize_status") or "").strip()
    try:
        target_coverage = int(payload.get("target_coverage", 100))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Target coverage must be a whole number")
    if not name or not capability:
        raise HTTPException(status_code=400, detail="Control name and capability are required")
    if not 0 <= target_coverage <= 100:
        raise HTTPException(status_code=400, detail="Target coverage must be between 0 and 100")
    if initialize_status and initialize_status not in {"Missing", "Unknown", "Not Applicable"}:
        raise HTTPException(status_code=400, detail="Invalid initial coverage status")
    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO controls(name,capability,description,target_coverage,active) VALUES(?,?,?,?,1)",
                (name, capability, description or None, target_coverage),
            )
            control_id = cur.lastrowid
            initialized = 0
            if initialize_status:
                conn.execute(
                    """INSERT OR IGNORE INTO coverage(asset_id,control_id,status,source)
                       SELECT id, ?, ?, 'Control initialization' FROM assets WHERE lifecycle_status != 'Decommissioned'""",
                    (control_id, initialize_status),
                )
                initialized = conn.execute("SELECT changes()").fetchone()[0]
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="A control with this name already exists")
    audit(user["username"], "CREATE", "control", str(control_id), f"{name}; initialized={initialized}")
    return {"id": control_id, "initialized_assets": initialized}


@app.put("/api/controls/{control_id}")
def update_control(control_id: int, request: Request, payload: dict[str, Any]):
    user = require_control_manager(request)
    name = str(payload.get("name") or "").strip()
    capability = str(payload.get("capability") or "").strip()
    description = str(payload.get("description") or "").strip()
    try:
        target_coverage = int(payload.get("target_coverage", 100))
        active = 1 if bool(payload.get("active", True)) else 0
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid control values")
    if not name or not capability:
        raise HTTPException(status_code=400, detail="Control name and capability are required")
    if not 0 <= target_coverage <= 100:
        raise HTTPException(status_code=400, detail="Target coverage must be between 0 and 100")
    try:
        with db() as conn:
            old = conn.execute("SELECT name FROM controls WHERE id=?", (control_id,)).fetchone()
            if not old:
                raise HTTPException(status_code=404, detail="Control not found")
            conn.execute(
                """UPDATE controls SET name=?, capability=?, description=?, target_coverage=?, active=?,
                   updated_at=CURRENT_TIMESTAMP WHERE id=?""",
                (name, capability, description or None, target_coverage, active, control_id),
            )
            # Preserve scoped administrators when a control is renamed.
            if old["name"] != name:
                conn.execute("UPDATE users SET scope_control=? WHERE scope_control=?", (name, old["name"]))
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="A control with this name already exists")
    audit(user["username"], "UPDATE", "control", str(control_id), name)
    return {"ok": True}


@app.post("/api/controls/{control_id}/initialize")
def initialize_control(control_id: int, request: Request, payload: dict[str, Any]):
    user = require_control_manager(request)
    status = str(payload.get("status") or "Unknown")
    if status not in {"Missing", "Unknown", "Not Applicable"}:
        raise HTTPException(status_code=400, detail="Status must be Missing, Unknown, or Not Applicable")
    with db() as conn:
        control = conn.execute("SELECT name FROM controls WHERE id=?", (control_id,)).fetchone()
        if not control:
            raise HTTPException(status_code=404, detail="Control not found")
        conn.execute(
            """INSERT OR IGNORE INTO coverage(asset_id,control_id,status,source)
               SELECT id, ?, ?, 'Control initialization' FROM assets WHERE lifecycle_status != 'Decommissioned'""",
            (control_id, status),
        )
        initialized = conn.execute("SELECT changes()").fetchone()[0]
    audit(user["username"], "INITIALIZE", "control", str(control_id), f"{status}; assets={initialized}")
    return {"initialized_assets": initialized}


@app.get("/api/coverage")
def list_coverage(request: Request, status: str = "", control_id: int | None = None):
    user = require_user(request)
    where, params = scoped_asset_where(user)
    clauses = []
    if where:
        clauses.append(where.replace(" WHERE ", ""))
    if status:
        clauses.append("cv.status=?")
        params.append(status)
    if control_id is not None:
        clauses.append("c.id=?")
        params.append(control_id)
    if user["role"] == "admin" and user.get("scope_control"):
        clauses.append("c.name=?")
        params.append(user["scope_control"])
    sql_where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with db() as conn:
        rows = conn.execute(
            f"""SELECT cv.id, a.hostname, a.cmdb_id, a.owner, a.criticality, c.id control_id, c.name control_name,
                       cv.status, cv.source, cv.agent_version, cv.last_seen, cv.updated_at
                FROM coverage cv JOIN assets a ON a.id=cv.asset_id JOIN controls c ON c.id=cv.control_id
                {sql_where} ORDER BY a.hostname, c.name LIMIT 5000""",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/import/assets")
async def import_assets(request: Request, file: UploadFile = File(...)):
    user = require_user(request, write=True)
    raw = (await file.read()).decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    required = {"hostname"}
    if not reader.fieldnames or not required.issubset({x.strip() for x in reader.fieldnames}):
        raise HTTPException(status_code=400, detail="Asset CSV requires a hostname header")
    ok = fail = 0
    with db() as conn:
        for row in reader:
            try:
                vals = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
                hostname = vals.get("hostname")
                if not hostname:
                    fail += 1
                    continue
                conn.execute(
                    """INSERT INTO assets(cmdb_id,hostname,fqdn,ip_address,operating_system,owner,business_unit,environment,criticality,lifecycle_status,notes)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(cmdb_id) DO UPDATE SET hostname=excluded.hostname,fqdn=excluded.fqdn,ip_address=excluded.ip_address,
                       operating_system=excluded.operating_system,owner=excluded.owner,business_unit=excluded.business_unit,
                       environment=excluded.environment,criticality=excluded.criticality,lifecycle_status=excluded.lifecycle_status,
                       notes=excluded.notes,updated_at=CURRENT_TIMESTAMP""",
                    (vals.get("cmdb_id") or None, hostname, vals.get("fqdn"), vals.get("ip_address"), vals.get("operating_system"),
                     vals.get("owner"), vals.get("business_unit"), vals.get("environment"), vals.get("criticality") or "Medium",
                     vals.get("lifecycle_status") or "Active", vals.get("notes")),
                )
                ok += 1
            except Exception:
                fail += 1
        conn.execute("INSERT INTO import_logs(import_type,filename,row_count,success_count,failure_count) VALUES(?,?,?,?,?)",
                     ("assets", file.filename or "upload.csv", ok+fail, ok, fail))
    audit(user["username"], "IMPORT", "assets", "", f"{ok} success, {fail} failed")
    return {"success": ok, "failed": fail}


@app.post("/api/import/coverage")
async def import_coverage(request: Request, control_name: str = Form(...), file: UploadFile = File(...)):
    user = require_user(request, write=True)
    if user["role"] == "admin" and user.get("scope_control") and user["scope_control"] != control_name:
        raise HTTPException(status_code=403, detail="Control outside assigned scope")
    raw = (await file.read()).decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(raw))
    fields = {x.strip() for x in (reader.fieldnames or [])}
    if "hostname" not in fields:
        raise HTTPException(status_code=400, detail="Coverage CSV requires hostname header")
    ok = fail = 0
    with db() as conn:
        control = conn.execute("SELECT id FROM controls WHERE name=? AND active=1", (control_name,)).fetchone()
        if not control:
            raise HTTPException(status_code=404, detail="Unknown or inactive control")
        control_id = control[0]
        for row in reader:
            try:
                vals = {k.strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items()}
                asset = conn.execute("SELECT id FROM assets WHERE hostname=? COLLATE NOCASE", (vals.get("hostname"),)).fetchone()
                if not asset:
                    fail += 1
                    continue
                status = vals.get("status") or "Protected"
                if status not in {"Protected","Missing","Unknown","Not Applicable"}:
                    status = "Unknown"
                conn.execute(
                    """INSERT INTO coverage(asset_id,control_id,status,source,agent_version,last_seen)
                       VALUES(?,?,?,?,?,?)
                       ON CONFLICT(asset_id,control_id) DO UPDATE SET status=excluded.status,source=excluded.source,
                       agent_version=excluded.agent_version,last_seen=excluded.last_seen,updated_at=CURRENT_TIMESTAMP""",
                    (asset[0], control_id, status, vals.get("source") or "CSV", vals.get("agent_version"), vals.get("last_seen")),
                )
                ok += 1
            except Exception:
                fail += 1
        conn.execute("INSERT INTO import_logs(import_type,filename,row_count,success_count,failure_count) VALUES(?,?,?,?,?)",
                     (f"coverage:{control_name}", file.filename or "upload.csv", ok+fail, ok, fail))
    audit(user["username"], "IMPORT", "coverage", control_name, f"{ok} success, {fail} failed")
    return {"success": ok, "failed": fail}


@app.get("/api/templates/assets")
def asset_template():
    return HTMLResponse("cmdb_id,hostname,fqdn,ip_address,operating_system,owner,business_unit,environment,criticality,lifecycle_status,notes\n", media_type="text/csv", headers={"Content-Disposition":"attachment; filename=asset_import_template.csv"})


@app.get("/api/templates/coverage")
def coverage_template():
    return HTMLResponse("hostname,status,agent_version,last_seen,source\n", media_type="text/csv", headers={"Content-Disposition":"attachment; filename=coverage_import_template.csv"})


def launch_browser(port: int = 7777) -> None:
    webbrowser.open(f"http://127.0.0.1:{port}")


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("SCT_HOST", "0.0.0.0")
    port = int(os.getenv("SCT_PORT", "7777"))
    threading.Timer(1.2, lambda: launch_browser(port)).start()
    uvicorn.run(app, host=host, port=port, log_level="warning")
