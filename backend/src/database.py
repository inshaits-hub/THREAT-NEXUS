"""SQLite storage layer: connection handling, schema setup and queries.

``.env`` is loaded at import time (a tiny stdlib parser - no extra
dependency) so ``DB_PATH`` works for the CLI, the API and pytest alike.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

BACKEND_ROOT = Path(__file__).resolve().parent.parent

LOG_COLUMNS = ("timestamp", "ip", "user", "action", "log_type", "raw_line")
THREAT_COLUMNS = (
    "type",
    "ip",
    "severity",
    "details",
    "path",
    "timestamp",
    "risk_score",
    "attempts",
)

#: Newest threats kept on disk; older rows are pruned so endless decoy
#: traffic cannot fill the database (see ``prune_threats``).
THREAT_RETENTION = 50_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    ip        TEXT,
    user      TEXT,
    action    TEXT,
    log_type  TEXT,
    raw_line  TEXT
);
CREATE TABLE IF NOT EXISTS threats (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT NOT NULL,
    ip         TEXT,
    severity   TEXT,
    details    TEXT,
    path       TEXT,
    timestamp  TEXT,
    risk_score INTEGER DEFAULT 0,
    attempts   INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS summary (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    total_events     INTEGER,
    total_threats    INTEGER,
    critical_threats INTEGER,
    unique_ips       INTEGER,
    created_at       TEXT
);
"""


def load_env(path: Optional[Path] = None) -> None:
    """Populate ``os.environ`` from ``backend/.env`` without overriding
    variables that are already set."""
    env_file = Path(path) if path else BACKEND_ROOT / ".env"
    try:
        lines = env_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env()


def resolve_path(value) -> Path:
    """Relative paths resolve against ``backend/`` regardless of the CWD."""
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else BACKEND_ROOT / path


def get_db_path() -> Path:
    return resolve_path(os.environ.get("DB_PATH", "instance/logs.db"))


def set_db_path(path) -> Path:
    """Point the process at another database file (used by tests / CLI)."""
    os.environ["DB_PATH"] = str(path)
    return get_db_path()


def get_connection(db_path=None) -> sqlite3.Connection:
    path = Path(db_path) if db_path is not None else get_db_path()
    if not path.is_absolute():
        path = resolve_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    # Flask serves requests on threads and gunicorn runs several workers, so
    # readers must not block the writer. WAL allows that; busy_timeout makes a
    # contended write wait instead of raising "database is locked" immediately.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
    except sqlite3.DatabaseError:
        # In-memory or read-only files reject the pragma; the defaults still work.
        pass
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after a database was first created.

    ``CREATE TABLE IF NOT EXISTS`` is a no-op on an existing table, so databases
    written by an older build keep the old shape until they are altered here.
    """
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(threats)")}
    if existing and "attempts" not in existing:
        conn.execute("ALTER TABLE threats ADD COLUMN attempts INTEGER DEFAULT 1")
    if existing and "path" not in existing:
        conn.execute("ALTER TABLE threats ADD COLUMN path TEXT")


def init_db(db_path=None) -> str:
    """Create tables/indexes if missing. Returns the database path."""
    path = Path(db_path) if db_path is not None else get_db_path()
    if not path.is_absolute():
        path = resolve_path(path)
    conn = get_connection(path)
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_ip ON threats(ip)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)"
        )
        conn.commit()
    finally:
        conn.close()
    return str(path)


def _write(sql: str, rows: Iterable[tuple], db_path=None, conn=None) -> int:
    own = conn is None
    connection = conn or get_connection(db_path)
    try:
        rows = list(rows)
        if rows:
            connection.executemany(sql, rows)
        if own:
            connection.commit()
        return len(rows)
    finally:
        if own:
            connection.close()


def insert_logs(events: Iterable[Dict], db_path=None, conn=None) -> int:
    placeholders = ",".join("?" for _ in LOG_COLUMNS)
    columns = ",".join(LOG_COLUMNS)
    rows = [
        tuple(event.get(column) for column in LOG_COLUMNS) for event in events or []
    ]
    return _write(
        f"INSERT INTO logs ({columns}) VALUES ({placeholders})", rows, db_path, conn
    )


def insert_threats(threats: Iterable[Dict], db_path=None, conn=None) -> int:
    placeholders = ",".join("?" for _ in THREAT_COLUMNS)
    columns = ",".join(THREAT_COLUMNS)
    rows = []
    for threat in threats or []:
        try:
            attempts = max(1, int(threat.get("attempts") or threat.get("occurrences") or 1))
        except (TypeError, ValueError):
            attempts = 1
        rows.append(
            (
                threat.get("type"),
                threat.get("ip"),
                threat.get("severity"),
                threat.get("details"),
                threat.get("path"),
                threat.get("timestamp"),
                int(threat.get("risk_score") or 0),
                attempts,
            )
        )
    return _write(
        f"INSERT INTO threats ({columns}) VALUES ({placeholders})", rows, db_path, conn
    )


def save_summary(summary: Dict, db_path=None, conn=None) -> int:
    rows = [
        (
            int(summary.get("total_events", 0)),
            int(summary.get("total_threats", 0)),
            int(summary.get("critical_threats", 0)),
            int(summary.get("unique_ips", 0)),
            summary.get("generated_at")
            or datetime.now().isoformat(sep=" ", timespec="seconds"),
        )
    ]
    return _write(
        "INSERT INTO summary (total_events, total_threats, critical_threats, "
        "unique_ips, created_at) VALUES (?, ?, ?, ?, ?)",
        rows,
        db_path,
        conn,
    )


def get_summary(db_path=None, conn=None) -> Dict[str, int]:
    """Live aggregate over the stored rows (what ``GET /api/v1/summary`` serves)."""
    own = conn is None
    connection = conn or get_connection(db_path)
    try:
        def scalar(sql: str) -> int:
            row = connection.execute(sql).fetchone()
            return int(row[0]) if row else 0

        return {
            "total_events": scalar("SELECT COUNT(*) FROM logs"),
            "total_threats": scalar("SELECT COUNT(*) FROM threats"),
            "critical_threats": scalar(
                "SELECT COUNT(*) FROM threats WHERE upper(severity) = 'CRITICAL'"
            ),
            "unique_ips": scalar(
                "SELECT COUNT(DISTINCT ip) FROM logs "
                "WHERE ip IS NOT NULL AND ip != ''"
            ),
        }
    finally:
        if own:
            connection.close()


def get_threats(
    ip: Optional[str] = None,
    severity: Optional[str] = None,
    limit: Optional[int] = None,
    db_path=None,
    conn=None,
) -> List[Dict]:
    clauses: List[str] = []
    params: List = []
    if ip:
        clauses.append("ip = ?")
        params.append(ip)
    if severity:
        # Severity canonicalization (MED -> MEDIUM, ...) belongs to the caller;
        # see alert_manager.normalize_severity used by the API layer.
        clauses.append("upper(severity) = ?")
        params.append(severity.strip().upper())

    sql = "SELECT * FROM threats"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY CASE upper(severity) WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
    sql += "WHEN 'MEDIUM' THEN 2 ELSE 3 END, risk_score DESC, id ASC"
    if limit:
        sql += f" LIMIT {int(limit)}"

    own = conn is None
    connection = conn or get_connection(db_path)
    try:
        return [dict(row) for row in connection.execute(sql, params).fetchall()]
    finally:
        if own:
            connection.close()


def get_logs(
    limit: Optional[int] = 200,
    ip: Optional[str] = None,
    db_path=None,
    conn=None,
) -> List[Dict]:
    sql = "SELECT * FROM logs"
    params: List = []
    if ip:
        sql += " WHERE ip = ?"
        params.append(ip)
    sql += " ORDER BY id DESC"
    if limit:
        sql += f" LIMIT {int(limit)}"

    own = conn is None
    connection = conn or get_connection(db_path)
    try:
        return [dict(row) for row in connection.execute(sql, params).fetchall()]
    finally:
        if own:
            connection.close()


def get_previous_summaries(limit: int = 10, db_path=None, conn=None) -> List[Dict]:
    own = conn is None
    connection = conn or get_connection(db_path)
    try:
        rows = connection.execute(
            "SELECT * FROM summary ORDER BY id DESC LIMIT ?", (int(limit),)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        if own:
            connection.close()


def get_threat(threat_id, db_path=None, conn=None) -> Optional[Dict]:
    """Single threat row by id, or ``None`` when it does not exist."""
    own = conn is None
    connection = conn or get_connection(db_path)
    try:
        row = connection.execute(
            "SELECT * FROM threats WHERE id = ?", (int(threat_id),)
        ).fetchone()
        return dict(row) if row else None
    finally:
        if own:
            connection.close()


def prune_threats(max_rows: int = THREAT_RETENTION, db_path=None, conn=None) -> int:
    """Keep only the newest ``max_rows`` threats; returns rows deleted.

    Retention backstop so a flood of honeypot hits (or repeated uploads)
    cannot grow the database without bound.
    """
    own = conn is None
    connection = conn or get_connection(db_path)
    try:
        row = connection.execute("SELECT COUNT(*) AS n FROM threats").fetchone()
        total = int(row["n"])
        if total <= max_rows:
            return 0
        cur = connection.execute(
            "DELETE FROM threats WHERE id NOT IN "
            "(SELECT id FROM threats ORDER BY id DESC LIMIT ?)",
            (int(max_rows),),
        )
        if own:
            connection.commit()
        return int(cur.rowcount or 0)
    finally:
        if own:
            connection.close()
