"""Honeypot Deception Engine.

Defines decoy routes and the alert machinery. A hit on any route listed in
``HONEYPOT_ROUTES`` raises a CRITICAL alert recording the source IP, the
requested path, and the timestamp.

Design goal: zero false positives for deliberately unreachable decoys.
This is a design goal for the decoy set, not a mathematical guarantee for
every detector in the system.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable

#: Severity used for every honeypot alert. A hit on a decoy route is a
#: high-confidence signal: no normal user has a legitimate reason to
#: request an intentionally hidden endpoint.
CRITICAL = "CRITICAL"

#: Bounds for requester-controlled alert fields. ``X-Forwarded-For`` and
#: ``User-Agent`` are attacker-controlled, so they are sanitized before
#: reaching SQLite: 45 chars is the longest textual IP representation,
#: and real user agents fit well inside 256. Without these bounds a
#: scanner could bloat (or poison) the alerts database with huge headers.
MAX_IP_LENGTH = 45
MAX_USER_AGENT_LENGTH = 256

#: Default retention: the newest N alerts are kept, older rows are pruned
#: so endless decoy traffic cannot fill the disk.
DEFAULT_MAX_ALERTS = 50_000


def _sanitize_field(value, limit: int) -> str:
    """Drop control characters and cap length (requester-controlled input)."""
    text = "" if value is None else str(value)
    return "".join(ch for ch in text if ch.isprintable())[:limit]


#: The decoy routes. These paths are deliberately plausible-looking but
#: must never be linked from, or reachable through, any real feature.
#: Isolation is a documented invariant: see README.md.
HONEYPOT_ROUTES: dict[str, str] = {
    "/api/v1/admin/backup": "fake_admin_backup",
    "/wp-login.php": "fake_wordpress_login",
    "/wp-admin/": "fake_wordpress_admin",
    "/xmlrpc.php": "fake_wordpress_xmlrpc",
    "/.env": "fake_env_file",
    "/.git/config": "fake_git_config",
    "/phpmyadmin/": "fake_phpmyadmin",
    "/admin/config.json": "fake_admin_config",
    "/cgi-bin/test-cgi": "fake_cgi",
    "/server-status": "fake_server_status",
}


class HoneypotHit(Exception):
    """Raised when a decoy route is requested.

    Carries everything needed to persist a CRITICAL alert.
    """

    def __init__(self, ip: str, path: str, method: str = "GET",
                 user_agent: str = "") -> None:
        self.ip = ip
        self.path = path
        self.method = method
        self.user_agent = user_agent
        super().__init__(f"honeypot hit: {method} {path} from {ip}")


@dataclass(frozen=True)
class Alert:
    """A recorded security alert."""

    severity: str
    ip: str
    path: str
    method: str
    user_agent: str
    timestamp: str  # UTC ISO-8601

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def raise_honeypot_alert(ip: str, path: str, method: str = "GET",
                         user_agent: str = "") -> HoneypotHit:
    """Build (but do not persist) a CRITICAL honeypot alert signal.

    Persistence happens when the app catches :class:`HoneypotHit` and
    writes it through :class:`AlertStore`. Keeping this separate makes
    the detection rule trivially testable.
    """
    return HoneypotHit(ip=ip, path=path, method=method, user_agent=user_agent)


def is_honeypot_path(path: str) -> bool:
    """Return True if ``path`` is a registered decoy route."""
    return path in HONEYPOT_ROUTES


class AlertStore:
    """Thread-safe SQLite store for honeypot alerts."""

    def __init__(self, db_path: str = "alerts.db",
                 max_alerts: int = DEFAULT_MAX_ALERTS) -> None:
        self._db_path = db_path
        self._max_alerts = max(1, int(max_alerts))
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    severity TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    path TEXT NOT NULL,
                    method TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                )
                """
            )
            self._rows = int(
                self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            )

    def save(self, alert: Alert) -> int:
        """Persist an alert; returns the new row id."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO alerts (severity, ip, path, method, user_agent,"
                " timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (alert.severity, alert.ip, alert.path, alert.method,
                 alert.user_agent, alert.timestamp),
            )
            # Retention: keep only the newest ``max_alerts`` rows so endless
            # decoy traffic cannot fill the disk.
            self._rows += 1
            if self._rows > self._max_alerts:
                self._conn.execute(
                    "DELETE FROM alerts WHERE id NOT IN "
                    "(SELECT id FROM alerts ORDER BY id DESC LIMIT ?)",
                    (self._max_alerts,),
                )
                self._rows = self._max_alerts
        return int(cur.lastrowid)

    def record_hit(self, hit: HoneypotHit) -> Alert:
        """Convert a :class:`HoneypotHit` into a persisted CRITICAL alert.

        ``ip`` and ``user_agent`` are requester-controlled: they are
        sanitized and length-bounded here (the single persistence path)
        before they reach SQLite.
        """
        alert = Alert(
            severity=CRITICAL,
            ip=_sanitize_field(hit.ip, MAX_IP_LENGTH),
            path=hit.path,
            method=hit.method,
            user_agent=_sanitize_field(hit.user_agent, MAX_USER_AGENT_LENGTH),
            timestamp=_utc_now(),
        )
        self.save(alert)
        return alert

    def list_alerts(self, limit: int = 100) -> list[dict[str, str]]:
        """Newest-first list of alerts as plain dicts."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT severity, ip, path, method, user_agent, timestamp"
                " FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()
        return int(row["n"])

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def build_alerts(alerts: Iterable[Alert]) -> list[dict[str, str]]:
    """Convenience helper: Alerts -> list of dicts (used by tests/tools)."""
    return [a.as_dict() for a in alerts]
