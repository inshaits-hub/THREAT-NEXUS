"""Honeypot deception routes for the Flask platform.

The 10 documented decoy paths from the standalone FastAPI variant,
ported into the main app so a hit becomes a scored ``HONEYPOT_HIT``
threat in the same SQLite database and streams over Socket.IO in the
same process (single-node design).

Isolation invariants (test-enforced in ``tests/test_honeypot_flask.py``):

* decoy paths are disjoint from every real API route,
* a real request never creates a threat,
* a decoy hit never reaches a production handler.

Hardening carried over from the verified FastAPI build: the first
``X-Forwarded-For`` hop only, requester-controlled fields sanitized and
bounded (IP 45 chars, User-Agent 256 chars, control characters
stripped), and threat-table retention via ``database.prune_threats``.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

from flask import Blueprint, Response, current_app, has_app_context, request

try:  # package import
    from . import database, scoring
except ImportError:  # script import (``python src/app.py``)
    import database
    import scoring

log = logging.getLogger(__name__)

#: Bounds for requester-controlled alert fields (see spec 4.4).
MAX_IP_LENGTH = 45
MAX_USER_AGENT_LENGTH = 256

#: Every HTTP method a scanner might use against a decoy.
DECOY_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]

#: (path, fake-response kind). Both slash variants are registered for the
#: two slash-terminated routes so scanners are recorded without relying
#: on redirects.
DECOY_ROUTES = [
    ("/api/v1/admin/backup", "fake_admin_backup"),
    ("/wp-login.php", "fake_wordpress_login"),
    ("/wp-admin/", "fake_wordpress_admin"),
    ("/wp-admin", "fake_wordpress_admin"),
    ("/xmlrpc.php", "fake_wordpress_xmlrpc"),
    ("/.env", "fake_env_file"),
    ("/.git/config", "fake_git_config"),
    ("/phpmyadmin/", "fake_phpmyadmin"),
    ("/phpmyadmin", "fake_phpmyadmin"),
    ("/admin/config.json", "fake_admin_config"),
    ("/cgi-bin/test-cgi", "fake_cgi"),
    ("/server-status", "fake_server_status"),
]

_FAKE_WP_LOGIN = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Log In &lsaquo; WordPress</title>
</head>
<body class="login wp-core-ui">
<form name="logform" action="/wp-login.php" method="post">
    <label for="user_login">Username or Email Address</label>
    <input type="text" name="log" id="user_login" value="">
    <label for="user_pass">Password</label>
    <input type="password" name="pwd" id="user_pass" value="">
    <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary" value="Log In">
    <input type="hidden" name="redirect_to" value="/wp-admin/">
</form>
</body>
</html>
"""

_FAKE_WP_ADMIN = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Dashboard &lsaquo; WordPress</title></head>
<body class="wp-admin wp-core-ui">
<h1>Dashboard</h1>
<p>Welcome to WordPress.</p>
</body>
</html>
"""

_FAKE_PHPMYADMIN = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>phpMyAdmin</title></head>
<body>
<h1>phpMyAdmin</h1>
<form action="index.php" method="post">
  <label>Username <input type="text" name="pma_username"></label>
  <label>Password <input type="password" name="pma_password"></label>
  <input type="submit" value="Go">
</form>
</body>
</html>
"""

_FAKE_ENV = """APP_NAME=ThreatNexus
APP_ENV=production
APP_KEY=base64:REPLACE_ME
APP_DEBUG=false
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
"""

_FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = https://github.com/example/threatnexus.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
"""

_FAKE_BACKUP = """{
  "status": "ok",
  "backup": {
    "id": "bkp-000000",
    "created_at": "1970-01-01T00:00:00Z",
    "size_bytes": 0,
    "location": "/var/backups/threatnexus"
  }
}
"""

_FAKE_CONFIG_JSON = """{
  "environment": "production",
  "debug": false,
  "database": {"host": "127.0.0.1", "port": 3306}
}
"""

_FAKE_XMLRPC = """<?xml version="1.0"?>
<methodResponse><fault><faultCode>-32600</faultCode><faultString>Invalid request</faultString></fault></methodResponse>
"""

_FAKE_CGI = """Content-type: text/plain

CGI test environment
"""

_FAKE_STATUS = """Apache Server Status for 127.0.0.1 (via 127.0.0.1)
Server Version: Apache/2.4.57 (Unix)
"""

_FAKE_RESPONSES = {
    "fake_admin_backup": ("application/json", _FAKE_BACKUP),
    "fake_wordpress_login": ("text/html; charset=utf-8", _FAKE_WP_LOGIN),
    "fake_wordpress_admin": ("text/html; charset=utf-8", _FAKE_WP_ADMIN),
    "fake_wordpress_xmlrpc": ("text/xml; charset=utf-8", _FAKE_XMLRPC),
    "fake_env_file": ("text/plain; charset=utf-8", _FAKE_ENV),
    "fake_git_config": ("text/plain; charset=utf-8", _FAKE_GIT_CONFIG),
    "fake_phpmyadmin": ("text/html; charset=utf-8", _FAKE_PHPMYADMIN),
    "fake_admin_config": ("application/json", _FAKE_CONFIG_JSON),
    "fake_cgi": ("text/plain; charset=utf-8", _FAKE_CGI),
    "fake_server_status": ("text/plain; charset=utf-8", _FAKE_STATUS),
}

_record_lock = threading.Lock()


def sanitize_field(value, limit: int) -> str:
    """Drop control characters and cap length (requester-controlled input)."""
    text = "" if value is None else str(value)
    return "".join(ch for ch in text if ch.isprintable())[:limit]


def client_ip() -> str:
    """First X-Forwarded-For hop if present, else the socket peer."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        hop = forwarded.split(",")[0].strip()
        if hop:
            return sanitize_field(hop, MAX_IP_LENGTH)
    return sanitize_field(request.remote_addr or "unknown", MAX_IP_LENGTH)


def record_honeypot_hit(ip, details, path=None, notify=None) -> dict:
    """Persist a CRITICAL ``HONEYPOT_HIT`` threat and notify listeners.

    Shared by the decoy routes (request context) and the SSH decoy
    listener (background thread). ``notify`` defaults to the app's
    Socket.IO notifier when running inside an application context.
    Never raises: a recording failure must not tip off the attacker by
    turning the fake response into a 500.
    """
    threat = {
        "type": "HONEYPOT_HIT",
        "ip": sanitize_field(ip, MAX_IP_LENGTH),
        "severity": "CRITICAL",
        "details": sanitize_field(details, 512),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_score": scoring.compute_score(
            attempts=1, severity="CRITICAL", honeypot=True
        ),
        "attempts": 1,
    }
    if path:
        threat["path"] = path
    try:
        with _record_lock:
            conn = database.get_connection()
            try:
                database.insert_threats([threat], conn=conn)
                database.prune_threats(conn=conn)
                conn.commit()
            finally:
                conn.close()
    except Exception:  # noqa: BLE001 - decoys must still answer like the real thing
        log.exception("failed to persist honeypot hit from %s", ip)
        return threat

    if notify is None and has_app_context():
        notify = current_app.extensions.get("threat_notifier")
    if notify is not None:
        try:
            notify(dict(threat))
        except Exception:  # noqa: BLE001 - streaming must never break a response
            log.exception("failed to stream honeypot hit from %s", ip)
    return threat


def create_honeypot_blueprint() -> Blueprint:
    """Build the isolated decoy blueprint (10 decoys, 12 paths)."""
    bp = Blueprint("honeypot", __name__)

    for index, (path, kind) in enumerate(DECOY_ROUTES):
        content_type, body = _FAKE_RESPONSES[kind]
        endpoint = f"decoy_{index}_{kind}"

        def view(_body=body, _ct=content_type, _path=path):
            record_honeypot_hit(
                ip=client_ip(),
                details=(
                    f"Decoy '{_path}' requested by requester "
                    f"({request.method}, user-agent: "
                    f"{sanitize_field(request.headers.get('User-Agent', ''), 120)})"
                ),
                path=_path,
            )
            return Response(_body, mimetype=_ct)

        view.__name__ = endpoint
        bp.add_url_rule(path, endpoint=endpoint, view_func=view,
                        methods=DECOY_METHODS)

    return bp
