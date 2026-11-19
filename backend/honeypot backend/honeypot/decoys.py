"""Decoy routes — isolated from every real route in the app.

This module is the ONLY place decoy paths are wired into the HTTP layer.
Handlers record a CRITICAL alert through :class:`AlertStore` and then
return a plausible-looking fake response so the attacker is not tipped
off. The router produced here is registered before the real API router
and excluded from the OpenAPI schema (``include_in_schema=False``), so
decoys never appear in docs or interact with production handlers.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from .honeypot import HONEYPOT_ROUTES, AlertStore, raise_honeypot_alert

#: Every HTTP method a scanner might use against a decoy.
DECOY_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]

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

_FAKE_RESPONSES: dict[str, tuple[str, str]] = {
    # kind -> (content_type, body)
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


def client_ip(request: Request) -> str:
    """Best-effort client IP: first X-Forwarded-For hop, else socket peer."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def create_decoy_router(store: AlertStore) -> APIRouter:
    """Build the isolated decoy router.

    Every route in ``HONEYPOT_ROUTES`` gets a handler that records a
    CRITICAL alert (IP, path, timestamp) and replies with a plausible
    fake response.
    """
    router = APIRouter(tags=["decoy"], include_in_schema=False)

    def make_handler(path: str, kind: str):
        content_type, body = _FAKE_RESPONSES[kind]

        async def handler(request: Request) -> Response:
            hit = raise_honeypot_alert(
                ip=client_ip(request),
                path=request.url.path,
                method=request.method,
                user_agent=request.headers.get("user-agent", ""),
            )
            store.record_hit(hit)
            return Response(content=body, media_type=content_type)

        handler.__name__ = f"decoy_{kind}"
        return handler

    for path, kind in HONEYPOT_ROUTES.items():
        router.add_api_route(
            path,
            make_handler(path, kind),
            methods=DECOY_METHODS,
            include_in_schema=False,
        )

    return router
