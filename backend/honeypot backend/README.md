# ThreatNexus — Honeypot Deception Engine

A decoy-endpoint detection backend. It plants convincing fake endpoints that
no legitimate user or integration ever needs. A hit on any of them is a
high-confidence signal that the requester is scanning or exploiting, so every
hit raises a **CRITICAL** alert.

> **Noob analogy:** a bank puts a convincing fake safe in a room. Normal
> employees never touch it. If someone opens it, the bank gets a very strong
> signal that the person is suspicious.

**Design goal:** zero false positives for deliberately unreachable decoys.
This is a design goal for the decoy set, not a mathematical guarantee for
every detector in the system.

## Quick start

```bash
# run the test suite
python -m pytest tests/ -q

# start the server
uvicorn honeypot.app:create_app --factory --host 127.0.0.1 --port 8000
```

Then:

```bash
curl http://127.0.0.1:8000/api/health      # real route -> {"status":"ok"}
curl http://127.0.0.1:8000/wp-login.php    # DECOY -> fake page + CRITICAL alert
curl http://127.0.0.1:8000/api/alerts      # real route -> lists alerts
```

## Decoy routes (documented decoys)

⚠️ **Every path below is a decoy.** None of them is reachable from any real
feature, linked anywhere, or included in the OpenAPI schema. Any request to
one of them — any method — records a CRITICAL alert.

| Decoy path               | Masquerades as              | Fake response            |
|--------------------------|-----------------------------|--------------------------|
| `/api/v1/admin/backup`   | Admin backup API            | JSON backup descriptor   |
| `/wp-login.php`          | WordPress login form        | HTML login page          |
| `/wp-admin/`             | WordPress admin dashboard   | HTML dashboard           |
| `/xmlrpc.php`            | WordPress XML-RPC           | XML fault response       |
| `/.env`                  | Leaked environment file     | Fake env vars            |
| `/.git/config`           | Leaked git config           | Fake git config          |
| `/phpmyadmin/`           | phpMyAdmin login            | HTML login page          |
| `/admin/config.json`     | Admin config file           | JSON config              |
| `/cgi-bin/test-cgi`      | Legacy CGI script           | Plain text               |
| `/server-status`         | Apache server-status        | Plain text               |

The registry lives in one place: `HONEYPOT_ROUTES` in
[honeypot/honeypot.py](honeypot/honeypot.py).

## Alerts

Every decoy hit produces an alert with:

- **severity**: always `CRITICAL`
- **ip**: first `X-Forwarded-For` hop if present, else the socket peer address
- **path**: the exact decoy path requested
- **method**: HTTP method used
- **user_agent**: captured for attribution
- **timestamp**: UTC ISO-8601

Alerts are persisted to SQLite (`alerts.db` by default) via `AlertStore`, so
they survive restarts. List them with the **real** route `GET /api/alerts`.

```json
{
  "count": 1,
  "alerts": [
    {
      "severity": "CRITICAL",
      "ip": "203.0.113.7",
      "path": "/wp-login.php",
      "method": "GET",
      "user_agent": "evil-scanner/1.0",
      "timestamp": "2026-10-07T12:00:00.000000+00:00"
    }
  ]
}
```

## Isolation from real routes

Decoys and real routes are structurally separate:

- Decoy handlers live only in [honeypot/decoys.py](honeypot/decoys.py) and are
  built by `create_decoy_router()`.
- Real routes (`/api/health`, `/api/alerts`) are registered by
  `_register_real_routes()` in [honeypot/app.py](honeypot/app.py).
- The decoy router is included with `include_in_schema=False`, so decoys never
  appear in `/docs` or `/openapi.json`.
- The two path sets are disjoint — enforced by
  `test_decoy_paths_never_overlap_real_routes`.

Tests assert both directions: real requests never create alerts, and decoy
hits never reach production handlers.

## Security notes

Hardening that keeps requester-controlled data and the host safe:

- **Bounded alert fields** — `ip` (first `X-Forwarded-For` hop / peer
  address) and `user_agent` are requester-controlled. `AlertStore.record_hit`
  strips control characters and truncates them (45 / 256 chars), so a
  scanner cannot bloat or poison `alerts.db` with oversized headers.
- **Retention cap** — the store keeps only the newest 50,000 alerts
  (`AlertStore(..., max_alerts=N)`) and prunes older rows on insert, so
  endless decoy traffic cannot fill the disk.
- **Optional alerts auth** — set `ALERTS_API_KEY` in the environment to
  require a matching `X-API-Key` header on `GET /api/alerts` (constant-time
  compare). With no key set the endpoint stays open, which keeps the
  documented `curl` flow working.
- **Trusted-proxy caveat** — the first `X-Forwarded-For` hop is trusted, so
  a client connecting directly can spoof its recorded IP. Behind a reverse
  proxy, that proxy should overwrite the header; bind to `127.0.0.1` (the
  quick-start default) when the API should not be reachable by others.
- **Runtime DB ignored** — `alerts.db` is git-ignored so recorded hits
  never end up in a commit.

```bash
# lock the alert listing behind a key
ALERTS_API_KEY=change-me uvicorn honeypot.app:create_app --factory --port 8000
curl -H "X-API-Key: change-me" http://127.0.0.1:8000/api/alerts   # 200
curl http://127.0.0.1:8000/api/alerts                            # 401
```

## Project layout

```
honeypot/
  __init__.py     # public API exports
  honeypot.py     # HONEYPOT_ROUTES registry, Alert, AlertStore, raise_honeypot_alert
  decoys.py       # isolated decoy router + plausible fake responses
  app.py          # FastAPI app factory (decoys first, real API second)
tests/
  test_honeypot.py
README.md
```

## Tests

```bash
python -m pytest tests/ -q
```

The suite covers: every decoy raising a CRITICAL alert with IP/path/timestamp,
persistence across store reopens, POST hits, decoy/OpenAPI isolation, real
routes producing no alerts, the `X-Forwarded-For` IP logic, plus the
hardening above (bounded attacker fields, control-character stripping,
retention pruning, optional `ALERTS_API_KEY`).

## Roadmap

- SSH decoy on port 2222 (blueprint concept; not yet implemented)
- Alert forwarding (webhook/email) and de-duplication
