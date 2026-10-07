# ThreatNexus Backend — Completion Design Spec

Date: 2026-10-07 · Status: approved by user ("Design approved — write the spec doc, then build and QA")
Classification: architectural (new subsystems on an existing, verified codebase)

## 1. Context & intent

ThreatNexus is a single-node academic security platform: parse security logs,
detect suspicious behavior, produce high-confidence signals through isolated
honeypot decoys, calculate explainable 0–100 risk scores with time decay,
persist in SQLite, stream alerts to a dashboard via Flask-SocketIO, and
generate remediation playbooks through a rule/template security copilot.

**Already built and verified (must keep passing unchanged):** log parsing →
normalized events, brute-force/web-exploit/scan/anomaly detection, dedup +
severity alerting, SQLite schema/CRUD, Flask REST API, HTML/JSON reports, CLI
(92 tests), hardened FastAPI honeypot standalone app (26 tests).

**Built by this spec (the missing subsystems):**
1. Explainable risk scoring with time decay (`scoring.py`)
2. Security Copilot: analyze → explain → remediate, reviewable-only UFW
   commands (`copilot.py`)
3. Flask-SocketIO live streaming (`threat_alert` events)
4. Honeypot routes ported into the Flask platform (`honeypot.py` blueprint)
   — user decision: **port decoys into Flask**; the FastAPI app stays as an
   optional standalone variant
5. SSH decoy port 2222 trap — user decision: **real listener, opt-in only**
6. Python 3.11+ virtual environment + updated requirements

## 2. Approved approaches

- **A — pure modules + thin integration:** new files are pure/testable;
  `src/app.py` only wires Socket.IO init, emit hooks, and one new endpoint.
  Existing 92 tests stay byte-identical.
- Honeypot: ported into Flask as an isolated blueprint writing
  `HONEYPOT_HIT` rows into the main `threats` table (one DB, one process).
- SSH decoy: threaded TCP listener, disabled unless `SSH_DECOY_ENABLED=1`.

## 3. Architecture / data flow

```
upload | CLI | decoy hit | SSH trap
   → log_parser → threat_detector → alert_manager (dedupe/severity)
   → SQLite (threats/logs/summary)
   → scoring (score = min(100, freq + severity + honeypot), decayed = score·e^(−λ·h))
   → Socket.IO 'threat_alert' → dashboard
   → copilot (on demand): explanation + UFW playbook
```

One Flask process, one DB (`instance/logs.db`). **No schema migration:**
`threats` already has type/ip/severity/details/timestamp/risk_score/attempts;
decay is computed at read time.

## 4. Components & interfaces

### 4.1 scoring.py (new, pure)
- `frequency_points(attempts) -> int` — `min(40, 5 × attempts)`
- `SEVERITY_POINTS = {LOW:10, MEDIUM:25, HIGH:45, CRITICAL:60}`
- `HONEYPOT_BONUS = 80`
- `compute_score(attempts, severity, honeypot: bool) -> int` —
  `min(100, frequency + severity + bonus)`
- `decay(score, hours, lam=DEFAULT_LAMBDA) -> float` —
  `score × exp(−λ·hours)`; `DEFAULT_LAMBDA = 0.05` (≈14 h half-life),
  overridable per call; app reads env `RISK_DECAY_LAMBDA`
- `score_factors(attempts, severity, honeypot, timestamp=None) -> dict` —
  `{frequency_points, severity_points, honeypot_bonus, score, decay_hours,
  lambda, decayed_score}` — the "explainable number"
- Honeypot hits: severity CRITICAL + bonus ⇒ raw score 100.

### 4.2 copilot.py (new, pure — no subprocess/os.system/eval, ever)
- `analyze(threat) -> {attack_type, title, ip, evidence, severity}`
- `explain(threat) -> str` — plain-English template per rule type
  (SSH_BRUTE_FORCE, SSH_BRUTE_FORCE_SUCCESS, SQL_INJECTION, XSS_ATTEMPT,
  DIRECTORY_TRAVERSAL, TRAFFIC_SPIKE, OFF_HOUR_ADMIN, WEB_DIRECTORY_SCAN,
  PORT_SCAN, HONEYPOT_HIT, generic fallback)
- `remediate(threat) -> {steps: [str], commands: [str], warnings: [str],
  note: str}` — `sudo ufw deny from <IP>` style strings; **data returned to
  the user, never executed**; `note` states review-before-run explicitly
- `_safe_ip(ip)` — `ipaddress.ip_address` validation; invalid/missing →
  literal `<ATTACKER_IP>` placeholder + warning
- LLM: not a dependency; module exposes a documented future
  `LLM_ENABLED` hook point only (stub, off)
- Endpoint: `GET /api/v1/copilot/<int:threat_id>` →
  `{threat_id, analysis, explanation, playbook}` | 404 unknown id

### 4.3 Streaming (flask-socketio)
- Deps: `flask-socketio>=5.3,<6`, `simple-websocket>=1.0,<2`
  (threading async mode: works with Werkzeug dev server and gunicorn
  `--threads`; falls back to long-polling if WebSocket is unavailable)
- `SocketIO(app, async_mode="threading",
  cors_allowed_origins=env SOCKETIO_ALLOWED_ORIGINS or "*")` inside
  `create_app`; stored in `app.extensions`
- Emits `threat_alert` for every new alert: upload path, decoy hits, SSH
  trap. Payload = threat dict + `score`, `decayed_score`, `score_factors`,
  `copilot: {explanation, commands}`
- `__main__` switches to `socketio.run(app, ..., allow_unsafe_werkzeug=True)`
  (dev only); gunicorn target `src.app:app` unchanged.

### 4.4 honeypot.py (Flask blueprint, new)
- The 10 decoy routes + fake bodies from the FastAPI app, registered on a
  `Blueprint("honeypot")` with both slash variants (`/wp-admin` +
  `/wp-admin/`, `/phpmyadmin` + `/phpmyadmin/`) so scanners are recorded
  without redirects; methods GET/POST/PUT/DELETE/HEAD/OPTIONS
- Same hardening: XFF first hop only, `_sanitize_field` bounds
  (IP 45, UA 256, control chars stripped)
- Hit handling: build threat
  `{type: HONEYPOT_HIT, severity: CRITICAL, ip, details, timestamp,
  risk_score: compute_score(...)=100, attempts: 1}` →
  `database.insert_threats` → retention prune → notify (Socket.IO) →
  return the plausible fake body (attacker not tipped off)
- Retention: `database.prune_threats(max_rows=50_000)` keeps newest rows so
  endless decoy traffic cannot fill the disk
- Isolation invariants (test-enforced): decoy paths disjoint from real
  routes; real requests never create threats; decoy hits never reach real
  handlers
- The FastAPI app in `honeypot backend/` remains as the standalone variant.

### 4.5 ssh_decoy.py (new)
- `SSHDecoyServer(host, port)` — daemon thread, `accept()` loop with stop
  timeout; on connect: record `HONEYPOT_HIT` (details name the decoy port)
  → notify → close. **Never speaks SSH, never executes anything.**
- Enabled only when `SSH_DECOY_ENABLED` ∈ {1,true,yes}; port
  `SSH_DECOY_PORT` (default 2222), host `SSH_DECOY_HOST` (default 0.0.0.0 —
  explicit opt-in makes exposure intentional); `create_app` starts it and
  registers `atexit` stop; failure to bind logs a warning, never crashes.

### 4.6 API surface changes
- `/api/v1/threats` payload gains: `score`, `decayed_score`,
  `score_factors` (existing fields unchanged — `risk_score` stays the IP
  reputation number, byte-identical)
- New: `GET /api/v1/copilot/<id>`
- New: Socket.IO event `threat_alert`
- New: 12 decoy paths (10 + 2 slash variants)
- Env: `RISK_DECAY_LAMBDA`, `SSH_DECOY_ENABLED/PORT/HOST`,
  `SOCKETIO_ALLOWED_ORIGINS`

## 5. Error handling

- Bind failures / Socket.IO absence: log + degrade, never break HTTP routes
- Copilot on unknown threat id → 404; unknown threat type → generic playbook
- Upload/DB transaction behavior unchanged (existing rollback path)
- All attacker-controlled stored fields bounded (shared sanitization rules)

## 6. Testing & QA (definition of done)

New suites: `tests/test_scoring.py`, `tests/test_copilot.py`,
`tests/test_honeypot_flask.py`, `tests/test_streaming.py`,
`tests/test_ssh_decoy.py` covering: formula/cap/decay exactness + monotonic
decay; playbook format, IP validation & injection rejection,
no-execution-primitives source assertion; every decoy records a bounded
CRITICAL HONEYPOT_HIT with factors, isolation both directions, retention
pruning; `threat_alert` emission for upload and decoy via Socket.IO test
client; SSH listener records a connection and is off by default.

Gates: **all 92 existing + 26 FastAPI tests stay green**, new suites pass,
then a live smoke: run server from the venv → upload attack log → Socket.IO
client receives `threat_alert` → curl a decoy → copilot returns UFW
playbook → connect to the SSH trap → verify events → stop everything.
Exit codes captured for every suite run.

## 7. Environment

- `.venv` (Python 3.11+; host runs 3.14.6) created and used for verification
- `requirements.txt`: add `flask-socketio`, `simple-websocket`
  (`requirements-docker.txt` inherits via `-r`)

## 8. Implementation plan (ordered)

1. Spec doc (this file) — user pre-approved build after spec
2. requirements + `.venv` install
3. `scoring.py` + `test_scoring.py`
4. `copilot.py` + `test_copilot.py`
5. `database.prune_threats` + `honeypot.py` blueprint + `test_honeypot_flask.py`
6. `ssh_decoy.py` + `test_ssh_decoy.py`
7. `app.py` wiring: Socket.IO, emits, copilot endpoint, decayed payload +
   `test_streaming.py`
8. Full QA: both suites + live smoke; README endpoint/env notes

Out of scope: frontend/dashboard changes, real LLM integration, production
deployment changes, changes to the standalone FastAPI honeypot.
