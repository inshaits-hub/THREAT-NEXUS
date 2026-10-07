# THREAT-NEXUS


Senior project: a log-analysis platform that ingests raw server logs, detects
threats with heuristic rules, and reports the results through both a REST API
and a standalone CLI.

- `backend/` — Flask REST API, heuristic threat engine, CLI, reports, tests
- `frontend/` — dashboard UI: overview, threats, log events, upload
- `index.html` — project landing page, module specs and the API contract

## Quick start

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env

./run_web.sh --demo        # REST API on http://127.0.0.1:5000, seeded with demo data
./run_cli.sh               # or analyze from the terminal, no server needed
python -m pytest           # 90 tests
```

Or with Docker:

```bash
cd backend
docker compose up --build          # API only, on http://localhost:5000
docker compose run --rm cli        # one-shot CLI run
```

## Run the dashboard

The frontend is plain HTML/CSS/JS with no build step, but it must be served
over HTTP (not opened as `file://`) and it needs the API running. Start each
in its own terminal.

macOS / Linux:

```bash
# terminal 1 - API seeded with demo data
cd backend && ./run_web.sh --demo

# terminal 2 - static server for the dashboard
cd frontend && python3 -m http.server 8123
# open http://127.0.0.1:8123
```

Windows (PowerShell):

```powershell
# terminal 1 - API seeded with demo data
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
py scripts\build_demo_db.py --fresh
py src\app.py

# terminal 2 - static server for the dashboard
cd frontend
py -m http.server 8123
# open http://127.0.0.1:8123
```

On `localhost`/`127.0.0.1` the dashboard automatically targets the API at
`http://127.0.0.1:5000`, so the rail shows **Live backend**. (The backend
allows cross-origin requests, so the two ports do not need a proxy for local
development.) Append `?mock=1` to any page to browse the built-in fixture
data instead (**Demo data**), or `?mock=empty` / `?mock=error` for those
states.

## Deployment

One command runs the whole stack — Flask behind gunicorn, plus nginx serving
the dashboard and reverse-proxying `/api/`:

```bash
docker compose up --build          # dashboard on http://localhost:8080
cp .env.example .env               # optional: set WEB_PORT / SECRET_KEY first
docker compose down -v             # stop and discard the database
```

Because nginx serves the pages and the API from the same origin, the
frontend's default `BASE_URL` of `/api/v1` just works — no CORS, no
hardcoded host. Deploying the two on separate hosts instead? Set the API
address without editing code, either in `frontend/index.html`'s `<head>`:

```html
<meta name="api-base-url" content="https://api.example.com/api/v1">
```

or via an inline script before `js/config.js`:

```html
<script>window.__LOG_ANALYZER_CONFIG__ = { baseUrl: "https://api.example.com/api/v1" };</script>
```

Set `baseUrl` and `useMock` in the same object to override both.

## Folder layout

```text
THREAT-NEXUS/
├── backend/                # see backend/README.md for the full map
│   ├── src/                # parser, analyzers, threat engine, alerts, reports, API, CLI
│   ├── tests/              # pytest suite
│   ├── samples/demo.log    # mixed auth.log + nginx + syslog capture
│   ├── scripts/            # demo database builder
│   ├── Dockerfile          # gunicorn image, non-root, HEALTHCHECK
│   └── run_cli.sh / run_web.sh
├── frontend/               # dashboard UI (static, no build step)
├── deploy/nginx.conf       # serves frontend/ and proxies /api/ to the API
├── docker-compose.yml      # full stack: api + web
├── .env.example            # WEB_PORT, SECRET_KEY for the compose stack
├── index.html              # landing page + API contract
└── .gitignore
```

## API contract

The endpoints the dashboard consumes, all under `http://localhost:5000`:

| Method | Endpoint | Returns |
|--------|----------|---------|
| GET | `/api/v1/summary` | `{total_events, total_threats, critical_threats, unique_ips}` |
| POST | `/api/v1/upload` | multipart `file` → `{status, filename, parsed_events, threats_detected, ...}` |
| GET | `/api/v1/threats?ip=&severity=` | alert list with `badge`, `title`, `risk_score`, `attempts` |
| GET | `/api/v1/export/report?format=` | `html` or `json` report download |

Also available: `/api/v1/events`, `/api/v1/stats`, `/api/v1/health`.

## For team members

Read `backend/README.md` first — it documents every module, the threat rules,
the database schema and the configuration options. Secrets and local state
(`.env`, `instance/`, `reports/`, `.venv/`) stay out of Git via `.gitignore`.


## Live alerts


New threats are pushed to the dashboard in real time over Socket.IO
(`threat_alert` event). The Threats page shows a **Live / Disconnected**
badge under the title and updates without a refresh.

- Start the API with `py src\app.py` (uses `socketio.run`).
- In Docker the API runs gunicorn with **one** worker and many threads;
  do not raise `WEB_CONCURRENCY` above 1 or live alerts will be lost.
- nginx proxies `/socket.io/` with WebSocket upgrade headers.
- Mock mode (`?mock=1`) never opens a socket.