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
├── .env.example
├── .gitignore
├── README.md
├── index.html
├── docker-compose.yml
├── .github/
│   ├── workflows/pipeline.yml          # asli CI/CD pipeline
│   └── workflow/fareeha-ci.yml         # singular folder, GitHub nahi padhta
├── deploy/
│   └── nginx.conf
├── src/
│   └── copilot.py                      # duplicate copilot.py (root par)
├── backend/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── .dockerignore / .env.example / .gitignore
│   ├── pytest.ini                      # testpaths = tests
│   ├── requirements.txt
│   ├── requirements-docker.txt
│   ├── run_cli.sh / run_web.sh
│   ├── README.md
│   ├── test_copilot.py                 # stray, tests/ ke bahar
│   ├── docs/superpowers/specs/2026-10-07-threatnexus-backend-design.md
│   ├── reports/.gitkeep
│   ├── samples/demo.log
│   ├── scripts/build_demo_db.py
│   ├── src/
│   │   ├── __init__.py, app.py, main.py
│   │   ├── log_parser.py, auth_analyzer.py, threat_detector.py
│   │   ├── alert_manager.py, scoring.py, copilot.py
│   │   ├── report_generator.py, database.py
│   │   └── honeypot.py, ssh_decoy.py
│   ├── tests/
│   │   ├── conftest.py
│   │   └── test_api, test_cli, test_copilot, test_honeypot_flask,
│   │       test_parser, test_reports, test_risk_scoring, test_scoring,
│   │       test_socketio, test_ssh_decoy, test_streaming, test_threats (.py)
│   └── honeypot backend/               # naam mein space, purana alag project
│       ├── README.md, requirements.txt
│       ├── honeypot/ (app.py, decoys.py, honeypot.py, __init__.py)
│       └── tests/test_honeypot.py
└── frontend/
    ├── index.html, threats.html, threat-detail.html,
    │   log-events.html, upload.html, README.md
    ├── css/style.css
    ├── assets/ (icons/favicon.svg, images/)
    └── js/
        ├── config.js, head.js, tailwind-config.js
        ├── core/      dom.js, format.js, pagination.js
        ├── ui/        layout.js, severity.js
        ├── pages/     overview, threats, threat-detail, log-events, upload (.js)
        └── services/  api, http-client, live, download, report-builder,
                       mock-api, mock-data (.js)
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
-testing pull request
