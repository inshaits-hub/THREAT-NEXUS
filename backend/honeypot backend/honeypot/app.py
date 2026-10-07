"""FastAPI application: decoy router + real API, kept strictly separate.

Registration order matters for clarity: the decoy router is included
first, then the real API router. The two routers share no paths, so a
real request can never raise an alert and a decoy hit never reaches a
production handler. Tests in ``tests/test_honeypot.py`` assert both
directions.
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException

from .decoys import create_decoy_router
from .honeypot import AlertStore

#: Default location of the alerts database (next to the package root).
DEFAULT_DB_PATH = str(Path(__file__).resolve().parent.parent / "alerts.db")


def _require_alerts_key(x_api_key: str | None = Header(None)) -> None:
    """Optional guard for ``GET /api/alerts``.

    When ``ALERTS_API_KEY`` is set in the environment, callers must send
    the same value in the ``X-API-Key`` header (constant-time compare).
    With no key configured the endpoint stays open for local use, which
    keeps the documented ``curl`` flow working.
    """
    expected = os.environ.get("ALERTS_API_KEY")
    if expected and not hmac.compare_digest(
        (x_api_key or "").encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


def create_app(db_path: str = DEFAULT_DB_PATH) -> FastAPI:
    """Build the ThreatNexus app: decoys first, real API second."""
    store = AlertStore(db_path)

    app = FastAPI(
        title="ThreatNexus",
        version="1.0.0",
        description="ThreatNexus API. Decoy endpoints are intentionally "
                    "hidden from this schema.",
    )
    app.state.alert_store = store

    # 1. Decoys — isolated, undocumented in OpenAPI, registered first.
    app.include_router(create_decoy_router(store))

    # 2. Real API routes.
    _register_real_routes(app, store)

    return app


def _register_real_routes(app: FastAPI, store: AlertStore) -> None:
    from fastapi import Query

    @app.get("/api/health", tags=["real"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/alerts", tags=["real"],
             dependencies=[Depends(_require_alerts_key)])
    def list_alerts(limit: int = Query(100, ge=1, le=1000)) -> dict:
        """Newest-first CRITICAL alerts raised by decoy hits.

        Open by default; set ``ALERTS_API_KEY`` to require an
        ``X-API-Key`` header (see ``_require_alerts_key``).
        """
        alerts = store.list_alerts(limit=limit)
        return {"count": store.count(), "alerts": alerts}
