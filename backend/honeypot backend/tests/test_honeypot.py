"""Tests for the Honeypot Deception Engine.

Covers the acceptance criteria:
- decoy routes exist and raise CRITICAL alerts
- alerts record IP, path, and timestamp
- decoy routes are isolated from real routes
- real routes never create alerts
"""

from __future__ import annotations

from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from honeypot import HONEYPOT_ROUTES, Alert, AlertStore, raise_honeypot_alert
from honeypot.app import create_app
from honeypot.decoys import client_ip


@pytest.fixture()
def store(tmp_path) -> AlertStore:
    return AlertStore(str(tmp_path / "alerts.db"))


@pytest.fixture()
def client(tmp_path) -> TestClient:
    app = create_app(db_path=str(tmp_path / "alerts.db"))
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Decoy route registry
# ---------------------------------------------------------------------------

def test_registry_contains_required_decoy_paths():
    """The blueprint's example decoys must be registered."""
    assert "/api/v1/admin/backup" in HONEYPOT_ROUTES
    assert "/wp-login.php" in HONEYPOT_ROUTES
    assert len(HONEYPOT_ROUTES) >= 4, "expected a healthy set of decoys"


def test_every_registry_path_has_a_fake_response():
    from honeypot.decoys import _FAKE_RESPONSES

    for path, kind in HONEYPOT_ROUTES.items():
        assert kind in _FAKE_RESPONSES, f"no fake response for {path}"


# ---------------------------------------------------------------------------
# A decoy hit creates a CRITICAL alert with IP, path, timestamp
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", sorted(HONEYPOT_ROUTES))
def test_decoy_hit_creates_critical_alert(client, store, path):
    resp = client.get(path, headers={"User-Agent": "evil-scanner/1.0"})
    assert resp.status_code == 200, f"{path} should answer like a real page"

    alerts = store.list_alerts()
    assert len(alerts) == 1
    alert = alerts[0]

    assert alert["severity"] == "CRITICAL"
    assert alert["path"] == path
    assert alert["ip"]  # recorded (TestClient uses "testclient")
    assert alert["method"] == "GET"
    assert alert["user_agent"] == "evil-scanner/1.0"

    # timestamp is valid UTC ISO-8601
    ts = datetime.fromisoformat(alert["timestamp"])
    assert ts.tzinfo is not None


def test_decoy_hit_records_client_ip(client, store):
    client.get("/wp-login.php", headers={"X-Forwarded-For": "203.0.113.7"})
    alert = store.list_alerts()[0]
    assert alert["ip"] == "203.0.113.7"


def test_post_to_decoy_also_alerts(client, store):
    resp = client.post("/wp-login.php", data={"log": "admin", "pwd": "x"})
    assert resp.status_code == 200
    alert = store.list_alerts()[0]
    assert alert["severity"] == "CRITICAL"
    assert alert["method"] == "POST"


def test_alerts_are_persisted(tmp_path):
    db = str(tmp_path / "persist.db")
    store = AlertStore(db)
    hit = raise_honeypot_alert(ip="198.51.100.4", path="/.env", method="GET")
    alert = store.record_hit(hit)
    store.close()

    # Re-open: data must survive (it is saved, not just in-memory).
    store2 = AlertStore(db)
    alerts = store2.list_alerts()
    store2.close()
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "198.51.100.4"
    assert alerts[0]["path"] == "/.env"
    assert alerts[0]["severity"] == alert.severity == "CRITICAL"


def test_alert_as_dict_has_required_fields():
    a = Alert(
        severity="CRITICAL", ip="1.2.3.4", path="/x", method="GET",
        user_agent="ua", timestamp="2026-10-07T00:00:00+00:00",
    )
    d = a.as_dict()
    assert {"severity", "ip", "path", "method", "user_agent", "timestamp"} <= set(d)


# ---------------------------------------------------------------------------
# Isolation: decoys vs real routes
# ---------------------------------------------------------------------------

def test_real_route_works_and_creates_no_alert(client, store):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
    assert store.count() == 0


def test_alert_listing_is_a_real_route_not_a_decoy(client, store):
    client.get("/wp-login.php")
    resp = client.get("/api/alerts")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["alerts"][0]["severity"] == "CRITICAL"
    # reading alerts must not itself create an alert
    assert store.count() == 1


def test_decoy_paths_never_overlap_real_routes(client):
    real_paths = {"/api/health", "/api/alerts"}
    assert real_paths.isdisjoint(set(HONEYPOT_ROUTES))


def test_decoys_are_hidden_from_openapi_schema(client):
    schema = client.get("/openapi.json").json()
    paths = set(schema["paths"])
    assert paths.isdisjoint(set(HONEYPOT_ROUTES)), "decoys leaked into docs"
    assert "/api/health" in paths


def test_unknown_real_path_does_not_alert(client, store):
    resp = client.get("/api/v1/definitely-not-a-decoy")
    assert resp.status_code == 404
    assert store.count() == 0


# ---------------------------------------------------------------------------
# Client IP helper
# ---------------------------------------------------------------------------

def test_client_ip_prefers_forwarded_for():
    class FakeHeaders(dict):
        def get(self, k, default=None):
            return dict.get(self, k.lower(), default)

    class FakeReq:
        headers = FakeHeaders({"x-forwarded-for": " 9.9.9.9 , 10.0.0.1"})
        client = None

    assert client_ip(FakeReq()) == "9.9.9.9"


# ---------------------------------------------------------------------------
# Hardening: bounded attacker fields, retention cap, optional alerts auth
# ---------------------------------------------------------------------------

def test_huge_requester_headers_are_bounded(client, store):
    """A scanner cannot bloat alerts.db with oversized XFF / User-Agent."""
    client.get(
        "/wp-login.php",
        headers={"User-Agent": "u" * 5000, "X-Forwarded-For": "1" * 400},
    )
    alert = store.list_alerts()[0]
    assert len(alert["user_agent"]) == 256
    assert len(alert["ip"]) == 45


def test_record_hit_strips_control_characters(store):
    """Stored fields never contain CR/LF/NUL (log-injection safety)."""
    hit = raise_honeypot_alert(
        ip="1.2.3.4\r\nINJECT", path="/.env", user_agent="scanner\x00\x1b[31m"
    )
    store.record_hit(hit)
    alert = store.list_alerts()[0]
    assert alert["ip"] == "1.2.3.4INJECT"
    assert alert["user_agent"] == "scanner[31m"


def test_alert_store_prunes_oldest_rows(tmp_path):
    """Retention cap: endless decoy traffic cannot grow the DB without bound."""
    store = AlertStore(str(tmp_path / "cap.db"), max_alerts=5)
    for i in range(7):
        store.record_hit(raise_honeypot_alert(ip=f"198.51.100.{i}", path="/.env"))
    assert store.count() == 5
    kept = [a["ip"] for a in store.list_alerts()]
    assert kept[0] == "198.51.100.6"  # newest survives
    assert "198.51.100.0" not in kept  # oldest pruned
    store.close()


def test_alerts_endpoint_requires_api_key_when_configured(tmp_path, monkeypatch):
    """ALERTS_API_KEY locks GET /api/alerts; decoys stay unaffected."""
    monkeypatch.setenv("ALERTS_API_KEY", "s3cret-key")
    app = create_app(db_path=str(tmp_path / "keyed.db"))
    with TestClient(app) as c:
        assert c.get("/wp-login.php").status_code == 200
        assert c.get("/api/alerts").status_code == 401
        assert c.get("/api/alerts", headers={"X-API-Key": "wrong"}).status_code == 401
        ok = c.get("/api/alerts", headers={"X-API-Key": "s3cret-key"})
        assert ok.status_code == 200
        assert ok.json()["count"] == 1
