"""Flask honeypot blueprint: decoy hits, isolation, hardening, retention."""

import pytest

from src import database, honeypot
from src.app import create_app

ALL_DECOY_PATHS = sorted({path for path, _kind in honeypot.DECOY_ROUTES})


@pytest.fixture()
def app(tmp_path):
    application = create_app(db_path=tmp_path / "hp.db",
                             reports_dir=tmp_path / "reports")
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _hits(app):
    import os
    # create_app() points DB_PATH at the tmp database
    rows = database.get_threats(db_path=os.environ["DB_PATH"])
    return [r for r in rows if r["type"] == "HONEYPOT_HIT"]


# ---------------------------------------------------------------------------
# Every decoy records a CRITICAL, fully-scored hit
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ALL_DECOY_PATHS)
def test_every_decoy_records_critical_hit(app, client, path):
    resp = client.get(path)
    assert resp.status_code == 200, f"{path} must answer like a real page"
    assert resp.data  # plausible fake body, not an empty stub

    hits = _hits(app)
    assert len(hits) == 1
    hit = hits[0]
    assert hit["severity"] == "CRITICAL"
    assert hit["risk_score"] == 100  # freq 5 + CRITICAL 60 + bonus 80, capped
    assert hit["ip"]
    assert hit["path"] == path  # AC: alert saves the decoy path
    assert path in hit["details"]
    from datetime import datetime
    assert datetime.fromisoformat(hit["timestamp"])  # AC: timestamp saved


def test_post_to_decoy_also_records(app, client):
    resp = client.post("/wp-login.php", data={"log": "admin", "pwd": "x"})
    assert resp.status_code == 200
    hit = _hits(app)[0]
    assert "POST" in hit["details"]


# ---------------------------------------------------------------------------
# Isolation: decoys vs real routes
# ---------------------------------------------------------------------------

def test_decoy_rules_disjoint_from_real_rules(app):
    rules = list(app.url_map.iter_rules())
    decoy_rules = {r.rule for r in rules if r.endpoint.startswith("honeypot.")}
    real_rules = {r.rule for r in rules if not r.endpoint.startswith("honeypot.")}
    assert len(decoy_rules) >= 10
    assert decoy_rules.isdisjoint(real_rules), "decoy/real path overlap"
    assert "/api/v1/upload" in real_rules
    assert "/api/v1/threats" in real_rules


def test_real_routes_create_no_threats(app, client):
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/summary").status_code == 200
    assert client.get("/api/v1/stats").status_code == 200
    assert _hits(app) == []
    assert database.get_threats(db_path=__import__("os").environ["DB_PATH"]) == []


def test_unknown_path_is_404_without_threat(app, client):
    resp = client.get("/api/v1/definitely-not-a-decoy")
    assert resp.status_code == 404
    assert _hits(app) == []


def test_threats_endpoint_exposes_explainable_honeypot_score(app, client):
    assert client.get("/.env").status_code == 200
    rows = client.get("/api/v1/threats").get_json()
    hit = [r for r in rows if r["type"] == "HONEYPOT_HIT"][0]
    assert hit["score"] == 100
    assert hit["path"] == "/.env"  # AC: path exposed on the alert listing
    assert hit["decayed_score"] <= hit["score"]
    assert hit["score_factors"]["honeypot_bonus"] == 80
    assert hit["severity"] == "CRITICAL"
    assert hit["score_factors"]["lambda"] > 0


# ---------------------------------------------------------------------------
# Hardening: bounded attacker fields, control characters, retention
# ---------------------------------------------------------------------------

def test_huge_requester_headers_are_bounded(app, client):
    client.get("/wp-login.php", headers={
        "User-Agent": "u" * 5000,
        "X-Forwarded-For": "1" * 400,
    })
    hit = _hits(app)[0]
    assert len(hit["ip"]) == 45
    assert "u" * 200 not in hit["details"]  # UA capped inside details too


def test_control_characters_stripped(app):
    with app.app_context():
        threat = honeypot.record_honeypot_hit(
            ip="1.2.3.4\r\nINJECT", details="d\x00etails\x1b[31m"
        )
    assert threat["ip"] == "1.2.3.4INJECT"
    assert threat["details"] == "details[31m"
    stored = _hits(app)[-1]
    assert "\r" not in stored["ip"] and "\n" not in stored["ip"]


def test_record_hit_survives_notifier_failure(app):
    """A broken streamer must not break the decoy response (spec §5)."""
    def boom(_threat):
        raise RuntimeError("socket down")

    with app.app_context():
        threat = honeypot.record_honeypot_hit(ip="9.9.9.9", details="x",
                                              notify=boom)
    assert threat["type"] == "HONEYPOT_HIT"
    assert _hits(app)[-1]["ip"] == "9.9.9.9"  # still persisted


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

def test_prune_threats_keeps_newest(tmp_path):
    db = str(tmp_path / "prune.db")
    database.init_db(db_path=db)
    for i in range(7):
        database.insert_threats([{
            "type": "T", "ip": f"10.0.0.{i}", "severity": "LOW",
            "details": "d", "timestamp": "2026-10-07T00:00:00+00:00",
            "risk_score": 1, "attempts": 1,
        }], db_path=db)

    assert database.prune_threats(max_rows=5, db_path=db) == 2
    rows = database.get_threats(db_path=db)
    assert len(rows) == 5
    ips = {r["ip"] for r in rows}
    assert "10.0.0.6" in ips  # newest survives
    assert "10.0.0.0" not in ips  # oldest pruned
    # Idempotent when under the cap.
    assert database.prune_threats(max_rows=5, db_path=db) == 0


def test_get_threat_by_id(tmp_path):
    db = str(tmp_path / "one.db")
    database.init_db(db_path=db)
    database.insert_threats([{
        "type": "T", "ip": "1.1.1.1", "severity": "LOW", "details": "d",
        "timestamp": "2026-10-07T00:00:00+00:00", "risk_score": 1,
        "attempts": 1,
    }], db_path=db)
    row = database.get_threats(db_path=db)[0]
    assert database.get_threat(row["id"], db_path=db)["ip"] == "1.1.1.1"
    assert database.get_threat(987654, db_path=db) is None


def test_threats_schema_migrates_legacy_path_column(tmp_path, monkeypatch):
    """A threats table written before the ``path`` column is migrated."""
    db_path = tmp_path / "legacy.db"
    conn = database.get_connection(db_path)
    try:
        conn.executescript(
            "CREATE TABLE threats (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "type TEXT NOT NULL, ip TEXT, severity TEXT, details TEXT, "
            "timestamp TEXT, risk_score INTEGER DEFAULT 0, "
            "attempts INTEGER DEFAULT 1)"
        )
        conn.commit()
    finally:
        conn.close()

    monkeypatch.setenv("DB_PATH", str(db_path))
    database.init_db()

    conn = database.get_connection(db_path)
    try:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(threats)")}
    finally:
        conn.close()
    assert "path" in columns
