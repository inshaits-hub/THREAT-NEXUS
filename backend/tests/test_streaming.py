"""Socket.IO streaming: 'threat_alert' events (spec §4.3)."""

import io

import pytest
from flask_socketio import SocketIO

from src.app import create_app


@pytest.fixture()
def app(tmp_path):
    application = create_app(db_path=tmp_path / "ws.db",
                             reports_dir=tmp_path / "reports")
    application.config["TESTING"] = True
    return application


def _upload(client, lines, filename="sample.log"):
    content = "\n".join(lines).encode("utf-8")
    return client.post(
        "/api/v1/upload",
        data={"file": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
    )


def _alerts(ws):
    return [packet for packet in ws.get_received()
            if packet["name"] == "threat_alert"]


def test_socketio_is_initialised(app):
    assert isinstance(app.extensions["socketio"], SocketIO)
    assert callable(app.extensions["threat_notifier"])


def test_upload_streams_threat_alert_with_score_and_copilot(
    app, brute_lines, web_lines
):
    ws = app.extensions["socketio"].test_client(app)
    http = app.test_client()

    assert _upload(http, brute_lines + web_lines).status_code == 200

    events = _alerts(ws)
    assert events, "upload must stream threat_alert events"
    payload = events[0]["args"][0]
    assert payload["type"]
    assert payload["ip"]
    assert payload["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert isinstance(payload["score"], int)
    assert isinstance(payload["decayed_score"], (int, float))
    assert payload["decayed_score"] <= payload["score"]
    factors = payload["score_factors"]
    assert {"frequency_points", "severity_points", "honeypot_bonus",
            "score", "decay_hours", "lambda", "decayed_score"} <= set(factors)
    assert payload["copilot"]["explanation"]
    for cmd in payload["copilot"]["commands"]:
        assert cmd.startswith("sudo ufw ")
    ws.disconnect()


def test_clean_upload_streams_nothing(app, clean_events):
    from src import log_parser
    lines = [e["raw_line"] for e in clean_events]
    ws = app.extensions["socketio"].test_client(app)
    http = app.test_client()
    assert _upload(http, lines).status_code == 200
    assert _alerts(ws) == []
    ws.disconnect()


def test_decoy_hit_streams_honeypot_alert(app):
    ws = app.extensions["socketio"].test_client(app)
    http = app.test_client()

    assert http.get("/wp-login.php").status_code == 200

    events = _alerts(ws)
    assert len(events) == 1
    payload = events[0]["args"][0]
    assert payload["type"] == "HONEYPOT_HIT"
    assert payload["severity"] == "CRITICAL"
    assert payload["score"] == 100
    assert payload["score_factors"]["honeypot_bonus"] == 80
    assert "/wp-login.php" in payload["copilot"]["explanation"] or \
        "decoy" in payload["copilot"]["explanation"]
    ws.disconnect()


def test_real_route_requests_emit_nothing(app):
    ws = app.extensions["socketio"].test_client(app)
    http = app.test_client()
    assert http.get("/api/v1/health").status_code == 200
    assert http.get("/api/v1/summary").status_code == 200
    assert _alerts(ws) == []
    ws.disconnect()
