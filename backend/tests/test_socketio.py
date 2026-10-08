"""Uploading a log must push one ``threat_alert`` event per stored threat."""

from pathlib import Path

try:
    from src.app import create_app, socketio
except ImportError:  # pragma: no cover - script-style import
    from app import create_app, socketio

DEMO_LOG = Path(__file__).resolve().parents[1] / "samples" / "demo.log"

EXPECTED_KEYS = {
    "type",
    "ip",
    "severity",
    "badge",
    "title",
    "details",
    "timestamp",
    "risk_score",
    "attempts",
}


def test_upload_emits_threat_alert_events(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "test.db"), reports_dir=str(tmp_path / "reports")
    )
    client = app.test_client()
    sio_client = socketio.test_client(app, flask_test_client=client)
    assert sio_client.is_connected()
    sio_client.get_received()  # drop the connect handshake

    with DEMO_LOG.open("rb") as handle:
        response = client.post(
            "/api/v1/upload",
            data={"file": (handle, "demo.log")},
            content_type="multipart/form-data",
        )

    assert response.status_code == 200
    detected = response.get_json()["threats_detected"]
    assert detected > 0

    alerts = [m for m in sio_client.get_received() if m["name"] == "threat_alert"]
    assert len(alerts) == detected
    assert EXPECTED_KEYS <= set(alerts[0]["args"][0])


def test_upload_without_listeners_still_succeeds(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "test2.db"), reports_dir=str(tmp_path / "reports2")
    )
    with DEMO_LOG.open("rb") as handle:
        response = app.test_client().post(
            "/api/v1/upload",
            data={"file": (handle, "demo.log")},
            content_type="multipart/form-data",
        )
    assert response.status_code == 200