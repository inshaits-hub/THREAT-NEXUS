"""SSH decoy listener: opt-in trap that records hits (spec §4.5)."""

import os
import socket
import time

from src import database, ssh_decoy
from src.app import create_app

LOCALHOSTS = {"127.0.0.1", "::ffff:127.0.0.1"}


def _wait(predicate, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


# ---------------------------------------------------------------------------
# Configuration / safety defaults
# ---------------------------------------------------------------------------

def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("SSH_DECOY_ENABLED", raising=False)
    assert ssh_decoy.env_enabled() is False
    assert ssh_decoy.start_from_env(lambda ip, port: None) is None


def test_env_parsing(monkeypatch):
    monkeypatch.setenv("SSH_DECOY_ENABLED", "1")
    monkeypatch.setenv("SSH_DECOY_PORT", "3333")
    monkeypatch.setenv("SSH_DECOY_HOST", "127.0.0.1")
    assert ssh_decoy.env_enabled() is True
    assert ssh_decoy.env_port() == 3333
    assert ssh_decoy.env_host() == "127.0.0.1"
    monkeypatch.setenv("SSH_DECOY_PORT", "not-a-port")
    assert ssh_decoy.env_port() == ssh_decoy.DEFAULT_PORT


def test_bind_failure_returns_none_and_never_raises(monkeypatch):
    # 203.0.0.1 (TEST-NET-1) is not a local address -> bind must fail.
    monkeypatch.setenv("SSH_DECOY_ENABLED", "true")
    monkeypatch.setenv("SSH_DECOY_HOST", "203.0.0.1")
    monkeypatch.setenv("SSH_DECOY_PORT", "2222")
    assert ssh_decoy.start_from_env(lambda ip, port: None) is None


# ---------------------------------------------------------------------------
# Listener behaviour
# ---------------------------------------------------------------------------

def test_listener_records_connection_and_closes_without_ssh():
    hits = []
    server = ssh_decoy.SSHDecoyServer(
        "127.0.0.1", 0, lambda ip, port: hits.append((ip, port))
    )
    server.start()
    try:
        assert server.port != 0  # ephemeral port resolved
        with socket.create_connection(("127.0.0.1", server.port), timeout=2) as conn:
            # The server closes without speaking SSH; a clean FIN arrives
            # as EOF (sending first would provoke a RST race on Windows).
            conn.settimeout(2)
            assert conn.recv(16) == b""  # closed without speaking SSH
        assert _wait(lambda: bool(hits)), "hit must be recorded"
        assert hits[0][1] == server.port
        assert hits[0][0] in LOCALHOSTS
    finally:
        server.stop()
    assert server._thread is None  # thread joined


def test_stop_is_idempotent():
    server = ssh_decoy.SSHDecoyServer("127.0.0.1", 0, lambda ip, port: None)
    server.start()
    server.stop()
    server.stop()  # second stop must not raise


def test_handler_crash_does_not_kill_listener():
    def boom(ip, port):
        raise RuntimeError("handler down")

    server = ssh_decoy.SSHDecoyServer("127.0.0.1", 0, boom)
    server.start()
    try:
        with socket.create_connection(("127.0.0.1", server.port), timeout=2):
            pass
        with socket.create_connection(("127.0.0.1", server.port), timeout=2) as conn:
            conn.settimeout(2)
            assert conn.recv(1) == b""  # still accepting after the crash
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# App integration
# ---------------------------------------------------------------------------

def test_app_does_not_start_decoy_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("SSH_DECOY_ENABLED", raising=False)
    app = create_app(db_path=tmp_path / "nossH.db",
                     reports_dir=tmp_path / "reports")
    assert app.extensions.get("ssh_decoy") is None


def test_app_starts_decoy_when_enabled_and_records_hit(tmp_path, monkeypatch):
    monkeypatch.setenv("SSH_DECOY_ENABLED", "1")
    monkeypatch.setenv("SSH_DECOY_HOST", "127.0.0.1")
    monkeypatch.setenv("SSH_DECOY_PORT", "0")  # ephemeral for the test
    db = str(tmp_path / "ssh.db")
    app = create_app(db_path=db, reports_dir=tmp_path / "reports")
    app.config["TESTING"] = True
    server = app.extensions.get("ssh_decoy")
    assert server is not None
    try:
        with socket.create_connection(("127.0.0.1", server.port), timeout=2):
            pass

        def recorded():
            hits = [r for r in database.get_threats(db_path=db)
                    if r["type"] == "HONEYPOT_HIT"]
            return bool(hits), hits

        assert _wait(lambda: recorded()[0]), "SSH trap hit must be persisted"
        hit = recorded()[1][0]
        assert hit["severity"] == "CRITICAL"
        assert hit["risk_score"] == 100
        assert "SSH decoy port" in hit["details"]
        assert hit["ip"] in LOCALHOSTS
    finally:
        server.stop()


def test_ssh_hit_streams_like_decoy_hits(tmp_path, monkeypatch):
    """The SSH trap uses the same notifier path as HTTP decoys (spec §4.5)."""
    monkeypatch.setenv("SSH_DECOY_ENABLED", "1")
    monkeypatch.setenv("SSH_DECOY_HOST", "127.0.0.1")
    monkeypatch.setenv("SSH_DECOY_PORT", "0")
    db = str(tmp_path / "ssh2.db")
    app = create_app(db_path=db, reports_dir=tmp_path / "reports")
    app.config["TESTING"] = True
    server = app.extensions["ssh_decoy"]
    ws = app.extensions["socketio"].test_client(app)
    try:
        with socket.create_connection(("127.0.0.1", server.port), timeout=2):
            pass

        def drain():
            return [p for p in ws.get_received()
                    if p["name"] == "threat_alert"]

        collected = []
        assert _wait(
            lambda: (collected.extend(drain()) or bool(collected))
        ), "threat_alert must be streamed"
        payload = collected[0]["args"][0]
        assert payload["type"] == "HONEYPOT_HIT"
        assert payload["copilot"]["explanation"]
    finally:
        ws.disconnect()
        server.stop()
