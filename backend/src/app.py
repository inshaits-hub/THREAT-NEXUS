"""Flask REST API controller.

Endpoints (base URL ``http://localhost:5000``):

==========================  ==============================================
``GET  /api/v1/summary``    metric counters for the dashboard
``POST /api/v1/upload``     ingest a ``.log``/``.txt`` file and analyze it
``GET  /api/v1/threats``    stored alerts, filterable by ``ip``/``severity``
``GET  /api/v1/export/report``  downloadable HTML/JSON report from ``reports/``
==========================  ==============================================

Real-time: every threat saved by ``/api/v1/upload`` is also pushed to
connected dashboards as a Socket.IO ``threat_alert`` event.

Core analysis stays in the pure modules; this file only orchestrates them.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from flask_socketio import SocketIO

try:  # package import
    from . import (
        alert_manager,
        auth_analyzer,
        database,
        log_parser,
        report_generator,
        threat_detector,
    )
except ImportError:  # script import (``python src/app.py``)
    import alert_manager
    import auth_analyzer
    import database
    import log_parser
    import report_generator
    import threat_detector

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {".log", ".txt"}
EXPORT_FORMATS = {"html", "json"}
SEVERITY_QUERY_VALUES = set(alert_manager.SEVERITY_RANK) | set(
    alert_manager.SEVERITY_ALIASES
)

# Real-time channel. "threading" mode needs no extra server library and works
# on Windows, with the Flask dev server and with gunicorn's gthread worker.
# CORS is open because the dashboard and API can live on different origins.
socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")


def _error(message: str, status: int, **extra):
    payload = {"status": "error", "message": message}
    payload.update(extra)
    return jsonify(payload), status


def _serialize_threat(row: dict) -> dict:
    """Shape a stored threat / fresh alert the way the dashboard expects it."""
    canonical = alert_manager.normalize_severity(
        row.get("severity"), row.get("risk_score")
    )
    try:
        attempts = max(1, int(row.get("attempts") or 1))
    except (TypeError, ValueError):
        attempts = 1
    timestamp = row.get("timestamp")
    if hasattr(timestamp, "isoformat"):
        timestamp = timestamp.isoformat(sep=" ", timespec="seconds")
    return {
        "id": row.get("id"),
        "type": row.get("type"),
        "ip": row.get("ip"),
        "severity": canonical,
        "badge": alert_manager.badge_for(canonical),
        "title": alert_manager.title_for(row.get("type")),
        "details": row.get("details"),
        "timestamp": timestamp,
        "risk_score": row.get("risk_score"),
        "attempts": attempts,
    }


def _emit_alerts(alerts) -> None:
    """Push each new alert to every connected dashboard.

    A failed push must never fail the upload itself: the data is already
    committed, so errors here are logged and swallowed.
    """
    for alert in alerts:
        try:
            socketio.emit("threat_alert", _serialize_threat(alert))
        except Exception:  # noqa: BLE001
            logger.exception("Could not emit threat_alert")


def create_app(db_path=None, reports_dir=None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-secret"),
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_MB", "16")) * 1024 * 1024,
        THRESHOLD=int(os.environ.get("ANALYSIS_THRESHOLD", "5")),
        JSON_SORT_KEYS=False,
    )

    if db_path is not None:
        database.set_db_path(db_path)
    database.init_db()

    reports_path = (
        Path(reports_dir)
        if reports_dir
        else database.resolve_path(os.environ.get("REPORTS_DIR", "reports"))
    )
    reports_path.mkdir(parents=True, exist_ok=True)

    # Attach the real-time layer to this app.
    socketio.init_app(app)

    # ------------------------------------------------------------------ CORS
    @app.after_request
    def add_cors_headers(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

    # --------------------------------------------------------------- health
    @app.get("/api/v1/health")
    def health():
        return jsonify(
            {
                "status": "ok",
                "service": "cybersecurity-log-analyzer",
                "database": str(database.get_db_path()),
                "reports_dir": str(reports_path),
                "timestamp": datetime.now().isoformat(sep=" ", timespec="seconds"),
            }
        )

    # -------------------------------------------------------------- summary
    @app.get("/api/v1/summary")
    def summary():
        return jsonify(database.get_summary())

    # ----------------------------------------------------------------- stats
    @app.get("/api/v1/stats")
    def stats():
        rows = database.get_threats()
        return jsonify(
            {
                "severity_counts": alert_manager.severity_counts(rows),
                "top_risk_ips": report_generator.build_summary(
                    threats=rows, counts=database.get_summary()
                )["top_risk_ips"],
                "recent_summaries": database.get_previous_summaries(10),
            }
        )

    # --------------------------------------------------------------- upload
    @app.post("/api/v1/upload")
    def upload():
        if "file" not in request.files:
            return _error('Missing log file: send multipart/form-data with a "file" field.', 400)
        file = request.files["file"]
        filename = file.filename or ""
        if not filename:
            return _error("Empty filename.", 400)
        suffix = Path(filename).suffix.lower()
        if suffix not in ALLOWED_EXTENSIONS:
            return _error(
                f"Unsupported file type '{suffix or filename}'. "
                f"Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
                400,
            )

        raw = file.read()
        if not raw:
            return _error("Uploaded file is empty.", 400)
        text = raw.decode("utf-8", errors="replace")

        events = log_parser.parse_text(text)
        threats = threat_detector.detect_threats(
            events, threshold=app.config["THRESHOLD"]
        )
        alerts = alert_manager.process_alerts(threats)
        analysis = report_generator.build_summary(events, alerts)

        # One transaction: logs, threats and the summary snapshot land together or not at all.
        conn = database.get_connection()
        try:
            database.insert_logs(events, conn=conn)
            database.insert_threats(alerts, conn=conn)
            database.save_summary(analysis, conn=conn)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

        # Data is safely stored; now tell every open dashboard about it.
        _emit_alerts(alerts)

        auth_stats = auth_analyzer.analyze_authentication(events)
        riskiest = analysis["top_risk_ips"][0] if analysis["top_risk_ips"] else None

        return (
            jsonify(
                {
                    "status": "success",
                    "filename": filename,
                    "parsed_events": len(events),
                    "threats_detected": len(alerts),
                    "severity_counts": analysis["severity_counts"],
                    "high_risk_accounts": [
                        account["user"] for account in auth_stats["high_risk_accounts"]
                    ],
                    "riskiest_ip": riskiest,
                    "message": (
                        "No parseable log lines found."
                        if not events
                        else f"Analyzed {len(events)} events, {len(alerts)} alerts."
                    ),
                }
            ),
            200,
        )

    # -------------------------------------------------------------- threats
    @app.get("/api/v1/threats")
    def threats():
        ip = request.args.get("ip", type=str)
        severity = request.args.get("severity", type=str)
        limit = request.args.get("limit", default=None, type=int)

        if severity:
            token = severity.strip().upper()
            if token not in SEVERITY_QUERY_VALUES:
                return _error(
                    "Invalid severity. Use CRITICAL, HIGH, MED/MEDIUM or LOW.", 400
                )
            severity = alert_manager.normalize_severity(token)

        rows = database.get_threats(ip=ip, severity=severity, limit=limit)
        return jsonify([_serialize_threat(row) for row in rows])

    # --------------------------------------------------------------- export
    @app.get("/api/v1/export/report")
    def export_report():
        fmt = (request.args.get("format") or "html").strip().lower()
        if fmt not in EXPORT_FORMATS:
            return _error("Invalid format. Use ?format=html or ?format=json.", 400)

        threats = database.get_threats()
        counts = database.get_summary()
        report_data = report_generator.build_summary(threats=threats, counts=counts)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        basename = f"report_{stamp}_{uuid.uuid4().hex[:6]}"
        output_path = report_generator.generate_report(
            report_data,
            threats,
            output_dir=str(reports_path),
            fmt=fmt,
            basename=basename,
        )
        download_name = Path(output_path).name
        return send_file(
            output_path,
            as_attachment=True,
            download_name=download_name,
            mimetype="text/html" if fmt == "html" else "application/json",
        )

    # --------------------------------------------------------------- events
    @app.get("/api/v1/events")
    def events():
        limit = request.args.get("limit", default=200, type=int)
        ip = request.args.get("ip", type=str)
        rows = database.get_logs(limit=limit or None, ip=ip)
        return jsonify({"count": len(rows), "events": rows})

    # ------------------------------------------------------- error handlers
    @app.errorhandler(404)
    def not_found(_error_obj):
        return _error("Endpoint not found.", 404)

    @app.errorhandler(405)
    def method_not_allowed(_error_obj):
        return _error("Method not allowed for this endpoint.", 405)

    @app.errorhandler(413)
    def payload_too_large(_error_obj):
        limit_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return _error(f"File too large. Maximum upload size is {limit_mb} MB.", 413)

    @app.errorhandler(500)
    def server_error(_error_obj):
        return _error("Internal server error.", 500)

    return app


app = create_app()


if __name__ == "__main__":
    # socketio.run (not app.run) so WebSocket connections are served too.
    socketio.run(
        app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_ENV", "development") == "development",
        allow_unsafe_werkzeug=True,
    )