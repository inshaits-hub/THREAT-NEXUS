#!/usr/bin/env python3
"""Pre-load a SQLite database with a analyzed capture.

Day-5 demo aid: the live demonstration should never depend on an upload
succeeding, so the shipped database already contains the parsed events, the
detected threats and a summary snapshot.

    python scripts/build_demo_db.py                       # -> instance/logs.db
    python scripts/build_demo_db.py --log a.log b.log     # custom inputs
    python scripts/build_demo_db.py --db samples/demo.db --fresh

``--fresh`` deletes the target first, so re-running never appends duplicate
rows. The same pipeline the CLI and the API use is applied, so the numbers in
the dashboard match what a real upload produces.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from src import (  # noqa: E402  (path shim above must run first)
    alert_manager,
    auth_analyzer,
    database,
    log_parser,
    report_generator,
    threat_detector,
)

from src.main import decay_lambda_arg  # noqa: E402

DEFAULT_LOG = BACKEND_ROOT / "samples" / "demo.log"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_demo_db",
        description="Populate a SQLite database from log files for demo/QA use.",
    )
    parser.add_argument(
        "--log",
        "-l",
        nargs="+",
        default=[str(DEFAULT_LOG)],
        metavar="FILE",
        help="Log files to ingest (default: samples/demo.log).",
    )
    parser.add_argument(
        "--db",
        default=None,
        help="Target SQLite file (default: DB_PATH from .env, i.e. instance/logs.db).",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=int(os.environ.get("ANALYSIS_THRESHOLD", "5")),
        help="Brute-force threshold (default: 5).",
    )
    parser.add_argument(
        "--decay-lambda",
        type=decay_lambda_arg,
        # A string default is run through type by argparse, so an invalid
        # RISK_DECAY_LAMBDA is reported as a clean usage error (exit 2) too.
        default=os.environ.get("RISK_DECAY_LAMBDA")
        or str(threat_detector.DEFAULT_DECAY_LAMBDA),
        help="Risk score decay per hour (default: ln2/24, a 24h half-life; 0 = no decay).",
    )
    parser.add_argument(
        "--honeypot-ips",
        default=os.environ.get("HONEYPOT_IPS", ""),
        help="Comma separated honeypot destination IPs; sources targeting them get +20 risk (default: HONEYPOT_IPS or none).",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Delete the target database before writing, avoiding duplicate rows.",
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    events = []
    for filepath in args.log:
        try:
            events.extend(log_parser.parse_file(filepath))
        except OSError as exc:
            print(
                f"[error] cannot read log file: {filepath} ({exc.strerror or exc})",
                file=sys.stderr,
            )
            return 1

    if not events:
        print("[error] no parseable log lines found.", file=sys.stderr)
        return 1

    db_path = Path(args.db) if args.db else database.get_db_path()
    if args.fresh and db_path.exists():
        db_path.unlink()
        print(f"[info] removed existing {db_path}")

    if args.db:
        database.set_db_path(db_path)
    database.init_db()

    threats = threat_detector.detect_threats(
        events,
        threshold=args.threshold,
        decay_lambda=args.decay_lambda,
        honeypot_ips=args.honeypot_ips,
    )
    alerts = alert_manager.process_alerts(threats)
    summary = report_generator.build_summary(events, alerts)
    auth_stats = auth_analyzer.analyze_authentication(events)

    conn = database.get_connection()
    try:
        database.insert_logs(events, conn=conn)
        database.insert_threats(alerts, conn=conn)
        database.save_summary(summary, conn=conn)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()

    severity = summary.get("severity_counts", {})
    riskiest = (summary.get("top_risk_ips") or [{}])[0]
    print(f"  Database           : {db_path}")
    print(f"  Parsed events      : {summary.get('total_events', len(events))}")
    print(
        "  Threats stored     : {}  (CRITICAL {} | HIGH {} | MEDIUM {} | LOW {})".format(
            summary.get("total_threats", len(alerts)),
            severity.get("CRITICAL", 0),
            severity.get("HIGH", 0),
            severity.get("MEDIUM", 0),
            severity.get("LOW", 0),
        )
    )
    if riskiest.get("ip"):
        print(f"  Riskiest IP        : {riskiest['ip']} ({riskiest.get('risk_score', 0)}/100)")
    print(f"  High-risk accounts : {', '.join(a['user'] for a in auth_stats['high_risk_accounts']) or '-'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
