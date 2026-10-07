"""Standalone CLI entry point - full analysis without Flask running.

Examples
--------
    python src/main.py --log /path/to/auth.log --export html
    python src/main.py --log samples/demo.log --export both --threshold 5
    python src/main.py --log a.log b.log --export json --output reports --no-save
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from typing import List, Optional

try:  # package import (``python -m src.main`` / pytest)
    from . import (
        alert_manager,
        auth_analyzer,
        database,
        log_parser,
        report_generator,
        threat_detector,
    )
except ImportError:  # script import (``python src/main.py``)
    import alert_manager
    import auth_analyzer
    import database
    import log_parser
    import report_generator
    import threat_detector

RULE_WIDTH = 76


def decay_lambda_arg(value: str) -> float:
    """argparse ``type=`` adapter around ``threat_detector.validate_decay_lambda``."""
    try:
        return threat_detector.validate_decay_lambda(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


# --------------------------------------------------------------------------- #
# Terminal colors
#
# Off by default when stdout is not a TTY (pipes, files, pytest capture), so
# redirected output stays clean. Force it with FORCE_COLOR=1, kill it with
# NO_COLOR=1. Same convention as ripgrep/ls/fzf.
# --------------------------------------------------------------------------- #
_RESET = "\033[0m"
_STYLES = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[1;31m",
    "orange": "\033[38;5;208m",
    "yellow": "\033[38;5;220m",
    "blue": "\033[38;5;39m",
    "cyan": "\033[36m",
    "green": "\033[1;32m",
}
SEVERITY_STYLES = {
    "CRITICAL": "red",
    "HIGH": "orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
}


def color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def _paint(text: str, style: str, color: bool) -> str:
    if not color or not style:
        return text
    return f"{_STYLES[style]}{text}{_RESET}"


def _severity_style(severity: str) -> str:
    return SEVERITY_STYLES.get(str(severity or "").strip().upper(), "bold")


def _risk_style(score: int) -> str:
    try:
        value = int(score)
    except (TypeError, ValueError):
        return ""
    if value >= 80:
        return "red"
    if value >= 60:
        return "orange"
    if value >= 30:
        return "yellow"
    return "dim"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cyber-log-analyzer",
        description="Cybersecurity Log Analyzer - standalone CLI (no Flask needed).",
    )
    parser.add_argument(
        "--log",
        "-l",
        nargs="+",
        required=True,
        metavar="FILE",
        help="One or more log files (auth.log, nginx/apache access logs, syslog).",
    )
    parser.add_argument(
        "--export",
        choices=("html", "json", "both", "none"),
        default="both",
        help="Report format to generate: html, json, both or none (default: both).",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Report output directory (default: reports/).",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=int(os.environ.get("ANALYSIS_THRESHOLD", "5")),
        help="Brute-force threshold: alert when failures exceed this within 60s "
        "(default: 5).",
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
        "--db", default=None, help="SQLite path (default: DB_PATH from .env)."
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Skip writing results to the database.",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of alerts to print (default: 10).",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Only print generated report paths."
    )
    colors = parser.add_mutually_exclusive_group()
    colors.add_argument(
        "--color",
        dest="color",
        action="store_true",
        default=None,
        help="Force colored badges even when stdout is not a terminal.",
    )
    colors.add_argument(
        "--no-color",
        dest="color",
        action="store_false",
        help="Disable colored output (same as NO_COLOR=1).",
    )
    return parser


def _row(label: str, value: str, color: bool, value_style: str = "") -> None:
    """Aligned ``label    : value`` line with an optionally colored value."""
    key = _paint("{:<20}: ".format(label), "dim", color)
    print("  {}{}".format(key, _paint(value, value_style, color) if value_style else value))


def _print_summary(
    files: List[str],
    events: List[dict],
    alerts: List[dict],
    summary: dict,
    auth_stats: dict,
    top: int,
    color: bool = False,
) -> None:
    severity = summary.get("severity_counts", {})
    riskiest = (summary.get("top_risk_ips") or [{}])[0]
    rule = _paint("=" * RULE_WIDTH, "cyan", color)

    print(rule)
    print(_paint("  CYBERSECURITY LOG ANALYZER - EXECUTIVE SUMMARY", "bold", color))
    print(rule)
    _row("Log files", ", ".join(files), color)
    _row("Parsed events", str(summary.get("total_events", len(events))), color, "bold")
    _row("Unique IPs", str(summary.get("unique_ips", 0)), color)

    rate = auth_stats["success_rate"]
    rate_style = "green" if rate >= 0.9 else ("yellow" if rate >= 0.5 else "red")
    _row(
        "Auth success/fail",
        f"{auth_stats['successful_logins']}/{auth_stats['failed_logins']} "
        f"(rate {rate:.0%})",
        color,
        rate_style,
    )

    breakdown = " | ".join(
        "{} {}".format(
            _paint(name, _severity_style(name), color), severity.get(name, 0)
        )
        for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )
    _row(
        "Threats detected",
        "{}  ({})".format(summary.get("total_threats", len(alerts)), breakdown),
        color,
        "bold",
    )

    if riskiest.get("ip"):
        score = riskiest.get("risk_score", 0)
        _row(
            "Riskiest IP",
            "{} ({}/100)".format(
                riskiest["ip"], _paint(str(score), _risk_style(score), color)
            ),
            color,
        )
    if auth_stats["high_risk_accounts"]:
        names = ", ".join(
            account["user"] for account in auth_stats["high_risk_accounts"][:5]
        )
        _row("High-risk accounts", names, color, "red")

    print(_paint("-" * RULE_WIDTH, "cyan", color))
    print(
        _paint(
            "  TOP ALERTS (showing {} of {})".format(min(top, len(alerts)), len(alerts)),
            "bold",
            color,
        )
    )
    if not alerts:
        print("  No threats detected.")
    for alert in alerts[:top]:
        # Truncate the plain text first so escape codes never eat the budget.
        details = alert["details"]
        if len(details) > RULE_WIDTH - 8:
            details = details[: RULE_WIDTH - 11] + "..."
        badge = _paint(
            "[{:<8}]".format(alert["severity"]),
            _severity_style(alert["severity"]),
            color,
        )
        risk = _paint(str(alert["risk_score"]), _risk_style(alert["risk_score"]), color)
        print(
            "  {} {} - {} (risk {})".format(
                badge, alert["title"], alert["ip"], risk
            )
        )
        print("      {}".format(_paint(details, "dim", color)))
    print(rule)


def _print_report_paths(paths: List[str], color: bool) -> None:
    print(_paint("  Report(s) written:", "bold", color))
    for path in paths:
        print("    {}".format(_paint(path, "green", color)))
    print(_paint("=" * RULE_WIDTH, "cyan", color))


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    color = color_enabled() if args.color is None else args.color

    events: List[dict] = []
    loaded: List[str] = []
    failures: List[str] = []
    for filepath in args.log:
        try:
            events.extend(log_parser.parse_file(filepath))
            loaded.append(filepath)
        except OSError as exc:
            failures.append(f"{filepath} ({exc.strerror or exc})")

    if failures:
        for failure in failures:
            print(f"[error] cannot read log file: {failure}", file=sys.stderr)
        if not loaded:
            return 1

    threats = threat_detector.detect_threats(
        events,
        threshold=args.threshold,
        decay_lambda=args.decay_lambda,
        honeypot_ips=args.honeypot_ips,
    )
    alerts = alert_manager.process_alerts(threats)
    summary = report_generator.build_summary(events, alerts)
    auth_stats = auth_analyzer.analyze_authentication(events)

    if not args.no_save:
        if args.db:
            database.set_db_path(args.db)
        database.init_db()
        # Single transaction so logs/threats/summary stay consistent.
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

    if not args.quiet:
        _print_summary(loaded, events, alerts, summary, auth_stats, args.top, color)

    if args.export != "none":
        output_dir = database.resolve_path(
            args.output or os.environ.get("REPORTS_DIR", "reports")
        )
        basename = datetime.now().strftime("report_%Y%m%d_%H%M%S")
        formats = ("html", "json") if args.export == "both" else (args.export,)
        written = []
        for fmt in formats:
            written.append(
                report_generator.generate_report(
                    summary, alerts, output_dir=str(output_dir), fmt=fmt,
                    basename=basename,
                )
            )
        if args.quiet:
            for path in written:
                print(path)
        else:
            _print_report_paths(written, color)

    return 0


if __name__ == "__main__":
    sys.exit(main())
