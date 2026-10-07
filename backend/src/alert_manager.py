"""Core Module 4 - Alert prioritization, deduplication and badging.

Turns the raw threat records produced by :mod:`threat_detector` into
presentation-ready alerts:

* severity categorization ``LOW`` / ``MEDIUM`` / ``HIGH`` / ``CRITICAL``
  (``MED`` and other aliases are normalized, and a missing severity is
  derived from the risk score),
* deduplication of redundant alerts for the same IP + rule type inside
  overlapping time windows (occurrences are merged, not lost),
* badge colors: red = CRITICAL, orange = HIGH, yellow = MEDIUM, blue = LOW,
* a structured ``payload`` object ready for the frontend.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, Iterable, List, Tuple

try:  # package import
    from .log_parser import parse_timestamp
except ImportError:  # script import (``python src/main.py``)
    from log_parser import parse_timestamp
  try:
    from .copilot import generate_copilot_output
except ImportError:
    from copilot import generate_copilot_output

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
BADGE_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange",
    "MEDIUM": "yellow",
    "LOW": "blue",
}
SEVERITY_ALIASES = {
    "MED": "MEDIUM",
    "MOD": "MEDIUM",
    "WARN": "MEDIUM",
    "WARNING": "MEDIUM",
    "SEVERE": "HIGH",
    "CRIT": "CRITICAL",
    "INFO": "LOW",
    "MINOR": "LOW",
    "NOTICE": "LOW",
}
#: Redundant alerts for the same IP + rule merged when they overlap in time.
DEDUPE_WINDOW_SECONDS = 120

TITLES = {
    "SSH_BRUTE_FORCE": "SSH Brute-Force Attack",
    "SSH_BRUTE_FORCE_SUCCESS": "Successful Brute-Force Login",
    "SQL_INJECTION": "SQL Injection Attempt",
    "XSS_ATTEMPT": "Cross-Site Scripting Attempt",
    "DIRECTORY_TRAVERSAL": "Directory Traversal Attempt",
    "TRAFFIC_SPIKE": "Traffic Spike / Volumetric Pattern",
    "OFF_HOUR_ADMIN": "Off-Hour Administrative Activity",
    "WEB_DIRECTORY_SCAN": "Web Content Scan",
    "PORT_SCAN": "Port Scan",
}


def normalize_severity(value=None, risk_score=None) -> str:
    """Canonical severity for a threat (aliases resolved, score-derived fallback)."""
    if isinstance(value, str) and value.strip():
        key = value.strip().upper()
        key = SEVERITY_ALIASES.get(key, key)
        if key in SEVERITY_RANK:
            return key
    try:
        score = int(risk_score or 0)
    except (TypeError, ValueError):
        score = 0
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def badge_for(severity) -> str:
    return BADGE_COLORS.get(normalize_severity(severity), "blue")


def title_for(threat_type) -> str:
    return TITLES.get(
        threat_type, str(threat_type or "Security Event").replace("_", " ").title()
    )


def severity_counts(alerts: Iterable[Dict]) -> Dict[str, int]:
    counts = {name: 0 for name in SEVERITY_RANK}
    for alert in alerts or []:
        severity = normalize_severity(
            alert.get("severity"), alert.get("risk_score")
        )
        counts[severity] += 1
    return counts


def _build_alert(item: Dict, dedupe_window: int = DEDUPE_WINDOW_SECONDS) -> Dict:
    severity = item["severity"]
    badge = BADGE_COLORS[severity]
    title = title_for(item["type"])
    occurrences = item["occurrences"]
    attempts = item["attempts"]
    first_seen = (
        item["_first"].isoformat(sep=" ") if item.get("_first") else item["timestamp"]
    )
    last_seen = (
        item["_last"].isoformat(sep=" ") if item.get("_last") else item["timestamp"]
    )
    span = 0
    if item.get("_first") and item.get("_last"):
        span = int((item["_last"] - item["_first"]).total_seconds())

    details = item["details"]
    if occurrences > 1:
        details = (
            f"{details} [deduplicated: {occurrences} correlated events within "
            f"{dedupe_window}s]"
        )

    return {
        "type": item["type"],
        "ip": item["ip"],
        "severity": severity,
        "badge": badge,
        "title": title,
        "details": details,
        "timestamp": item["timestamp"],
        "first_seen": first_seen,
        "last_seen": last_seen,
        "risk_score": item["risk_score"],
        "occurrences": occurrences,
        "attempts": attempts,
        "copilot": generate_copilot_output({"type": item["type"], "ip": item["ip"]}),
        "payload": {
            "rule": item["type"],
            "title": title,
            "severity": severity,
            "badge": badge,
            "ip": item["ip"],
            "risk_score": item["risk_score"],
            "occurrences": occurrences,
            "attempts": attempts,
            "window": {
                "first_seen": first_seen,
                "last_seen": last_seen,
                "span_seconds": span,
            },
            "summary": item["details"],
        },
    }


def process_alerts(
    raw_threats: Iterable[Dict], dedupe_window: int = DEDUPE_WINDOW_SECONDS
) -> List[Dict]:
    """Categorize, deduplicate and badge raw threat records."""
    groups: Dict[Tuple[str, str], List[Dict]] = {}
    for threat in raw_threats or []:
        severity = normalize_severity(
            threat.get("severity"), threat.get("risk_score")
        )
        try:
            risk_score = max(0, min(100, int(threat.get("risk_score") or 0)))
        except (TypeError, ValueError):
            risk_score = 0
        moment = parse_timestamp(threat.get("timestamp"))
        try:
            attempts = max(1, int(threat.get("attempts") or threat.get("occurrences") or 1))
        except (TypeError, ValueError):
            attempts = 1
        item = {
            "type": threat.get("type") or "UNKNOWN",
            "ip": threat.get("ip") or "unknown",
            "severity": severity,
            "details": threat.get("details") or "",
            "timestamp": threat.get("timestamp"),
            "risk_score": risk_score,
            "occurrences": 1,
            "attempts": attempts,
            "_dt": moment,
            "_first": moment,
            "_last": moment,
        }
        groups.setdefault((item["ip"], item["type"]), []).append(item)

    alerts: List[Dict] = []
    for (_ip, _kind), items in groups.items():
        items.sort(
            key=lambda entry: (
                entry["_dt"] is None,
                entry["_dt"] or datetime.min,
                str(entry["timestamp"]),
            )
        )
        current = items[0]
        pending: List[Dict] = []
        for item in items[1:]:
            mergeable = (
                current["_last"] is not None
                and item["_dt"] is not None
                and (item["_dt"] - current["_last"]).total_seconds()
                <= dedupe_window
            )
            if mergeable:
                current["occurrences"] += item["occurrences"]
                current["attempts"] += item["attempts"]
                current["risk_score"] = max(current["risk_score"], item["risk_score"])
                if SEVERITY_RANK[item["severity"]] < SEVERITY_RANK[current["severity"]]:
                    current["severity"] = item["severity"]
                current["_last"] = max(current["_last"], item["_last"])
            else:
                pending.append(current)
                current = item
        pending.append(current)
        alerts.extend(_build_alert(entry, dedupe_window) for entry in pending)

    alerts.sort(
        key=lambda alert: (
            SEVERITY_RANK[alert["severity"]],
            -alert["risk_score"],
            str(alert["ip"]),
            str(alert["timestamp"]),
        )
    )
    return alerts
