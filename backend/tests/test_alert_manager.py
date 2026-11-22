"""Focused tests for alert normalization, deduplication and payloads."""

import pytest

from src.alert_manager import (
    badge_for,
    normalize_severity,
    process_alerts,
    severity_counts,
)


def _threat(
    *,
    timestamp="2026-09-28 09:13:05",
    ip="203.0.113.9",
    threat_type="SSH_BRUTE_FORCE",
    severity="HIGH",
    risk_score=70,
    attempts=1,
    details="failed login activity",
):
    return {
        "type": threat_type,
        "ip": ip,
        "severity": severity,
        "details": details,
        "timestamp": timestamp,
        "risk_score": risk_score,
        "attempts": attempts,
    }


@pytest.mark.parametrize(
    ("value", "risk_score", "expected"),
    [
        (" med ", None, "MEDIUM"),
        ("warning", None, "MEDIUM"),
        ("severe", None, "HIGH"),
        ("crit", None, "CRITICAL"),
        ("info", None, "LOW"),
        ("not-a-severity", 80, "CRITICAL"),
        (None, 60, "HIGH"),
        (None, 30, "MEDIUM"),
        (None, 29, "LOW"),
        (None, "invalid", "LOW"),
    ],
)
def test_normalize_severity_aliases_and_score_fallback(value, risk_score, expected):
    assert normalize_severity(value, risk_score) == expected


@pytest.mark.parametrize(
    ("severity", "expected_badge"),
    [
        ("CRITICAL", "red"),
        ("HIGH", "orange"),
        ("MEDIUM", "yellow"),
        ("LOW", "blue"),
    ],
)
def test_badges_match_canonical_severity(severity, expected_badge):
    assert badge_for(severity) == expected_badge


def test_overlapping_alerts_merge_at_inclusive_window_boundary():
    first = _threat(attempts=3, details="first detector result")
    second = _threat(
        timestamp="2026-09-28 09:15:05",
        severity="CRITICAL",
        risk_score=92,
        attempts=2,
        details="second detector result",
    )

    alerts = process_alerts([first, second])

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["occurrences"] == 2
    assert alert["attempts"] == 5
    assert alert["severity"] == "CRITICAL"
    assert alert["risk_score"] == 92
    assert alert["timestamp"] == first["timestamp"]
    assert alert["first_seen"] == first["timestamp"]
    assert alert["last_seen"] == second["timestamp"]
    assert alert["payload"]["window"]["span_seconds"] == 120
    assert alert["payload"]["attempts"] == 5
    assert "[deduplicated: 2 correlated events within 120s]" in alert["details"]


def test_alerts_outside_dedupe_window_remain_separate():
    first = _threat()
    second = _threat(timestamp="2026-09-28 09:15:06")

    alerts = process_alerts([first, second])

    assert len(alerts) == 2
    assert [alert["occurrences"] for alert in alerts] == [1, 1]


def test_deduplication_does_not_cross_ip_or_rule_boundaries():
    threats = [
        _threat(),
        _threat(ip="203.0.113.10"),
        _threat(threat_type="SQL_INJECTION"),
        _threat(threat_type="SQL_INJECTION", ip="203.0.113.10"),
    ]

    alerts = process_alerts(threats)

    assert len(alerts) == 4
    assert all(alert["occurrences"] == 1 for alert in alerts)


def test_invalid_timestamps_cannot_be_correlated():
    threats = [
        _threat(timestamp="unrecognized"),
        _threat(timestamp=None),
    ]

    alerts = process_alerts(threats)

    assert len(alerts) == 2
    assert all(alert["occurrences"] == 1 for alert in alerts)


def test_alerts_are_ordered_by_severity_then_risk_score():
    threats = [
        _threat(threat_type="LOW_RULE", severity="LOW", risk_score=99),
        _threat(threat_type="HIGH_70", severity="HIGH", risk_score=70),
        _threat(threat_type="CRITICAL_RULE", severity="CRITICAL", risk_score=60),
        _threat(threat_type="HIGH_90", severity="HIGH", risk_score=90),
    ]

    alerts = process_alerts(threats)

    assert [alert["type"] for alert in alerts] == [
        "CRITICAL_RULE",
        "HIGH_90",
        "HIGH_70",
        "LOW_RULE",
    ]


def test_scores_and_attempts_are_safely_normalized():
    alerts = process_alerts(
        [
            _threat(
                severity="UNKNOWN",
                risk_score=150,
                attempts=-5,
            ),
            _threat(
                timestamp="2026-09-28 09:20:00",
                threat_type="OTHER_RULE",
                severity="HIGH",
                risk_score=-10,
                attempts="invalid",
            ),
        ]
    )

    first = next(alert for alert in alerts if alert["type"] == "SSH_BRUTE_FORCE")
    second = next(alert for alert in alerts if alert["type"] == "OTHER_RULE")
    assert (first["severity"], first["risk_score"], first["attempts"]) == (
        "CRITICAL",
        100,
        1,
    )
    assert (second["risk_score"], second["attempts"]) == (0, 1)


def test_severity_counts_include_empty_buckets_and_derive_missing_labels():
    counts = severity_counts(
        [
            {"severity": "crit"},
            {"severity": None, "risk_score": 65},
            {"severity": "invalid", "risk_score": 0},
        ]
    )

    assert counts == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 1}
    assert severity_counts([]) == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }


def test_alert_exposes_frontend_payload_contract():
    alert = process_alerts([_threat()])[0]

    assert alert["title"] == "SSH Brute-Force Attack"
    assert alert["badge"] == "orange"
    assert alert["payload"] == {
        "rule": "SSH_BRUTE_FORCE",
        "title": alert["title"],
        "severity": "HIGH",
        "badge": "orange",
        "ip": "203.0.113.9",
        "risk_score": 70,
        "occurrences": 1,
        "attempts": 1,
        "window": {
            "first_seen": alert["timestamp"],
            "last_seen": alert["timestamp"],
            "span_seconds": 0,
        },
        "summary": "failed login activity",
    }
