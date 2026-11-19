"""Dynamic 0-100 explainable risk scoring: bounds, decay, honeypot, factors."""

import io
import math

import pytest

from src import alert_manager, database, log_parser, threat_detector
from src.threat_detector import (
    DEFAULT_DECAY_LAMBDA,
    HONEYPOT_BONUS,
    compute_ip_risk_scores,
    detect_threats,
    explain_ip_risk_scores,
    parse_honeypot_ips,
    validate_decay_lambda,
)

ATTACKER = "203.0.113.9"
OTHER = "198.51.100.7"


def _failures(ip, count, day=28, hour=9, minute=0):
    return log_parser.parse_lines(
        f"Sep {day} {hour:02d}:{minute:02d}:{index:02d} web01 sshd[1]: Failed "
        f"password for root from {ip} port {50000 + index} ssh2"
        for index in range(count)
    )


HONEYPOT = "10.9.9.9"


def _fw(src, dst, second=0, minute=20):
    """UFW firewall block from ``src`` to ``dst`` (``DST=`` is in the raw line)."""
    return log_parser.parse_log_line(
        f"Sep 28 09:{minute:02d}:{second:02d} fw01 kernel: [UFW BLOCK] IN=eth0 OUT= "
        f"MAC=00:11 SRC={src} DST={dst} PROTO=TCP SPT=51000 DPT=22 WINDOW=1024"
    )


def _dated_failures(ip, count, stamp):
    """Failed-login events with an explicit year-qualified timestamp (deterministic)."""
    return [
        {
            "timestamp": stamp,
            "ip": ip,
            "user": "root",
            "action": "ssh_login_failure",
            "log_type": "auth",
            "raw_line": f"{stamp} {ip} {index}",
            "pid": str(index),
        }
        for index in range(count)
    ]


def _headerless_failures(ip, count):
    return log_parser.parse_lines(
        f"sshd[1]: Failed password for root from {ip} port {5000 + index} ssh2"
        for index in range(count)
    )


def _score(events, **kwargs):
    return compute_ip_risk_scores(events, [], **kwargs)


def _explain(events, threats=(), **kwargs):
    return explain_ip_risk_scores(events, list(threats), **kwargs)


def _threat(kind, ip=ATTACKER, timestamp="2026-09-28 09:00:00"):
    return {"type": kind, "ip": ip, "severity": "HIGH", "timestamp": timestamp}


# --------------------------------------------------------------- boundaries
def test_no_events_means_no_scores():
    assert compute_ip_risk_scores([], []) == {}
    assert explain_ip_risk_scores([], []) == {}


def test_score_is_zero_without_activity():
    events = log_parser.parse_lines(
        ['10.0.0.15 - - [28/Sep/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 1 "-" "x"']
    )
    assert _score(events) == {}


def test_score_is_capped_at_100():
    threats = [_threat(kind) for kind in threat_detector.RULE_WEIGHTS]
    result = _explain(_failures(ATTACKER, 20), threats, decay_lambda=0)[ATTACKER]
    assert result["frequency_points"] + result["severity_points"] > 100
    assert result["base_score"] == 100
    assert result["score"] == 100


def test_cap_adds_explicit_factor_and_factors_sum_to_base():
    threats = [_threat(kind) for kind in threat_detector.RULE_WEIGHTS]
    result = _explain(_failures(ATTACKER, 20), threats, decay_lambda=0)[ATTACKER]
    cap = [f for f in result["factors"] if f["factor"] == "capped_at_100"]
    assert len(cap) == 1
    raw = result["frequency_points"] + result["severity_points"] + result["honeypot_bonus"]
    assert raw > 100 and result["base_score"] == 100
    assert cap[0]["points"] == 100 - raw
    assert str(raw) in cap[0]["detail"] and "100" in cap[0]["detail"]
    assert sum(f["points"] for f in result["factors"]) == result["base_score"]


def test_no_cap_factor_below_100():
    result = _explain(_failures(ATTACKER, 3), decay_lambda=0)[ATTACKER]
    assert all(f["factor"] != "capped_at_100" for f in result["factors"])


def test_rule_factors_use_readable_alert_titles():
    result = _explain([], [_threat("PORT_SCAN")], decay_lambda=0)[ATTACKER]
    rule = [f for f in result["factors"] if f["factor"] == "rule:PORT_SCAN"][0]
    assert alert_manager.title_for("PORT_SCAN") in rule["detail"]


def test_score_boundary_exactly_100_and_99():
    # 35 + 45 + 15 = 95 (no cap); +20 honeypot = 115 -> capped to 100
    threats = [_threat("SSH_BRUTE_FORCE"), _threat("SSH_BRUTE_FORCE_SUCCESS"), _threat("XSS_ATTEMPT")]
    assert _explain([], threats, decay_lambda=0)[ATTACKER]["score"] == 95
    capped = _explain(
        [_fw(ATTACKER, HONEYPOT)], threats, decay_lambda=0, honeypot_ips=[HONEYPOT]
    )[ATTACKER]
    assert capped["score"] == 100
    assert capped["base_score"] == 100
    # 45 + 30 + 10 = 85 severity + 7 failed logins * 2 = 14 frequency -> exactly 99
    ninety_nine = [_threat("SSH_BRUTE_FORCE_SUCCESS"), _threat("SQL_INJECTION"), _threat("OFF_HOUR_ADMIN")]
    assert _explain(_failures(ATTACKER, 7), ninety_nine, decay_lambda=0)[ATTACKER]["score"] == 99


# ------------------------------------------------- frequency / severity points
def test_frequency_points_scale_and_cap():
    assert _explain(_failures(ATTACKER, 3), decay_lambda=0)[ATTACKER]["frequency_points"] == 6
    assert _explain(_failures(ATTACKER, 40), decay_lambda=0)[ATTACKER]["frequency_points"] == 25


def test_severity_points_come_from_rule_weights_without_stacking():
    threats = [_threat("PORT_SCAN"), _threat("PORT_SCAN"), _threat("XSS_ATTEMPT")]
    result = _explain([], threats, decay_lambda=0)[ATTACKER]
    assert result["severity_points"] == (
        threat_detector.RULE_WEIGHTS["PORT_SCAN"] + threat_detector.RULE_WEIGHTS["XSS_ATTEMPT"]
    )


# ---------------------------------------------------------------- honeypot
def test_attacker_targeting_honeypot_gets_20_points():
    events = _failures(ATTACKER, 3) + [_fw(ATTACKER, HONEYPOT)]
    plain = _explain(events, decay_lambda=0)[ATTACKER]
    boosted = _explain(events, decay_lambda=0, honeypot_ips=[HONEYPOT])[ATTACKER]
    assert HONEYPOT_BONUS == 20
    assert plain["honeypot_bonus"] == 0
    assert boosted["honeypot_bonus"] == 20
    assert boosted["score"] == plain["score"] + 20
    factor = [f for f in boosted["factors"] if f["factor"] == "honeypot"]
    assert factor and factor[0]["points"] == 20 and HONEYPOT in factor[0]["detail"]


def test_attacker_not_targeting_honeypot_gets_no_bonus():
    events = _failures(ATTACKER, 3) + [_fw(ATTACKER, "192.0.2.50")]
    result = _explain(events, decay_lambda=0, honeypot_ips=[HONEYPOT])[ATTACKER]
    assert result["honeypot_bonus"] == 0
    assert all(f["factor"] != "honeypot" for f in result["factors"])


def test_multiple_honeypot_hits_award_bonus_once():
    events = (
        _failures(ATTACKER, 3)
        + [_fw(ATTACKER, HONEYPOT, second=sec) for sec in range(5)]
        + [_fw(ATTACKER, "10.9.9.10", second=30)]
    )
    result = _explain(
        events, decay_lambda=0, honeypot_ips=[HONEYPOT, "10.9.9.10"]
    )[ATTACKER]
    assert result["honeypot_bonus"] == 20
    assert len([f for f in result["factors"] if f["factor"] == "honeypot"]) == 1


def test_source_ip_listed_as_honeypot_gets_no_bonus():
    events = _failures(ATTACKER, 3) + [_fw(ATTACKER, "192.0.2.50")]
    result = _explain(events, decay_lambda=0, honeypot_ips=[ATTACKER])[ATTACKER]
    assert result["honeypot_bonus"] == 0
    assert all(f["factor"] != "honeypot" for f in result["factors"])


def test_configured_honeypot_without_dst_match_gives_no_bonus():
    events = _failures(ATTACKER, 3)  # SSH events carry no DST=
    result = _explain(events, decay_lambda=0, honeypot_ips=[HONEYPOT])
    assert result[ATTACKER]["honeypot_bonus"] == 0
    assert HONEYPOT not in result


def test_event_destination_helper():
    assert log_parser.event_destination(_fw(ATTACKER, HONEYPOT)) == HONEYPOT
    assert log_parser.event_destination(_failures(ATTACKER, 1)[0]) is None
    assert log_parser.event_destination(None) is None
    assert log_parser.event_destination({"raw_line": None}) is None


def test_event_destination_ignores_dst_in_non_firewall_events():
    lines = [
        # web request whose path happens to contain DST=
        f'{ATTACKER} - - [28/Sep/2026:02:14:07 +0000] "GET /x?DST={HONEYPOT} HTTP/1.1" 200 1 "-" "x"',
        # auth line mentioning DST=
        f"Sep 28 09:13:05 web01 sshd[1]: Failed password for root from {ATTACKER} "
        f"port 50100 ssh2 DST={HONEYPOT}",
        # ordinary syslog line (not a firewall block) with SRC= and DST=
        f"Sep 28 09:21:00 fw01 app: note SRC={ATTACKER} DST={HONEYPOT}",
    ]
    for event in log_parser.parse_lines(lines):
        assert event["action"] != "firewall_block"
        assert HONEYPOT in event["raw_line"]
        assert log_parser.event_destination(event) is None
    # ...so they never earn the honeypot bonus
    events = log_parser.parse_lines(lines)
    result = _explain(events, [_threat("PORT_SCAN")], decay_lambda=0, honeypot_ips=[HONEYPOT])
    assert result[ATTACKER]["honeypot_bonus"] == 0


def test_event_destination_supports_ipv6_firewall_events():
    event = _fw("2001:db8::1", "2001:db8::beef")
    assert event["action"] == "firewall_block"
    assert log_parser.event_destination(event) == "2001:db8::beef"


def test_parse_honeypot_ips():
    assert parse_honeypot_ips("") == frozenset()
    assert parse_honeypot_ips(None) == frozenset()
    assert parse_honeypot_ips(" 1.1.1.1, 2.2.2.2 ,,") == {"1.1.1.1", "2.2.2.2"}


# -------------------------------------------------------------- time decay
def _two_ips(hours_apart):
    """ATTACKER last seen ``hours_apart`` before OTHER (the newest event)."""
    old = _failures(ATTACKER, 5, day=27, hour=12)
    newest_hour = 12 + hours_apart
    day = 27 + newest_hour // 24
    new = _failures(OTHER, 5, day=day, hour=newest_hour % 24)
    return old + new


def test_zero_hours_since_event_means_no_decay():
    result = _explain(_two_ips(0))
    assert result[OTHER]["hours_since_last_event"] == 0
    assert result[OTHER]["decay_factor"] == 1.0
    assert result[OTHER]["score"] == result[OTHER]["base_score"]


def test_positive_decay_halves_after_24_hours():
    # Both IPs have the same base; the older one is 24h behind the newest event.
    result = _explain(_two_ips(24))
    old, new = result[ATTACKER], result[OTHER]
    assert old["base_score"] == new["base_score"]
    assert old["hours_since_last_event"] == pytest.approx(24, abs=0.01)
    assert old["decay_factor"] == pytest.approx(0.5, abs=0.001)
    assert abs(old["score"] - new["score"] / 2) <= 1
    assert old["score"] < new["score"]


def test_decay_matches_formula_and_rounds_once():
    result = _explain(_two_ips(10))[ATTACKER]
    expected = result["base_score"] * math.exp(-DEFAULT_DECAY_LAMBDA * 10)
    assert result["score"] == int(expected + 0.5)
    assert isinstance(result["score"], int)


def test_lambda_zero_disables_decay():
    result = _explain(_two_ips(200), decay_lambda=0)[ATTACKER]
    assert result["decay_factor"] == 1.0
    assert result["score"] == result["base_score"]


def test_lambda_is_configurable():
    events = _two_ips(24)
    slow = _explain(events, decay_lambda=0.001)[ATTACKER]["score"]
    fast = _explain(events, decay_lambda=0.1)[ATTACKER].get("score", 0)
    assert slow > fast


def test_negative_lambda_is_rejected():
    with pytest.raises(ValueError):
        _explain(_failures(ATTACKER, 3), decay_lambda=-0.1)
    with pytest.raises(ValueError):
        validate_decay_lambda(-1)
    with pytest.raises(ValueError):
        validate_decay_lambda("abc")


@pytest.mark.parametrize(
    "bad", [float("nan"), float("inf"), float("-inf"), "nan", "inf", "-inf"]
)
def test_non_finite_lambda_is_rejected(bad):
    with pytest.raises(ValueError):
        validate_decay_lambda(bad)
    with pytest.raises(ValueError):
        _explain(_failures(ATTACKER, 3), decay_lambda=bad)


def test_zero_lambda_is_valid():
    assert validate_decay_lambda(0) == 0.0


def test_future_or_reordered_timestamps_never_give_negative_hours():
    # Newest-first order plus a far-future event: any "last event after
    # reference time" arithmetic would go negative and inflate the score.
    future = _dated_failures(OTHER, 5, "2099-01-01 00:00:00")
    past = _dated_failures(ATTACKER, 5, "2026-09-28 09:00:00")
    result = _explain(future + past)
    assert result[OTHER]["hours_since_last_event"] == 0
    assert result[OTHER]["score"] == result[OTHER]["base_score"]
    for entry in result.values():
        assert entry["hours_since_last_event"] >= 0
        assert entry["decay_factor"] <= 1.0
        assert entry["score"] <= entry["base_score"] <= 100
    assert _explain(past + future) == result  # input order does not matter


def test_decay_is_relative_to_dataset_not_wall_clock():
    # Year-qualified, long past: the newest IP must not decay at all.
    events = log_parser.parse_lines(
        [
            "2001-01-01 10:00:00 junk",
            '203.0.113.5 - - [01/Jan/2001:10:00:00 +0000] "GET /a?x=../../etc/passwd HTTP/1.1" 404 1 "-" "x"',
        ]
    )
    result = _explain(events)["203.0.113.5"]
    assert result["decay_factor"] == 1.0


def test_headerless_events_are_not_decayed_in_mixed_datasets():
    """Regression: synthetic 1970 fallback times must never drive decay."""
    old = _dated_failures(ATTACKER, 5, "2026-09-27 12:00:00")
    new = _dated_failures(OTHER, 5, "2026-09-28 12:00:00")
    bare = _headerless_failures("9.9.9.9", 8)
    assert all(event["timestamp"] is None for event in bare)

    result = _explain(bare + old + new)
    assert result["9.9.9.9"]["score"] == result["9.9.9.9"]["base_score"] > 0
    assert result["9.9.9.9"]["decay_factor"] == 1.0
    assert result["9.9.9.9"]["last_event"] is None
    assert result[OTHER]["decay_factor"] == 1.0
    assert result[ATTACKER]["hours_since_last_event"] == pytest.approx(24, abs=0.01)
    assert result[ATTACKER]["decay_factor"] == pytest.approx(0.5, abs=0.001)


def test_headerless_ip_keeps_score_through_detect_threats():
    events = _headerless_failures("9.9.9.9", 8) + _failures(OTHER, 8)
    with_decay = {t["ip"]: t["risk_score"] for t in detect_threats(events)}
    no_decay = {t["ip"]: t["risk_score"] for t in detect_threats(events, decay_lambda=0)}
    assert with_decay["9.9.9.9"] == no_decay["9.9.9.9"] > 0


def test_decayed_to_zero_ip_is_kept_with_factors():
    old = _dated_failures(ATTACKER, 5, "2026-01-01 00:00:00")
    new = _dated_failures(OTHER, 5, "2026-09-28 00:00:00")
    result = _explain(old + new)
    entry = result[ATTACKER]
    assert entry["score"] == 0
    assert entry["base_score"] > 0
    assert entry["factors"]
    decay = [f for f in entry["factors"] if f["factor"] == "time_decay"][0]
    assert decay["points"] == -entry["base_score"]
    assert sum(f["points"] for f in entry["factors"]) == 0  # base fully decayed away
    assert result[OTHER]["score"] > 0
    assert compute_ip_risk_scores(old + new, [])[ATTACKER] == 0


def test_decayed_to_zero_ip_keeps_factors_through_alerts_and_api(tmp_path):
    from src.app import create_app

    lines = [
        f"Sep 28 09:13:{sec:02d} web01 sshd[2200]: Failed password for root from "
        f"{ATTACKER} port {50100 + sec} ssh2"
        for sec in (5, 14, 23, 31, 40, 49)
    ] + [
        '10.0.0.15 - - [28/Oct/2099:12:00:01 +0000] "GET / HTTP/1.1" 200 1 "-" "x"'
    ]
    threats = detect_threats(log_parser.parse_lines(lines))
    brute = [t for t in threats if t["ip"] == ATTACKER]
    assert brute and all(t["risk_score"] == 0 and t["risk_factors"] for t in brute)
    alerts = alert_manager.process_alerts(threats)
    assert all(a["risk_score"] == 0 and a["risk_factors"] for a in alerts if a["ip"] == ATTACKER)

    client = create_app(db_path=tmp_path / "z.db", reports_dir=tmp_path / "r").test_client()
    response = client.post(
        "/api/v1/upload",
        data={"file": (io.BytesIO("\n".join(lines).encode()), "a.log")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    rows = client.get(f"/api/v1/threats?ip={ATTACKER}").get_json()
    assert rows and all(r["risk_score"] == 0 and r["risk_factors"] for r in rows)


# ----------------------------------------------------------- invalid data
def test_missing_ip_and_bad_timestamps_do_not_crash():
    events = [
        {"timestamp": None, "ip": None, "action": "ssh_login_failure", "log_type": "auth"},
        {"timestamp": "garbage", "ip": ATTACKER, "action": "ssh_login_failure", "log_type": "auth", "user": "root"},
        "not-a-dict",
    ]
    threats = [{"type": "PORT_SCAN", "ip": None}, _threat("PORT_SCAN", timestamp="nonsense")]
    result = explain_ip_risk_scores([e for e in events if isinstance(e, dict)], threats)
    assert result[ATTACKER]["decay_factor"] == 1.0
    assert None not in result


# ----------------------------------------------------------- explainability
def test_every_score_lists_contributing_factors():
    events = _failures(ATTACKER, 6) + [_fw(ATTACKER, HONEYPOT)]
    threats = [_threat("SSH_BRUTE_FORCE")]
    result = _explain(events, threats, decay_lambda=0, honeypot_ips=[HONEYPOT])[ATTACKER]
    names = {f["factor"] for f in result["factors"]}
    assert {"rule:SSH_BRUTE_FORCE", "failed_logins", "honeypot"} <= names
    for factor in result["factors"]:
        assert {"factor", "points", "detail"} <= set(factor)
    assert sum(f["points"] for f in result["factors"]) == result["base_score"]


def test_decay_appears_as_a_factor_when_applied():
    entry = _explain(_two_ips(24))[ATTACKER]
    decay = [f for f in entry["factors"] if f["factor"] == "time_decay"]
    assert decay and decay[0]["points"] == entry["score"] - entry["base_score"]
    assert all(f["factor"] != "time_decay" for f in _explain(_two_ips(24))[OTHER]["factors"])


# ----------------------------------------------------- integration / compat
def test_compute_ip_risk_scores_keeps_int_mapping_type(brute_events):
    threats = detect_threats(brute_events)
    scores = compute_ip_risk_scores(brute_events, threats)
    assert all(isinstance(ip, str) and isinstance(v, int) for ip, v in scores.items())
    explained = explain_ip_risk_scores(brute_events, threats)
    assert scores == {ip: e["score"] for ip, e in explained.items()}


def test_detect_threats_attaches_factors_and_honeypot(brute_events):
    plain = detect_threats(brute_events, decay_lambda=0)
    boosted = detect_threats(
        brute_events + [_fw(ATTACKER, HONEYPOT)], decay_lambda=0, honeypot_ips=HONEYPOT
    )
    for threat in boosted:
        assert threat["risk_factors"]
    assert boosted[0]["risk_score"] >= plain[0]["risk_score"]
    assert any(f["factor"] == "honeypot" for f in boosted[0]["risk_factors"])


def test_alerts_carry_risk_factors(brute_events):
    alerts = alert_manager.process_alerts(detect_threats(brute_events))
    assert alerts and all(alert["risk_factors"] for alert in alerts)
    assert alerts[0]["payload"]["risk_factors"] == alerts[0]["risk_factors"]


def test_threats_api_exposes_risk_factors(client, brute_lines):
    response = client.post(
        "/api/v1/upload",
        data={"file": (io.BytesIO("\n".join(brute_lines).encode()), "a.log")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    rows = client.get("/api/v1/threats").get_json()
    assert rows and all(isinstance(row["risk_factors"], list) and row["risk_factors"] for row in rows)


def _sqli_lines(ip, stamp):
    """Two SQL-injection requests (one SQL_INJECTION threat, 2 exploit requests)."""
    return [
        f'{ip} - - [{stamp}7 +0000] "GET /index.php?id=1%20UNION%20SELECT%20username%20'
        f'FROM%20users HTTP/1.1" 404 162 "-" "sqlmap/1.7.2"',
        f'{ip} - - [{stamp}9 +0000] "GET /login.php?user=%27%20OR%20%271%27%3D%271 '
        f'HTTP/1.1" 200 981 "-" "sqlmap/1.7.2"',
    ]


def _fw_line(src, dst, stamp="Sep 28 12:00:30"):
    return (
        f"{stamp} fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11 "
        f"SRC={src} DST={dst} PROTO=TCP SPT=51000 DPT=22 WINDOW=1024"
    )


def _upload_and_get(app, lines, ip):
    client = app.test_client()
    response = client.post(
        "/api/v1/upload",
        data={"file": (io.BytesIO("\n".join(lines).encode()), "a.log")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    return client.get(f"/api/v1/threats?ip={ip}").get_json()


def test_honeypot_env_to_api_end_to_end(tmp_path, monkeypatch):
    from src.app import create_app

    # One SQL_INJECTION alert: rule 30 + 2 exploit requests = 32 (+20 honeypot = 52).
    lines = _sqli_lines(ATTACKER, "28/Sep/2026:12:00:0") + [_fw_line(ATTACKER, HONEYPOT)]

    def rows_for(honeypots, name):
        monkeypatch.setenv("HONEYPOT_IPS", honeypots)
        app = create_app(db_path=tmp_path / f"{name}.db", reports_dir=tmp_path / "r")
        return _upload_and_get(app, lines, ATTACKER)

    miss = rows_for("", "miss")
    hit = rows_for(HONEYPOT, "hit")
    assert [r["risk_score"] for r in miss] == [32]
    assert [r["risk_score"] for r in hit] == [52]
    assert [f for f in miss[0]["risk_factors"] if f["factor"] == "honeypot"] == []
    honeypot = [f for f in hit[0]["risk_factors"] if f["factor"] == "honeypot"]
    assert [(f["factor"], f["points"]) for f in honeypot] == [("honeypot", 20)]
    assert HONEYPOT in honeypot[0]["detail"]


def test_known_scenario_exact_score_and_factors():
    """Golden value, hand-calculated (not derived from the implementation):

    SQL injection rule .......... 30   (one rule type, counts once)
    3 failed SSH logins ......... 6    (3 x 2)
    2 exploit requests .......... 2    (2 x 1)
    honeypot destination hit .... 20
    total ....................... 58  (< 100, last event is the newest -> no decay)
    """
    web = log_parser.parse_lines(_sqli_lines(ATTACKER, "28/Sep/2026:12:00:0"))
    failures = _dated_failures(ATTACKER, 3, "2026-09-28 12:00:00")
    firewall = log_parser.parse_log_line(_fw_line(ATTACKER, HONEYPOT))
    firewall["timestamp"] = "2026-09-28 12:00:30"

    threats = detect_threats(failures + web + [firewall], honeypot_ips=HONEYPOT)
    assert [t["type"] for t in threats] == ["SQL_INJECTION", "SQL_INJECTION"]
    for threat in threats:
        assert threat["risk_score"] == 58
        factors = [(f["factor"], f["points"]) for f in threat["risk_factors"]]
        assert factors == [
            ("rule:SQL_INJECTION", 30),
            ("failed_logins", 6),
            ("exploit_requests", 2),
            ("honeypot", 20),
        ]
        assert sum(points for _name, points in factors) == 58


def test_api_decay_lambda_changes_returned_score(tmp_path, monkeypatch):
    """OLD last seen exactly 24h before NEW; each has base 32 (30 rule + 2 exploits)."""
    from src.app import create_app

    lines = _sqli_lines(OTHER, "27/Sep/2026:12:00:0") + _sqli_lines(ATTACKER, "28/Sep/2026:12:00:0")

    def scores(lambda_value, name):
        if lambda_value is None:
            monkeypatch.delenv("RISK_DECAY_LAMBDA", raising=False)
        else:
            monkeypatch.setenv("RISK_DECAY_LAMBDA", lambda_value)
        app = create_app(db_path=tmp_path / f"{name}.db", reports_dir=tmp_path / "r")
        client = app.test_client()
        client.post(
            "/api/v1/upload",
            data={"file": (io.BytesIO("\n".join(lines).encode()), "a.log")},
            content_type="multipart/form-data",
        )
        rows = client.get("/api/v1/threats").get_json()
        return {row["ip"]: row["risk_score"] for row in rows}

    # default 24h half-life: 32 * 0.5 = 16 for the older IP, newest untouched
    assert scores(None, "default") == {OTHER: 16, ATTACKER: 32}
    # lambda 0: no decay at all
    assert scores("0", "zero") == {OTHER: 32, ATTACKER: 32}
    # lambda 0.1/h: 32 * exp(-2.4) = 2.9 -> 3
    assert scores("0.1", "fast") == {OTHER: 3, ATTACKER: 32}


@pytest.mark.parametrize("kind", ["main", "demo"])
@pytest.mark.parametrize("mode", ["none", "flag", "env"])
def test_cli_honeypot_configuration_reaches_scoring(kind, mode, tmp_path, monkeypatch):
    log = tmp_path / "hp.log"
    log.write_text(
        "\n".join(_sqli_lines(ATTACKER, "28/Sep/2026:12:00:0") + [_fw_line(ATTACKER, HONEYPOT)])
    )
    db = tmp_path / "hp.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.delenv("HONEYPOT_IPS", raising=False)
    args = ["--log", str(log), "--db", str(db)]
    if mode == "flag":
        args += ["--honeypot-ips", HONEYPOT]
    elif mode == "env":
        monkeypatch.setenv("HONEYPOT_IPS", HONEYPOT)
    if kind == "main":
        from src import main

        assert main.main(args + ["--export", "none", "--quiet"]) == 0
    else:
        assert _load_demo_script().main(args + ["--fresh"]) == 0

    rows = database.get_threats(ip=ATTACKER, db_path=db)
    assert len(rows) == 1
    import json

    factors = json.loads(rows[0]["risk_factors"])
    honeypot = [f for f in factors if f["factor"] == "honeypot"]
    if mode == "none":
        assert honeypot == [] and rows[0]["risk_score"] == 32
    else:
        assert [f["points"] for f in honeypot] == [20]
        assert rows[0]["risk_score"] == 52


@pytest.mark.parametrize("kind", ["main", "demo"])
@pytest.mark.parametrize("lambda_args,expected", [([], {OTHER: 16, ATTACKER: 32}),
                                                   (["--decay-lambda", "0"], {OTHER: 32, ATTACKER: 32})])
def test_cli_decay_lambda_changes_stored_scores(kind, lambda_args, expected, tmp_path, monkeypatch):
    log = tmp_path / "d.log"
    log.write_text(
        "\n".join(_sqli_lines(OTHER, "27/Sep/2026:12:00:0") + _sqli_lines(ATTACKER, "28/Sep/2026:12:00:0"))
    )
    db = tmp_path / "d.db"
    monkeypatch.setenv("DB_PATH", str(db))
    monkeypatch.delenv("RISK_DECAY_LAMBDA", raising=False)
    args = ["--log", str(log), "--db", str(db)] + lambda_args
    if kind == "main":
        from src import main

        assert main.main(args + ["--export", "none", "--quiet"]) == 0
    else:
        assert _load_demo_script().main(args + ["--fresh"]) == 0
    rows = database.get_threats(db_path=db)
    assert {row["ip"]: row["risk_score"] for row in rows} == expected


def test_legacy_database_gains_risk_factors_column(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    conn = database.get_connection(db_path)
    conn.executescript(
        "CREATE TABLE threats (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, "
        "ip TEXT, severity TEXT, details TEXT, timestamp TEXT, risk_score INTEGER DEFAULT 0, "
        "attempts INTEGER DEFAULT 1)"
    )
    conn.commit()
    conn.close()
    monkeypatch.setenv("DB_PATH", str(db_path))
    database.init_db()
    conn = database.get_connection(db_path)
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(threats)")}
    conn.close()
    assert "risk_factors" in columns


def test_app_reads_lambda_and_honeypots_from_environment(tmp_path, monkeypatch):
    from src.app import create_app

    monkeypatch.setenv("RISK_DECAY_LAMBDA", "0.5")
    monkeypatch.setenv("HONEYPOT_IPS", "1.2.3.4, 5.6.7.8")
    app = create_app(db_path=tmp_path / "e.db", reports_dir=tmp_path / "r")
    assert app.config["RISK_DECAY_LAMBDA"] == 0.5
    assert app.config["HONEYPOT_IPS"] == {"1.2.3.4", "5.6.7.8"}

    monkeypatch.setenv("RISK_DECAY_LAMBDA", "-1")
    with pytest.raises(ValueError):
        create_app(db_path=tmp_path / "e2.db", reports_dir=tmp_path / "r")
    monkeypatch.delenv("RISK_DECAY_LAMBDA")
    monkeypatch.delenv("HONEYPOT_IPS")
    app = create_app(db_path=tmp_path / "e3.db", reports_dir=tmp_path / "r")
    assert app.config["RISK_DECAY_LAMBDA"] == pytest.approx(math.log(2) / 24)
    assert app.config["HONEYPOT_IPS"] == frozenset()


def _load_demo_script():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "scripts" / "build_demo_db.py"
    spec = importlib.util.spec_from_file_location("build_demo_db_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_cli(kind, tmp_path, extra=()):
    """Run main.py or build_demo_db.py with extra args."""
    from src import main

    if kind == "main":
        log = tmp_path / "a.log"
        log.write_text("\n".join(e["raw_line"] for e in _failures(ATTACKER, 8)))
        return main.main(["--log", str(log), "--no-save", "--export", "none", *extra])
    script = _load_demo_script()
    return script.main(["--db", str(tmp_path / "demo.db"), "--fresh", *extra])


@pytest.mark.parametrize("kind", ["main", "demo"])
@pytest.mark.parametrize("bad", ["-1", "nan", "inf", "-inf", "abc"])
def test_cli_rejects_invalid_decay_lambda_flag(kind, bad, tmp_path, capsys):
    with pytest.raises(SystemExit) as exit_info:
        _run_cli(kind, tmp_path, ["--decay-lambda=" + bad])
    assert exit_info.value.code == 2
    err = capsys.readouterr().err
    assert "--decay-lambda" in err and "Traceback" not in err


@pytest.mark.parametrize("kind", ["main", "demo"])
@pytest.mark.parametrize("bad", ["abc", "-1", "nan", "inf", " "])
def test_cli_rejects_invalid_decay_lambda_environment(kind, bad, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("RISK_DECAY_LAMBDA", bad)
    monkeypatch.setenv("DB_PATH", str(tmp_path / "env.db"))
    with pytest.raises(SystemExit) as exit_info:
        _run_cli(kind, tmp_path)
    assert exit_info.value.code == 2
    assert "--decay-lambda" in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["main", "demo"])
def test_cli_accepts_zero_and_empty_environment_lambda(kind, tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "ok.db"))
    assert _run_cli(kind, tmp_path, ["--decay-lambda", "0"]) == 0
    monkeypatch.setenv("RISK_DECAY_LAMBDA", "")  # empty -> default fallback
    assert _run_cli(kind, tmp_path) == 0
    monkeypatch.setenv("RISK_DECAY_LAMBDA", "0")
    assert _run_cli(kind, tmp_path) == 0
