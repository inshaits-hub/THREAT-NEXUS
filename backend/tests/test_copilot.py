"""Unit tests for the security copilot (src/copilot.py).

Covers the three stages (analyze/explain/remediate) and, critically, the
safety contract: generated firewall commands are validated, review-only
strings and the module contains no execution primitives.
"""

import io
import re
from pathlib import Path

import pytest

from src import copilot

KNOWN_TYPES = [
    "SSH_BRUTE_FORCE",
    "SSH_BRUTE_FORCE_SUCCESS",
    "SQL_INJECTION",
    "XSS_ATTEMPT",
    "DIRECTORY_TRAVERSAL",
    "TRAFFIC_SPIKE",
    "OFF_HOUR_ADMIN",
    "WEB_DIRECTORY_SCAN",
    "PORT_SCAN",
    "HONEYPOT_HIT",
]


def _threat(**overrides):
    base = {
        "type": "SSH_BRUTE_FORCE",
        "ip": "203.0.113.9",
        "severity": "HIGH",
        "details": "6 failed SSH login attempts from 203.0.113.9 within 60s",
        "risk_score": 92,
        "attempts": 6,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Stage 1: analyze
# ---------------------------------------------------------------------------

def test_analyze_identifies_alert():
    analysis = copilot.analyze(_threat())
    assert analysis["attack_type"] == "SSH_BRUTE_FORCE"
    assert analysis["title"]
    assert analysis["ip"] == "203.0.113.9"
    assert analysis["severity"] == "HIGH"
    assert "203.0.113.9" in analysis["evidence"]


def test_analyze_resolves_ip_from_details_when_column_missing():
    analysis = copilot.analyze(
        _threat(ip=None, details="blocked host 198.51.100.7 after 5 tries")
    )
    assert analysis["ip"] == "198.51.100.7"


# ---------------------------------------------------------------------------
# Stage 2: explain
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("threat_type", KNOWN_TYPES)
def test_explain_covers_every_rule(threat_type):
    text = copilot.explain(_threat(type=threat_type))
    assert text.strip()
    assert "203.0.113.9" in text


def test_explain_uses_decoy_path_from_details():
    text = copilot.explain(_threat(
        type="HONEYPOT_HIT",
        details="Decoy '/wp-login.php' requested by requester (GET, user-agent: x)",
    ))
    assert "/wp-login.php" in text


def test_explain_counts_attempts_in_bruteforce_reasoning():
    text = copilot.explain(_threat(attempts=7))
    assert "7" in text


def test_unknown_rule_still_explains():
    text = copilot.explain(_threat(type="SOMETHING_NEW"))
    assert "SOMETHING_NEW" in text


# ---------------------------------------------------------------------------
# Stage 3: remediate (review-only)
# ---------------------------------------------------------------------------

def test_remediate_returns_ufw_recommendations_for_valid_ip():
    result = copilot.remediate(_threat())
    assert result["steps"]
    assert result["commands"]
    for cmd in result["commands"]:
        assert cmd.startswith("sudo ufw ")
    # At least one command names the validated source IP; some rules also
    # add generic hardening commands (e.g. `ufw limit ... port 22`).
    assert any("203.0.113.9" in cmd for cmd in result["commands"])
    assert "never modifies" in result["note"]


def test_invalid_ip_becomes_placeholder_and_warns():
    result = copilot.remediate(_threat(ip="1.2.3.4; rm -rf /"))
    assert result["warnings"]
    assert result["commands"]
    assert any("<ATTACKER_IP>" in cmd for cmd in result["commands"])
    joined = " ".join(result["commands"])
    assert ";" not in joined
    assert "rm -rf" not in joined
    assert "1.2.3.4" not in joined  # hostile input never interpolated


def test_hostile_never_reaches_commands():
    result = copilot.remediate(_threat(ip=None, details="evil $(reboot) x"))
    joined = " ".join(result["commands"])
    assert "$(reboot)" not in joined
    if result["commands"]:
        assert "<ATTACKER_IP>" in joined
    assert result["warnings"]


def test_commands_match_safe_ufw_grammar():
    for hostile_ip in ("203.0.113.9", "2001:db8::1", "junk; drop table x",
                       "<ATTACKER_IP>", None):
        for cmd in copilot.remediate(_threat(ip=hostile_ip))["commands"]:
            assert cmd.startswith("sudo ufw "), cmd
            match = re.search(r"\bfrom (\S+)", cmd)
            if match:
                token = match.group(1)
                if token != "<ATTACKER_IP>":
                    import ipaddress
                    ipaddress.ip_address(token)  # raises if unsafe


def test_module_contains_no_execution_primitives():
    source = Path("src/copilot.py").read_text(encoding="utf-8")
    assert not re.search(r"^\s*(import subprocess|from subprocess)", source, re.M)
    assert "os.system(" not in source
    assert "os.popen(" not in source
    assert not re.search(r"\beval\(", source)
    assert not re.search(r"\bexec\(", source)
    assert not re.search(r"__import__\(", source)
    assert "pty." not in source


def test_build_playbook_shape():
    playbook = copilot.build_playbook(_threat())
    assert set(playbook) == {"analysis", "explanation", "playbook"}
    assert playbook["playbook"]["note"]
    assert isinstance(playbook["playbook"]["commands"], list)


# ---------------------------------------------------------------------------
# Compatibility wrapper (old barira_dev API): generate_copilot_output
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("threat_type", KNOWN_TYPES)
def test_wrapper_has_explanation_and_remediation_for_each_type(threat_type):
    out = copilot.generate_copilot_output({"type": threat_type, "ip": "10.0.0.5"})
    assert out["explanation"]
    assert out["remediation"]


def test_wrapper_remediation_has_reviewable_command():
    out = copilot.generate_copilot_output({"type": "SSH_BRUTE_FORCE", "ip": "10.0.0.5"})
    assert any(
        step.startswith("sudo ufw deny from 10.0.0.5") for step in out["remediation"]
    )


def test_wrapper_never_auto_applies():
    out = copilot.generate_copilot_output({"type": "PORT_SCAN", "ip": "10.0.0.5"})
    assert out["auto_applied"] is False


def test_wrapper_accepts_source_ip_key():
    out = copilot.generate_copilot_output(
        {"type": "PORT_SCAN", "source_ip": "10.0.0.5"}
    )
    assert "10.0.0.5" in out["explanation"]
    assert any("10.0.0.5" in step for step in out["remediation"])


def test_wrapper_unknown_type_still_explains():
    out = copilot.generate_copilot_output({"type": "WEIRD", "ip": "10.0.0.5"})
    assert "10.0.0.5" in out["explanation"]


def test_wrapper_malicious_ip_is_rejected():
    out = copilot.generate_copilot_output(
        {"type": "SSH_BRUTE_FORCE", "ip": "1.1.1.1; rm -rf /"}
    )
    assert all("rm -rf" not in step for step in out["remediation"])
    assert any("<ATTACKER_IP>" in step for step in out["remediation"])


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------

def test_copilot_endpoint_explains_a_stored_threat(client, brute_lines):
    upload = client.post(
        "/api/v1/upload",
        data={"file": (io.BytesIO("\n".join(brute_lines).encode()), "b.log")},
        content_type="multipart/form-data",
    )
    assert upload.status_code == 200
    threats = client.get("/api/v1/threats").get_json()
    threat_id = threats[0]["id"]

    resp = client.get(f"/api/v1/copilot/{threat_id}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["threat_id"] == threat_id
    assert body["analysis"]["attack_type"]
    assert body["explanation"]
    assert body["playbook"]["commands"] is not None
    assert "never modifies" in body["playbook"]["note"]


def test_copilot_endpoint_404_for_unknown_threat(client):
    resp = client.get("/api/v1/copilot/999999")
    assert resp.status_code == 404
    assert resp.get_json()["status"] == "error"