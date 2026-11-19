"""Core Module 7 - AI Security Copilot (rules/template engine).

Turns a detection into a human-readable explanation and a defensive
playbook: **Analyze → Explain → Remediate**.

Safety contract (academic baseline, deliberately boring):

* Pure Python templates - **no LLM is required and none is executed**.
  A future optional LLM layer can wrap :func:`explain`; it must stay a
  non-default enhancement, never a hard dependency.
* Remediation commands are **strings returned for human review only**.
  This module never imports ``subprocess``/``os.system`` and never
  executes anything - a unit test asserts that at source level.
* Attacker-controlled IPs are validated with :mod:`ipaddress` before they
  are interpolated into a command. Anything that is not a syntactically
  valid IP address becomes the literal ``<ATTACKER_IP>`` placeholder plus
  a warning, so a hostile log line can never smuggle shell syntax into a
  generated recommendation.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional

try:  # package import
    from .alert_manager import normalize_severity, title_for
except ImportError:  # script import (``python src/main.py``)
    from alert_manager import normalize_severity, title_for

__all__ = [
    "analyze",
    "explain",
    "remediate",
    "build_playbook",
    "generate_copilot_output",
]

#: Each rule type gets reasoning + playbook steps + command *templates*.
#: ``{ip}`` is filled only after validation (see ``_safe_ip``).
_RULES = {
    "SSH_BRUTE_FORCE": {
        "summary": (
            "{count} failed SSH login attempts from {ip} inside a 60s window "
            "is credential brute-forcing, not a misconfiguration."
        ),
        "steps": [
            "Confirm the source is not a shared NAT/VPN egress address.",
            "Temporarily restrict SSH to known source IPs or keys only.",
            "Enable fail2ban-style rate limiting on sshd.",
            "Force password rotation for the targeted accounts.",
        ],
        "commands": [
            "sudo ufw deny from {ip} comment 'ThreatNexus: SSH brute force'",
            "sudo ufw limit in on eth0 port 22 proto tcp",
        ],
    },
    "SSH_BRUTE_FORCE_SUCCESS": {
        "summary": (
            "A successful SSH login for {ip} followed a burst of failures - "
            "assume the account may be compromised until proven otherwise."
        ),
        "steps": [
            "Reset credentials for the logged-in account immediately.",
            "Review ~/.ssh/authorized_keys and shell history on the host.",
            "Check for new cron jobs, users and outbound connections.",
            "Block the source IP pending investigation.",
        ],
        "commands": [
            "sudo ufw deny from {ip} comment 'ThreatNexus: post-brute login'",
        ],
    },
    "SQL_INJECTION": {
        "summary": (
            "Request payloads from {ip} contain SQL syntax "
            "('union select', 'sleep(', boolean tautologies) aimed at "
            "extracting or mutating database content."
        ),
        "steps": [
            "Route the matching application logs to the incident record.",
            "Verify parameterized queries / ORM usage on the matched route.",
            "WAF-rate-limit the source while the patch is verified.",
        ],
        "commands": [
            "sudo ufw deny from {ip} comment 'ThreatNexus: SQL injection'",
        ],
    },
    "XSS_ATTEMPT": {
        "summary": (
            "Request payloads from {ip} carry script tags or event handlers "
            "intended to execute in another user's browser."
        ),
        "steps": [
            "Confirm output encoding on the matched route.",
            "Review stored content written around the same timestamp.",
            "Rate-limit the source pending patch verification.",
        ],
        "commands": [
            "sudo ufw deny from {ip} comment 'ThreatNexus: XSS attempt'",
        ],
    },
    "DIRECTORY_TRAVERSAL": {
        "summary": (
            "Request targets from {ip} contain ../-style traversal or "
            "sensitive system paths (/etc/passwd, win.ini, ...)."
        ),
        "steps": [
            "Check web-server access logs for the exact decoded path.",
            "Verify path canonicalization and chroot/jail configuration.",
            "Block the source while the file-access control is reviewed.",
        ],
        "commands": [
            "sudo ufw deny from {ip} comment 'ThreatNexus: traversal attempt'",
        ],
    },
    "TRAFFIC_SPIKE": {
        "summary": (
            "{ip} produced an abnormal request burst in one minute - "
            "volumetric probing or an automated scanner."
        ),
        "steps": [
            "Confirm it is not a legitimate batch job or monitoring sweep.",
            "Enable rate limiting for the source if the burst repeats.",
        ],
        "commands": [
            "sudo ufw limit from {ip} comment 'ThreatNexus: traffic spike'",
        ],
    },
    "OFF_HOUR_ADMIN": {
        "summary": (
            "Administrative/sensitive activity from {ip} during off-hours "
            "(00:00-05:59) - legitimate admin work rarely happens then."
        ),
        "steps": [
            "Correlate with the change-management/on-call record.",
            "Require MFA for administrative logins if not already enforced.",
        ],
        "commands": [],
    },
    "WEB_DIRECTORY_SCAN": {
        "summary": (
            "{ip} requested many distinct paths in 60s - content discovery "
            "scanning ahead of an exploit attempt."
        ),
        "steps": [
            "Compare probed paths against your actual site map.",
            "Rate-limit the source and watch for a follow-up exploit wave.",
        ],
        "commands": [
            "sudo ufw limit from {ip} comment 'ThreatNexus: directory scan'",
        ],
    },
    "PORT_SCAN": {
        "summary": (
            "{ip} probed many distinct destination ports in 60s - "
            "service enumeration before a targeted attack."
        ),
        "steps": [
            "Confirm which services were reached and their exposure.",
            "Restrict inbound exposure to required ports only.",
        ],
        "commands": [
            "sudo ufw deny from {ip} comment 'ThreatNexus: port scan'",
        ],
    },
    "HONEYPOT_HIT": {
        "summary": (
            "A deliberately unreachable decoy ({path}) was requested by "
            "{ip}. No legitimate user or integration ever needs this path, "
            "so this is a high-confidence malicious signal."
        ),
        "steps": [
            "Treat the source as hostile until proven otherwise.",
            "Correlate the same IP against normal application traffic.",
            "Review whether the scanner reached any real service.",
        ],
        "commands": [
            "sudo ufw deny from {ip} comment 'ThreatNexus: honeypot hit'",
        ],
    },
    "UNKNOWN": {
        "summary": (
            "Alert raised for {ip} by rule '{rule}' with severity "
            "{severity}."
        ),
        "steps": [
            "Inspect the raw alert details and related log lines.",
            "Apply your normal incident-response procedure.",
        ],
        "commands": [],
    },
}


def _rule_for(threat_type) -> dict:
    return _RULES.get(str(threat_type or "UNKNOWN"), _RULES["UNKNOWN"])


def _safe_ip(value) -> Optional[str]:
    """Return the IP if it is syntactically valid, else ``None``.

    This is the only gate before an IP reaches a command string.
    """
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _first_match_ip(threat: dict) -> Optional[str]:
    """Pull a candidate IP out of free-text details (best effort)."""
    details = str(threat.get("details") or "")
    for token in re.findall(r"\b[0-9A-Fa-f:.]{2,45}\b", details):
        safe = _safe_ip(token)
        if safe:
            return safe
    return None


def _resolve_ip(threat: dict) -> Optional[str]:
    """Single source of truth for the alert's IP.

    * ``ip`` (or ``source_ip``) present and valid -> use it.
    * present but invalid -> ``None``; hostile input is never "repaired"
      by guessing another address from the details text.
    * absent -> best-effort IP found in the free-text details.

    Used by analyze/explain/remediate so all three stages agree on which
    address they are talking about.
    """
    raw = threat.get("ip") or threat.get("source_ip")
    if raw:
        return _safe_ip(raw)
    return _first_match_ip(threat)


def analyze(threat: dict) -> dict:
    """Stage 1 - identify attack type, IP, evidence and severity."""
    threat_type = str(threat.get("type") or "UNKNOWN")
    return {
        "attack_type": threat_type,
        "title": title_for(threat_type),
        "ip": _resolve_ip(threat),
        "path": threat.get("path") or None,
        "evidence": str(threat.get("details") or threat.get("raw_line") or ""),
        "severity": normalize_severity(
            threat.get("severity"), threat.get("risk_score")
        ),
    }


def explain(threat: dict) -> str:
    """Stage 2 - plain-English reasoning for the alert."""
    rule = _rule_for(threat.get("type"))
    ip = _resolve_ip(threat) or "an unresolved source"
    try:
        attempts = max(1, int(threat.get("attempts") or 1))
    except (TypeError, ValueError):
        attempts = 1
    # Details are log-derived text; quote them but never interpret them
    # as markup - callers render this as text.
    path = str(threat.get("path") or "")
    if not path:
        match = re.search(r"Decoy '([^']+)'", str(threat.get("details") or ""))
        path = match.group(1) if match else "decoy endpoint"
    text = rule["summary"].format(
        ip=ip,
        count=attempts,
        path=path,
        rule=str(threat.get("type") or "UNKNOWN"),
        severity=analyze(threat)["severity"],
    )
    return text


def remediate(threat: dict) -> dict:
    """Stage 3 - reviewable defensive commands and hardening steps.

    **Recommendations only.** Nothing here is executed anywhere in the
    codebase; the operator reviews and runs (or rejects) each command.
    """
    rule = _rule_for(threat.get("type"))
    warnings: List[str] = []

    raw_ip = threat.get("ip") or threat.get("source_ip")
    ip = _resolve_ip(threat)
    if ip is None:
        if raw_ip:
            warnings.append(
                f"Source '{str(raw_ip)[:64]}' is not a valid IP address; "
                "replace <ATTACKER_IP> manually before running anything."
            )
        else:
            warnings.append(
                "No source IP on this alert; <ATTACKER_IP> is a placeholder."
            )
        ip = "<ATTACKER_IP>"

    commands = [
        template.format(ip=ip) for template in rule.get("commands", [])
    ]
    return {
        "steps": list(rule.get("steps", [])),
        "commands": commands,
        "warnings": warnings,
        "note": (
            "ThreatNexus only recommends defensive commands - review each "
            "one and run it yourself; the platform never modifies the "
            "firewall."
        ),
    }


def build_playbook(threat: dict) -> dict:
    """All three stages in one payload (API / Socket.IO friendly)."""
    return {
        "analysis": analyze(threat),
        "explanation": explain(threat),
        "playbook": remediate(threat),
    }


def generate_copilot_output(alert: dict) -> Dict[str, object]:
    """Compatibility wrapper for the old ``barira_dev`` API.

    Returns the flat shape ``{explanation, remediation, auto_applied}``
    on top of the Module 7 engine. New code should call
    :func:`build_playbook` instead. Still recommendation-only.
    """
    playbook = remediate(alert)
    return {
        "explanation": explain(alert),
        "remediation": playbook["steps"] + playbook["commands"],
        "auto_applied": False,
    }