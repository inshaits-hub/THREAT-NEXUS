"""Core Module 1 - Regex based log ingestion and normalization.

Supported formats
-----------------
1. Linux ``auth.log``  - syslog framed SSH / PAM events
   (``Accepted password``, ``Failed password``, ``Invalid user``, PAM
   ``authentication failure``).
2. Nginx / Apache access logs - Combined Log Format
   (``IP - - [timestamp] "GET /path HTTP/1.1" status bytes``).
3. Standard syslog - RFC3164 style ``timestamp host process: message`` lines
   (including firewall records such as ``UFW BLOCK``).

``parse_log_line`` returns ``None`` for anything it cannot recognize, so
callers can silently skip malformed input.  The module only depends on the
Python standard library, which keeps it usable from the CLI, the Flask API
and pytest without any coupling.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

__all__ = [
    "parse_log_line",
    "parse_lines",
    "parse_text",
    "parse_file",
    "parse_timestamp",
    "event_time",
    "event_destination",
]

# --------------------------------------------------------------------------- #
# Regex definitions
# --------------------------------------------------------------------------- #

# ``timestamp host process[pid](tag): message`` - the process token is lazy so
# names that contain parentheses/colons (``pam_unix(sshd:auth):``) parse cleanly.
SYSLOG_RE = re.compile(
    r"^(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\s:\[]+?)(?:\[(?P<pid>\d+)\])?(?:\((?P<tag>[^)]*)\))?:\s*"
    r"(?P<message>.*)$"
)

# Logs that dropped the syslog header but keep the daemon prefix.
BARE_DAEMON_RE = re.compile(
    r"^(?P<process>sshd|sudo|systemd-logind|cron)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

# Combined Log Format (Nginx / Apache). The request target is matched lazily
# up to the closing quote so encoded *and* raw-space targets both survive.
WEB_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?:(?P<method>[A-Z]{3,10})\s+(?P<path>.*?)(?:\s+(?P<protocol>HTTP/[\d.]+))?|-)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)")?(?:\s+"(?P<agent>[^"]*)")?\s*$'
)

# SSH / PAM message rules: (regex, action, fields)
_AUTH_RULES = [
    (
        re.compile(
            r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) "
            r"port (?P<port>\d+)"
        ),
        "ssh_login_success",
    ),
    (
        re.compile(
            r"Failed password for (?:invalid user )?(?P<user>\S+) from "
            r"(?P<ip>\S+) port (?P<port>\d+)"
        ),
        "ssh_login_failure",
    ),
    (
        re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"),
        "ssh_invalid_user",
    ),
    (
        re.compile(
            r"authentication failure;.*?rhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?",
            re.IGNORECASE,
        ),
        "ssh_auth_failure",
    ),
    (
        re.compile(r"session opened for user (?P<user>\S+)"),
        "ssh_session_opened",
    ),
    (
        re.compile(r"Received disconnect from (?P<ip>\S+)"),
        "ssh_disconnect",
    ),
]

_FIREWALL_SRC_RE = re.compile(r"\bSRC=(?P<ip>[0-9A-Fa-f:.]+)")
_FIREWALL_DST_RE = re.compile(r"\bDST=(?P<ip>[0-9A-Fa-f:.]+)")
_FIREWALL_DPT_RE = re.compile(r"\bDPT=(?P<port>\d+)")
_FIREWALL_RE = re.compile(r"\bUFW BLOCK\b|\bDROP\b|iptables", re.IGNORECASE)

_ACTION_SUCCESS = "ssh_login_success"


# --------------------------------------------------------------------------- #
# Timestamp helpers
# --------------------------------------------------------------------------- #
def _naive_utc(dt: datetime) -> datetime:
    """Drop tz info after normalizing to UTC so all times are comparable."""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def parse_timestamp(value, default_year: Optional[int] = None) -> Optional[datetime]:
    """Parse the timestamp shapes found in the supported log formats.

    Returns a **naive UTC** :class:`datetime` or ``None`` when the value is
    not recognizable.  Syslog timestamps carry no year, so ``default_year``
    (defaults to the current year) is injected.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return _naive_utc(value)

    text = str(value).strip()
    if not text:
        return None

    # Epoch seconds.
    if re.fullmatch(r"\d{9,11}(\.\d+)?", text):
        return datetime.fromtimestamp(float(text), tz=timezone.utc).replace(tzinfo=None)

    compact = re.sub(r"\s+", " ", text)

    # ISO-8601 (``2026-09-28T03:05:00``, ``...+00:00``, ``...Z``).
    try:
        return _naive_utc(datetime.fromisoformat(compact.replace("Z", "+00:00")))
    except ValueError:
        pass

    # Web access log: ``28/Sep/2026:02:14:07 +0000``.
    try:
        return _naive_utc(datetime.strptime(compact, "%d/%b/%Y:%H:%M:%S %z"))
    except ValueError:
        pass

    # Already year-qualified.
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%b %d %Y %H:%M:%S"):
        try:
            return datetime.strptime(compact, fmt)
        except ValueError:
            continue

    # Syslog / auth.log: ``Sep 28 09:12:01`` (year injected).
    try:
        return datetime.strptime(
            f"{default_year or datetime.now().year} {compact}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None


def event_time(event: Dict) -> Optional[datetime]:
    """Naive-UTC datetime for a normalized event (or ``None``)."""
    if not isinstance(event, dict):
        return None
    return parse_timestamp(event.get("timestamp"))


def event_destination(event: Dict) -> Optional[str]:
    """Destination IP (``DST=``) of a firewall record, or ``None``."""
    if not isinstance(event, dict) or event.get("action") != "firewall_block":
        return None
    match = _FIREWALL_DST_RE.search(str(event.get("raw_line") or ""))
    return match.group("ip") if match else None


# --------------------------------------------------------------------------- #
# Event builders
# --------------------------------------------------------------------------- #
def _base_event(
    timestamp,
    ip,
    user,
    action,
    status_code,
    raw_line,
    log_type,
    **extra,
) -> Dict:
    event = {
        "timestamp": timestamp,
        "ip": ip,
        "user": user,
        "action": action,
        "status_code": status_code,
        "raw_line": raw_line,
        "log_type": log_type,
    }
    event.update(extra)
    return event


def _build_auth_event(meta: Dict, raw_line: str) -> Optional[Dict]:
    message = meta.get("message") or ""
    for pattern, action in _AUTH_RULES:
        match = pattern.search(message)
        if not match:
            continue
        groups = match.groupdict()
        port = groups.get("port")
        return _base_event(
            timestamp=meta.get("timestamp"),
            ip=groups.get("ip"),
            user=groups.get("user"),
            action=action,
            status_code=None,
            raw_line=raw_line,
            log_type="auth",
            host=meta.get("host"),
            process=meta.get("process"),
            pid=meta.get("pid"),
            message=message,
            port=int(port) if port else None,
        )
    return None


def _build_syslog_event(meta: Dict, raw_line: str) -> Dict:
    message = meta.get("message") or ""
    ip = None
    dst_port = None
    action = "syslog_event"

    src_match = _FIREWALL_SRC_RE.search(message)
    if src_match:
        ip = src_match.group("ip")
        port_match = _FIREWALL_DPT_RE.search(message)
        if port_match:
            dst_port = int(port_match.group("port"))
        if _FIREWALL_RE.search(message):
            action = "firewall_block"

    return _base_event(
        timestamp=meta.get("timestamp"),
        ip=ip,
        user=None,
        action=action,
        status_code=None,
        raw_line=raw_line,
        log_type="syslog",
        host=meta.get("host"),
        process=meta.get("process"),
        pid=meta.get("pid"),
        message=message,
        dst_port=dst_port,
    )


def _build_web_event(match: "re.Match[str]", raw_line: str) -> Dict:
    groups = match.groupdict()
    return _base_event(
        timestamp=groups.get("timestamp"),
        ip=groups.get("ip"),
        user=None,
        action="http_request",
        status_code=int(groups["status"]),
        raw_line=raw_line,
        log_type="web",
        method=groups.get("method"),
        path=groups.get("path"),
        protocol=groups.get("protocol"),
        bytes_sent=groups.get("bytes"),
        referrer=groups.get("referrer"),
        user_agent=groups.get("agent"),
    )


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def parse_log_line(line: str) -> Optional[Dict]:
    """Identify the format of ``line`` and normalize it.

    Returns ``{timestamp, ip, user, action, status_code, raw_line, log_type}``
    plus format specific extras (``path``/``method`` for web events, ``host``/
    ``process``/``message`` for syslog, ``port`` for SSH events), or ``None``
    when the line does not match any supported format.
    """
    if line is None:
        return None
    raw = str(line).rstrip("\r\n")
    text = raw.strip()
    if not text:
        return None

    # 1) auth.log / syslog framed line.
    match = SYSLOG_RE.match(text)
    if match:
        meta = {
            "timestamp": match.group("timestamp"),
            "host": match.group("host"),
            "process": match.group("process"),
            "pid": match.group("pid"),
            "message": match.group("message"),
        }
        auth_event = _build_auth_event(meta, raw)
        if auth_event is not None:
            return auth_event
        return _build_syslog_event(meta, raw)

    # 2) Daemon prefixed line without syslog header.
    match = BARE_DAEMON_RE.match(text)
    if match:
        meta = {
            "timestamp": None,
            "host": None,
            "process": match.group("process"),
            "pid": match.group("pid"),
            "message": match.group("message"),
        }
        auth_event = _build_auth_event(meta, raw)
        if auth_event is not None:
            return auth_event

    # 3) Web access log.
    match = WEB_RE.match(text)
    if match:
        return _build_web_event(match, raw)

    # 4) Bare SSH/PAM message with no daemon prefix at all.
    return _build_auth_event(
        {"timestamp": None, "host": None, "process": None, "message": text}, raw
    )


def parse_lines(lines: Iterable[str]) -> List[Dict]:
    """Parse an iterable of raw lines, skipping anything unrecognized."""
    events: List[Dict] = []
    for line in lines:
        event = parse_log_line(line)
        if event is not None:
            events.append(event)
    return events


def parse_text(text: str) -> List[Dict]:
    """Parse a whole document (e.g. an uploaded file's contents)."""
    return parse_lines((text or "").splitlines())


def parse_file(filepath: str) -> List[Dict]:
    """Read ``filepath`` line-by-line and return every parsed event.

    Unreadable bytes are replaced instead of raising so partially corrupt
    captures still analyze.  ``FileNotFoundError`` propagates to the caller.
    """
    path = Path(filepath)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle)
