"""Core Module 5 - Executive reporting (standalone HTML + structured JSON).

Both writers are plain functions: hand them a summary dict and a list of
threat/alert records and they render a self-contained file into ``reports/``.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

try:  # package import
    from .alert_manager import (
        BADGE_COLORS,
        badge_for,
        normalize_severity,
        severity_counts,
        title_for,
    )
except ImportError:  # script import (``python src/main.py``)
    from alert_manager import (
        BADGE_COLORS,
        badge_for,
        normalize_severity,
        severity_counts,
        title_for,
    )

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

CSS = """
:root{--bg:#0f172a;--card:#1e293b;--line:#334155;--text:#e2e8f0;--muted:#94a3b8;}
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#f1f5f9;color:#0f172a;}
.wrap{max-width:1180px;margin:0 auto;padding:32px 24px 64px}
header.top{background:var(--bg);color:#fff;border-radius:14px;padding:28px 32px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
header.top h1{margin:0;font-size:24px;letter-spacing:.4px}
header.top .meta{color:var(--muted);font-size:13px;text-align:right}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:16px;margin:24px 0}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:18px 20px;box-shadow:0 1px 3px rgba(15,23,42,.06)}
.card .label{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#64748b}
.card .value{font-size:32px;font-weight:700;margin-top:6px}
.card.crit .value{color:#dc2626}
section{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:22px 24px;margin-top:22px;box-shadow:0 1px 3px rgba(15,23,42,.06)}
section h2{margin:0 0 16px;font-size:17px;text-transform:uppercase;letter-spacing:.8px;color:#334155;border-bottom:1px solid #e2e8f0;padding-bottom:10px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:#64748b;padding:8px 10px;border-bottom:2px solid #e2e8f0}
td{padding:9px 10px;border-bottom:1px solid #f1f5f9;vertical-align:top}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:11.5px;font-weight:700;letter-spacing:.6px;color:#fff}
.badge.red{background:#dc2626}.badge.orange{background:#f97316}.badge.yellow{background:#eab308;color:#422006}.badge.blue{background:#3b82f6}
.bar{position:relative;background:#e2e8f0;border-radius:6px;height:14px;min-width:120px;overflow:hidden}
.bar>span{position:absolute;left:0;top:0;bottom:0;border-radius:6px}
.ip{font-family:Consolas,'Courier New',monospace;font-weight:600}
.mono{font-family:Consolas,'Courier New',monospace;font-size:13px}
.muted{color:#94a3b8}
.empty{padding:24px;text-align:center;color:#64748b;font-size:15px}
footer{margin-top:26px;text-align:center;color:#94a3b8;font-size:12.5px}
.distro{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}
.distro .item{border:1px solid #e2e8f0;border-radius:10px;padding:12px 14px}
.distro .item .n{font-size:22px;font-weight:700}
"""

_SEVERITY_HEX = {
    "CRITICAL": "#dc2626",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#3b82f6",
}


# --------------------------------------------------------------------------- #
# Summary helpers
# --------------------------------------------------------------------------- #
def _threat_severity(threat: Dict) -> str:
    return normalize_severity(threat.get("severity"), threat.get("risk_score"))


def _type_counts(threats: Iterable[Dict]) -> Dict[str, int]:
    return dict(
        Counter(str(threat.get("type") or "UNKNOWN") for threat in threats or [])
    )


def _top_risk_ips(threats: Iterable[Dict], limit: int = 5) -> List[Dict]:
    best: Dict[str, Dict] = {}
    per_count: Counter = Counter()
    for threat in threats or []:
        ip = threat.get("ip")
        if not ip:
            continue
        per_count[ip] += 1
        score = int(threat.get("risk_score") or 0)
        if ip not in best or score > best[ip]["risk_score"]:
            best[ip] = {"ip": ip, "risk_score": score}
    ranked = sorted(
        best.values(), key=lambda row: (-row["risk_score"], -per_count[row["ip"]])
    )
    for row in ranked:
        row["threat_count"] = per_count[row["ip"]]
    return ranked[:limit]


def build_summary(
    parsed_events: Optional[Iterable[Dict]] = None,
    threats: Optional[Iterable[Dict]] = None,
    counts: Optional[Dict] = None,
) -> Dict:
    """Build the metric dictionary used by reports, the CLI and the API.

    Provide either ``parsed_events`` (counts derived) or ``counts`` (e.g. from
    a database ``get_summary()`` call).
    """
    threats = list(threats or [])
    if counts is None:
        events = list(parsed_events or [])
        counts = {
            "total_events": len(events),
            "unique_ips": len({e.get("ip") for e in events if e.get("ip")}),
        }
    severity = severity_counts(threats)
    summary = {
        "total_events": int(counts.get("total_events", 0)),
        "total_threats": int(counts.get("total_threats", len(threats))),
        "critical_threats": int(
            counts.get("critical_threats", severity.get("CRITICAL", 0))
        ),
        "unique_ips": int(counts.get("unique_ips", 0)),
        "severity_counts": severity,
        "threat_types": _type_counts(threats),
        "top_risk_ips": _top_risk_ips(threats),
        "generated_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
    }
    return summary


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #
def _bar(percent: float, color: str) -> str:
    percent = max(3, min(100, percent))
    return (
        f'<div class="bar"><span style="width:{percent:.0f}%;background:{color}">'
        f"</span></div>"
    )


def _cards_html(summary: Dict) -> str:
    riskiest = (summary.get("top_risk_ips") or [{}])[0]
    cards = [
        ("Total Events", summary.get("total_events", 0), ""),
        ("Total Threats", summary.get("total_threats", 0), ""),
        ("Critical Threats", summary.get("critical_threats", 0), "crit"),
        ("Unique IPs", summary.get("unique_ips", 0), ""),
        (
            "Riskiest IP",
            f'<span class="ip" style="font-size:20px">{html.escape(str(riskiest.get("ip") or "n/a"))}</span>'
            + (
                f'<div class="muted" style="font-size:13px">score {int(riskiest.get("risk_score") or 0)}/100</div>'
                if riskiest.get("ip")
                else ""
            ),
            "",
        ),
    ]
    rendered = []
    for label, value, css in cards:
        inner = value if isinstance(value, str) else html.escape(str(value))
        rendered.append(
            f'<div class="card {css}"><div class="label">{html.escape(label)}</div>'
            f'<div class="value">{inner}</div></div>'
        )
    return '<div class="cards">' + "".join(rendered) + "</div>"


def _severity_section(summary: Dict, threats: List[Dict]) -> str:
    counts = summary.get("severity_counts") or severity_counts(threats)
    total = sum(counts.values()) or 1
    items = []
    for name in SEVERITIES:
        count = int(counts.get(name, 0))
        pct = 100.0 * count / total
        items.append(
            f'<div class="item"><div class="muted">{name}</div>'
            f'<div class="n" style="color:{_SEVERITY_HEX[name]}">{count}</div>'
            f"{_bar(pct, _SEVERITY_HEX[name])}</div>"
        )
    return '<div class="distro">' + "".join(items) + "</div>"


def _type_section(summary: Dict, threats: List[Dict]) -> str:
    counts = summary.get("threat_types") or _type_counts(threats)
    if not counts:
        return '<div class="empty">No threat types recorded.</div>'
    total = sum(counts.values()) or 1
    max_count = max(counts.values())
    rows = []
    for kind, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        pct = 100.0 * count / total
        rows.append(
            f"<tr><td>{html.escape(title_for(kind))}</td>"
            f'<td class="mono">{html.escape(str(kind))}</td>'
            f"<td>{count}</td><td>{pct:.1f}%</td>"
            f"<td>{_bar(100.0 * count / max_count, '#3b82f6')}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Threat</th><th>Rule</th><th>Count</th>"
        "<th>Share</th><th>Distribution</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _risk_ips_section(summary: Dict) -> str:
    rows = summary.get("top_risk_ips") or []
    if not rows:
        return '<div class="empty">No risky IPs identified.</div>'
    body = []
    for row in rows:
        score = int(row.get("risk_score") or 0)
        color = "#dc2626" if score >= 80 else "#f97316" if score >= 60 else "#eab308" if score >= 30 else "#3b82f6"
        body.append(
            f'<tr><td class="ip">{html.escape(str(row.get("ip")))}</td>'
            f"<td>{score}/100</td>"
            f"<td>{_bar(score, color)}</td>"
            f"<td>{int(row.get('threat_count') or 0)}</td></tr>"
        )
    return (
        "<table><thead><tr><th>IP Address</th><th>Risk Score</th>"
        "<th>Reputation</th><th>Threats</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table>"
    )


def _threat_rows(threats: List[Dict]) -> str:
    rows = []
    for threat in threats:
        severity = _threat_severity(threat)
        badge = badge_for(severity)
        rows.append(
            f"<tr>"
            f'<td class="mono">{html.escape(str(threat.get("timestamp") or "-"))}</td>'
            f'<td class="ip">{html.escape(str(threat.get("ip") or "-"))}</td>'
            f"<td>{html.escape(title_for(threat.get('type')))}</td>"
            f'<td><span class="badge {badge}">{severity}</span></td>'
            f"<td>{int(threat.get('risk_score') or 0)}</td>"
            f"<td>{html.escape(str(threat.get('details') or ''))}</td>"
            f"</tr>"
        )
    if not rows:
        return '<div class="empty">&#10003; No threats detected in the analyzed logs.</div>'
    return (
        "<table><thead><tr><th>Timestamp</th><th>IP</th><th>Threat</th>"
        "<th>Severity</th><th>Risk</th><th>Details</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def generate_html_report(
    summary_data: Dict, threats: List[Dict], output_filepath: str
) -> str:
    """Render a standalone executive HTML report and return its path."""
    path = Path(output_filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = dict(summary_data or {})
    threats = list(threats or [])

    generated = summary.get("generated_at") or datetime.now().isoformat(
        sep=" ", timespec="seconds"
    )
    parts = [
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Cybersecurity Log Analysis - Executive Report</title>",
        f"<style>{CSS}</style></head><body><div class=\"wrap\">",
        '<header class="top"><div><h1>Cybersecurity Log Analysis</h1>'
        '<div class="muted" style="color:#94a3b8;font-size:13px">'
        "Executive threat report</div></div>"
        f'<div class="meta">Generated: {html.escape(str(generated))}<br>'
        f"Threats analyzed: {len(threats)}</div></header>",
        _cards_html(summary),
        "<section><h2>Threat Severity Distribution</h2>",
        _severity_section(summary, threats),
        "</section>",
        "<section><h2>Threat Type Breakdown</h2>",
        _type_section(summary, threats),
        "</section>",
        "<section><h2>Top Risk IPs (0-100 reputation)</h2>",
        _risk_ips_section(summary),
        "</section>",
        "<section><h2>Alert Details</h2>",
        _threat_rows(threats),
        "</section>",
        '<footer>THREAT-NEXUS &middot; generated by report_generator.py'
        "</footer>",
        "</div></body></html>",
    ]
    path.write_text("".join(parts), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------- #
# JSON report
# --------------------------------------------------------------------------- #
def generate_json_report(
    summary_data: Dict, threats: List[Dict], output_filepath: str
) -> str:
    """Export the analysis as formatted JSON and return the file path."""
    path = Path(output_filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = dict(summary_data or {})
    threats = list(threats or [])

    normalized_threats = []
    for threat in threats:
        severity = _threat_severity(threat)
        normalized_threats.append(
            {
                "type": threat.get("type"),
                "ip": threat.get("ip"),
                "severity": severity,
                "badge": badge_for(severity),
                "title": title_for(threat.get("type")),
                "details": threat.get("details"),
                "timestamp": threat.get("timestamp"),
                "risk_score": int(threat.get("risk_score") or 0),
                "occurrences": int(threat.get("occurrences") or 1),
            }
        )

    payload = {
        "report": {
            "title": "Cybersecurity Log Analysis - Executive Report",
            "format": "json",
            "generated_at": summary.get("generated_at")
            or datetime.now().isoformat(sep=" ", timespec="seconds"),
        },
        "summary": {
            "total_events": int(summary.get("total_events", 0)),
            "total_threats": int(summary.get("total_threats", len(threats))),
            "critical_threats": int(summary.get("critical_threats", 0)),
            "unique_ips": int(summary.get("unique_ips", 0)),
        },
        "statistics": {
            "severity_distribution": summary.get("severity_counts")
            or severity_counts(threats),
            "threat_types": summary.get("threat_types") or _type_counts(threats),
            "top_risk_ips": summary.get("top_risk_ips") or _top_risk_ips(threats),
            "badge_colors": BADGE_COLORS,
        },
        "threats": normalized_threats,
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return str(path)


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #
def generate_report(
    summary_data: Dict,
    threats: List[Dict],
    output_dir: str = "reports",
    fmt: str = "html",
    basename: Optional[str] = None,
) -> str:
    """Generate an ``html`` or ``json`` report inside ``output_dir``."""
    fmt = (fmt or "html").lower()
    if fmt not in {"html", "json"}:
        raise ValueError(f"Unsupported report format: {fmt!r}")
    stamp = basename or datetime.now().strftime("report_%Y%m%d_%H%M%S")
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    filepath = target / f"{stamp}.{fmt}"
    if fmt == "html":
        return generate_html_report(summary_data, threats, str(filepath))
    return generate_json_report(summary_data, threats, str(filepath))
