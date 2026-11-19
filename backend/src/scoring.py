"""Core Module 6 - Explainable risk scoring with time decay.

ThreatNexus does not just say "this IP is bad": every threat gets an
interpretable 0-100 number assembled from named, individually visible
factors::

    score = min(100, frequency_points + severity_points + honeypot_bonus)
    decayed_score = score * exp(-lambda * hours_since_last_event)

* **frequency** - repeated attempts raise the score (capped).
* **severity** - LOW/MEDIUM/HIGH/CRITICAL payload severity.
* **honeypot bonus** - a deception hit is a high-confidence signal (+80).
* **time decay (lambda)** - old activity gradually loses influence.

The module is pure Python: no Flask, no database, no I/O. ``lambda`` is a
parameter of every call so tests stay deterministic; the app layer reads
``RISK_DECAY_LAMBDA`` from the environment when it needs a custom value.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Optional

try:  # package import
    from .log_parser import parse_timestamp
except ImportError:  # script import (``python src/main.py``)
    from log_parser import parse_timestamp

__all__ = [
    "SEVERITY_POINTS",
    "HONEYPOT_BONUS",
    "DEFAULT_LAMBDA",
    "frequency_points",
    "severity_points",
    "compute_score",
    "decay",
    "hours_since",
    "score_factors",
]

#: Points contributed by each canonical severity level.
SEVERITY_POINTS = {"LOW": 10, "MEDIUM": 25, "HIGH": 45, "CRITICAL": 60}

#: A honeypot interaction is a deliberately unreachable decoy being touched:
#: the strongest single signal the platform has.
HONEYPOT_BONUS = 80

#: Decay rate per hour. 0.05 ≈ 14 h half-life: yesterday's activity still
#: counts, last week's barely does. Overridable via RISK_DECAY_LAMBDA.
DEFAULT_LAMBDA = 0.05

#: Frequency points are earned per attempt and capped so spam cannot
#: dominate severity on its own.
MAX_FREQUENCY_POINTS = 40
POINTS_PER_ATTEMPT = 5


def frequency_points(attempts) -> int:
    """Points from repetition: ``5 × attempts``, capped at 40."""
    try:
        count = max(1, int(attempts or 1))
    except (TypeError, ValueError):
        count = 1
    return min(MAX_FREQUENCY_POINTS, POINTS_PER_ATTEMPT * count)


def severity_points(severity) -> int:
    """Points for a canonical severity (unknown/missing → LOW)."""
    key = str(severity or "LOW").strip().upper()
    return SEVERITY_POINTS.get(key, SEVERITY_POINTS["LOW"])


def compute_score(attempts=1, severity="LOW", honeypot: bool = False) -> int:
    """Raw explainable score: ``min(100, frequency + severity + bonus)``."""
    score = frequency_points(attempts) + severity_points(severity)
    if honeypot:
        score += HONEYPOT_BONUS
    return max(0, min(100, score))


def decay(score: float, hours: float, lam: float = DEFAULT_LAMBDA) -> float:
    """``score × e^(−λ·hours)`` — monotonic, untouched at ``hours == 0``.

    Negative ages (events dated in the future) are treated as 0 so the
    decay can never *increase* a score.
    """
    age = max(0.0, float(hours))
    lam = max(0.0, float(lam))
    return float(score) * math.exp(-lam * age)


def hours_since(timestamp, now: Optional[datetime] = None) -> float:
    """Hours between an event timestamp and now (0.0 when unparseable)."""
    moment = parse_timestamp(timestamp)
    if moment is None:
        return 0.0
    reference = now or datetime.now(timezone.utc).replace(tzinfo=None)
    if isinstance(reference, datetime) and reference.tzinfo is not None:
        reference = reference.astimezone(timezone.utc).replace(tzinfo=None)
    return max(0.0, (reference - moment).total_seconds() / 3600.0)


def score_factors(
    attempts=1,
    severity="LOW",
    honeypot: bool = False,
    timestamp=None,
    lam: float = DEFAULT_LAMBDA,
    now: Optional[datetime] = None,
) -> dict:
    """Full breakdown behind a threat's score — the explainable number.

    Returns raw points, the capped score, the decay inputs and the
    final ``decayed_score`` so dashboards can show *why* a score is what
    it is.
    """
    hours = hours_since(timestamp, now=now) if timestamp is not None else 0.0
    raw = compute_score(attempts=attempts, severity=severity, honeypot=honeypot)
    return {
        "frequency_points": frequency_points(attempts),
        "severity_points": severity_points(severity),
        "honeypot_bonus": HONEYPOT_BONUS if honeypot else 0,
        "score": raw,
        "decay_hours": round(hours, 4),
        "lambda": float(lam),
        "decayed_score": round(decay(raw, hours, lam), 1),
    }
