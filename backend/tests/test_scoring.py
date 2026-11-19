"""Unit tests for the explainable risk-scoring engine (src/scoring.py)."""

import math
from datetime import datetime, timedelta

import pytest

from src import scoring


def test_frequency_points_scale_and_cap():
    assert scoring.frequency_points(1) == 5
    assert scoring.frequency_points(3) == 15
    assert scoring.frequency_points(8) == 40  # capped: spam cannot dominate
    assert scoring.frequency_points(1000) == 40
    assert scoring.frequency_points(0) == 5  # at least one attempt
    assert scoring.frequency_points("junk") == 5  # defensive default


def test_severity_points_table():
    assert scoring.severity_points("CRITICAL") == 60
    assert scoring.severity_points("critical") == 60
    assert scoring.severity_points("HIGH") == 45
    assert scoring.severity_points("MEDIUM") == 25
    assert scoring.severity_points("LOW") == 10
    assert scoring.severity_points(None) == 10
    assert scoring.severity_points("NOT-A-LEVEL") == 10


def test_compute_score_sums_and_caps_at_100():
    assert scoring.compute_score(attempts=1, severity="LOW") == 15
    assert scoring.compute_score(attempts=2, severity="HIGH") == 55
    # Honeypot bonus alone nearly exhausts the budget -> capped at 100.
    assert scoring.compute_score(attempts=1, severity="CRITICAL",
                                 honeypot=True) == 100
    assert scoring.compute_score(attempts=1000, severity="CRITICAL",
                                 honeypot=True) == 100


def test_decay_is_exponential_and_never_increases():
    assert scoring.decay(100, 0) == 100
    assert scoring.decay(100, 10, lam=0) == 100  # lambda 0 = no decay
    # Half-life: score halves exactly when lambda * hours == ln(2).
    hours = math.log(2) / 0.05
    assert scoring.decay(100, hours) == pytest.approx(50, rel=1e-6)
    assert scoring.decay(100, 48) < scoring.decay(100, 1) < 100
    # A future-dated event (negative age) never gains score.
    assert scoring.decay(50, -5) == 50


def test_hours_since_parses_and_clamps():
    now = datetime(2026, 10, 7, 12, 0, 0)
    stamp = datetime(2026, 10, 7, 10, 0, 0).isoformat()
    assert scoring.hours_since(stamp, now=now) == pytest.approx(2.0)
    assert scoring.hours_since("not-a-time", now=now) == 0.0
    assert scoring.hours_since(None) == 0.0
    # Event after `now` clamps to zero instead of going negative.
    future = datetime(2026, 10, 7, 14, 0, 0).isoformat()
    assert scoring.hours_since(future, now=now) == 0.0


def test_score_factors_are_explainable():
    now = datetime(2026, 10, 7, 12, 0, 0)
    stamp = (now - timedelta(hours=10)).isoformat()
    factors = scoring.score_factors(attempts=3, severity="HIGH",
                                    honeypot=False, timestamp=stamp, now=now)
    assert factors["frequency_points"] == 15
    assert factors["severity_points"] == 45
    assert factors["honeypot_bonus"] == 0
    assert factors["score"] == 60
    assert factors["decay_hours"] == pytest.approx(10.0)
    assert factors["lambda"] == scoring.DEFAULT_LAMBDA
    assert factors["decayed_score"] == pytest.approx(
        60 * math.exp(-0.05 * 10), rel=1e-3
    )
    assert factors["decayed_score"] <= factors["score"]


def test_honeypot_bonus_shows_in_factors():
    factors = scoring.score_factors(attempts=1, severity="CRITICAL",
                                    honeypot=True)
    assert factors["honeypot_bonus"] == scoring.HONEYPOT_BONUS == 80
    assert factors["score"] == 100
    assert factors["decay_hours"] == 0.0  # no timestamp -> no decay
    assert factors["decayed_score"] == 100


def test_honeypot_hits_carry_the_bonus_end_to_end(tmp_path):
    """The stored honeypot threat scores with the +80 deception bonus."""
    from src import database, honeypot
    from src.app import create_app

    app = create_app(db_path=tmp_path / "bonus.db",
                     reports_dir=tmp_path / "reports")
    app.config["TESTING"] = True
    with app.test_client() as client:
        assert client.get("/.env").status_code == 200
    rows = database.get_threats(db_path=str(tmp_path / "bonus.db"))
    hit = [r for r in rows if r["type"] == "HONEYPOT_HIT"][0]
    assert hit["risk_score"] == 100
    factors = scoring.score_factors(
        attempts=hit["attempts"], severity=hit["severity"], honeypot=True,
        timestamp=hit["timestamp"],
    )
    assert factors["honeypot_bonus"] == 80
    assert factors["score"] == 100
