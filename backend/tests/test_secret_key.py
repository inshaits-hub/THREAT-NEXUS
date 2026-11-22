"""SECRET_KEY must be a real value when FLASK_ENV=production."""

import pytest

from src.app import create_app  # pylint: disable=import-error,no-name-in-module


@pytest.mark.parametrize("value", [None, "", "dev-secret", "change-me-in-production"])
def test_production_rejects_insecure_secret(monkeypatch, tmp_path, value):
    """Reject insecure or missing SECRET_KEY values in production."""
    monkeypatch.setenv("FLASK_ENV", "production")
    if value is None:
        monkeypatch.delenv("SECRET_KEY", raising=False)
    else:
        monkeypatch.setenv("SECRET_KEY", value)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(db_path=tmp_path / "t.db", reports_dir=tmp_path / "reports")


def test_production_accepts_real_secret(monkeypatch, tmp_path):
    """Accept a real SECRET_KEY value in production."""
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.setenv("SECRET_KEY", "a-long-random-value-for-tests")
    app = create_app(db_path=tmp_path / "t.db", reports_dir=tmp_path / "reports")
    assert app.config["SECRET_KEY"] == "a-long-random-value-for-tests"


def test_development_keeps_default(monkeypatch, tmp_path):
    """Keep the default SECRET_KEY in development when unset."""
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    app = create_app(db_path=tmp_path / "t.db", reports_dir=tmp_path / "reports")
    assert app.config["SECRET_KEY"] == "dev-secret"
