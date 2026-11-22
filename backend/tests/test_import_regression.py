"""Regression test: alert_manager and copilot must import in any order."""

import importlib


def test_alert_manager_imports_without_circular_error():
    module = importlib.import_module("src.alert_manager")
    assert hasattr(module, "process_alerts")


def test_copilot_imports_without_circular_error():
    module = importlib.import_module("src.copilot")
    assert hasattr(module, "generate_copilot_output")