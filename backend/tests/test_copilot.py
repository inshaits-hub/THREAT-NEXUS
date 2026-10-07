try:
    from src.copilot import generate_copilot_output, TEMPLATES, PLACEHOLDER
except ImportError:
    from copilot import generate_copilot_output, TEMPLATES, PLACEHOLDER


def test_template_exists_for_each_type():
    for attack_type in TEMPLATES:
        out = generate_copilot_output({"type": attack_type, "ip": "10.0.0.5"})
        assert out["explanation"]
        assert out["remediation"]


def test_remediation_has_reviewable_command():
    out = generate_copilot_output({"type": "SSH_BRUTE_FORCE", "ip": "10.0.0.5"})
    assert "sudo ufw deny from 10.0.0.5" in out["remediation"]


def test_never_auto_applies():
    out = generate_copilot_output({"type": "PORT_SCAN", "ip": "10.0.0.5"})
    assert out["auto_applied"] is False


def test_unknown_type_uses_default():
    out = generate_copilot_output({"type": "WEIRD", "ip": "10.0.0.5"})
    assert "10.0.0.5" in out["explanation"]


def test_malicious_ip_is_rejected():
    out = generate_copilot_output({"type": "SSH_BRUTE_FORCE", "ip": "1.1.1.1; rm -rf /"})
    assert all("rm -rf" not in step for step in out["remediation"])
    assert any(PLACEHOLDER in step for step in out["remediation"])
