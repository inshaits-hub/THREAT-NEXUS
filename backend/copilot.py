# copilot.py
"""Rule-based Copilot: explains alerts and RECOMMENDS remediation.
It never executes anything. Commands are returned as text for human review."""
import ipaddress

PLACEHOLDER = "<SOURCE_IP>"

TEMPLATES = {
    "brute_force": {
        "explanation": "Multiple failed login attempts came from {ip}. "
                       "This looks like someone guessing passwords.",
        "remediation": [
            "sudo ufw deny from {ip}",
            "sudo fail2ban-client set sshd banip {ip}",
            "Enforce strong passwords and enable key-based SSH login.",
        ],
    },
    "port_scan": {
        "explanation": "{ip} probed many ports in a short time. "
                       "Attackers do this to find open services.",
        "remediation": [
            "sudo ufw deny from {ip}",
            "sudo ufw status numbered",
            "Close any ports that are not needed.",
        ],
    },
    "sql_injection": {
        "explanation": "A request from {ip} contained SQL syntax meant to "
                       "manipulate the database.",
        "remediation": [
            "sudo ufw deny from {ip}",
            "Use parameterized queries and validate all user input.",
            "Review web server logs for other requests from {ip}.",
        ],
    },
    "ddos": {
        "explanation": "Unusually high traffic from {ip} may be trying to "
                       "overwhelm the service.",
        "remediation": [
            "sudo ufw limit from {ip}",
            "sudo ufw deny from {ip}",
            "Enable rate limiting on the web server or load balancer.",
        ],
    },
}

DEFAULT = {
    "explanation": "Suspicious activity was detected from {ip}. "
                   "Manual investigation is recommended.",
    "remediation": [
        "Review logs related to {ip}.",
        "sudo ufw deny from {ip}",
    ],
}


def _safe_ip(ip):
    """Only accept real IPs, so nobody can inject text into a command."""
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return PLACEHOLDER


def generate_copilot_output(alert: dict) -> dict:
    template = TEMPLATES.get(alert.get("type"), DEFAULT)
    ip = _safe_ip(alert.get("source_ip"))
    return {
        "explanation": template["explanation"].format(ip=ip),
        "remediation": [step.format(ip=ip) for step in template["remediation"]],
        "auto_applied": False,  # we only recommend, never modify the firewall
    }
