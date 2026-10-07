"""Rule-based Copilot: explains alerts and RECOMMENDS remediation.

It never executes anything. Commands are returned as text for human review.
"""
import ipaddress

PLACEHOLDER = "<SOURCE_IP>"

TEMPLATES = {
    "SSH_BRUTE_FORCE": {
        "explanation": "{ip} made many failed SSH logins in a short time. "
                       "This looks like password guessing.",
        "remediation": [
            "sudo ufw deny from {ip}",
            "sudo fail2ban-client set sshd banip {ip}",
            "Disable password login and use SSH keys.",
        ],
    },
    "SSH_BRUTE_FORCE_SUCCESS": {
        "explanation": "{ip} logged in successfully right after many failed "
                       "attempts. The account may be compromised.",
        "remediation": [
            "sudo ufw deny from {ip}",
            "sudo ss -tnp | grep {ip}",
            "Reset the password of the account that was accessed.",
            "Review the account's recent activity for unauthorized changes.",
        ],
    },
    "SQL_INJECTION": {
        "explanation": "A request from {ip} contained SQL code meant to "
                       "manipulate the database.",
        "remediation": [
            "sudo ufw deny from {ip}",
            "Use parameterized queries and validate all user input.",
            "Check web server logs for other requests from {ip}.",
        ],
    },
    "XSS_ATTEMPT": {
        "explanation": "A request from {ip} contained script code meant to "
                       "run in other users' browsers (XSS).",
        "remediation": [
            "sudo ufw deny from {ip}",
            "Escape and sanitize all user input before showing it.",
            "Add a Content-Security-Policy header.",
        ],
    },
    "DIRECTORY_TRAVERSAL": {
        "explanation": "A request from {ip} tried to read files outside the "
                       "web folder using ../ paths.",
        "remediation": [
            "sudo ufw deny from {ip}",
            "Reject any file path containing '..' and use an allow-list of files.",
            "Check that the web server user cannot read system files.",
        ],
    },
    "TRAFFIC_SPIKE": {
        "explanation": "{ip} sent an unusually high number of requests in one "
                       "minute. It may be trying to overload the service.",
        "remediation": [
            "sudo ufw limit from {ip}",
            "sudo ufw deny from {ip}",
            "Enable rate limiting on the web server.",
        ],
    },
    "OFF_HOUR_ADMIN": {
        "explanation": "{ip} accessed admin pages or sensitive accounts during "
                       "off-hours (00:00-05:59).",
        "remediation": [
            "Confirm with the admin team that this access was expected.",
            "sudo last -i | grep {ip}",
            "sudo ufw deny from {ip}",
        ],
    },
    "WEB_DIRECTORY_SCAN": {
        "explanation": "{ip} requested many different URLs quickly. Attackers "
                       "do this to find hidden pages.",
        "remediation": [
            "sudo ufw deny from {ip}",
            "Remove unused pages and admin paths from the public site.",
            "Enable rate limiting on the web server.",
        ],
    },
    "PORT_SCAN": {
        "explanation": "{ip} probed many network ports in a short time to find "
                       "open services.",
        "remediation": [
            "sudo ufw deny from {ip}",
            "sudo ufw status numbered",
            "Close ports that are not needed.",
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
    """Accept only real IPs so nothing can be injected into a command."""
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return PLACEHOLDER


def generate_copilot_output(alert):
    """Return explanation + recommended commands for one alert (never runs them)."""
    template = TEMPLATES.get(alert.get("type"), DEFAULT)
    ip = _safe_ip(alert.get("ip") or alert.get("source_ip"))
    return {
        "explanation": template["explanation"].format(ip=ip),
        "remediation": [step.format(ip=ip) for step in template["remediation"]],
        "auto_applied": False,
    }
