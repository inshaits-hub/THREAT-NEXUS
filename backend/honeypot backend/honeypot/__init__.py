"""ThreatNexus Honeypot Deception Engine.

Decoy endpoints that no legitimate user should ever touch. Any hit on a
decoy route produces a high-confidence CRITICAL alert.
"""

from .honeypot import (
    HONEYPOT_ROUTES,
    Alert,
    AlertStore,
    raise_honeypot_alert,
)

__all__ = [
    "HONEYPOT_ROUTES",
    "Alert",
    "AlertStore",
    "raise_honeypot_alert",
]
