"""SSH decoy listener - the port-2222 trap, opt-in.

A deliberately boring TCP listener: it accepts a connection, records a
CRITICAL ``HONEYPOT_HIT`` for the source address and closes the socket.
It never speaks the SSH protocol, never authenticates anything and
never executes commands - there is nothing to exploit, only signal to
record.

Safety / operability:

* **Off by default.** Enabled only when ``SSH_DECOY_ENABLED`` is
  ``1/true/yes/on``; port ``SSH_DECOY_PORT`` (default 2222), bind host
  ``SSH_DECOY_HOST`` (default 0.0.0.0 - exposure is intentional on an
  explicitly enabled trap).
* Bind failures log a warning and leave the platform running.
* ``SSHDecoyServer.stop()`` is idempotent and is registered with
  ``atexit`` by the app factory.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
from typing import Callable, Optional

log = logging.getLogger(__name__)

DEFAULT_PORT = 2222
DEFAULT_HOST = "0.0.0.0"

_ENV_TRUE = {"1", "true", "yes", "on"}


def env_enabled(name: str = "SSH_DECOY_ENABLED") -> bool:
    return str(os.environ.get(name, "")).strip().lower() in _ENV_TRUE


def env_port() -> int:
    try:
        return int(os.environ.get("SSH_DECOY_PORT", DEFAULT_PORT))
    except (TypeError, ValueError):
        return DEFAULT_PORT


def env_host() -> str:
    return os.environ.get("SSH_DECOY_HOST") or DEFAULT_HOST


class SSHDecoyServer:
    """Threaded accept-loop that records connections via ``on_hit``."""

    def __init__(self, host: str, port: int,
                 on_hit: Callable[[str, int], None]) -> None:
        self._host = host
        self._requested_port = port
        self._on_hit = on_hit
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.port: int = port

    def start(self) -> "SSHDecoyServer":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._host, self._requested_port))
        sock.listen(16)
        sock.settimeout(0.5)
        self._sock = sock
        self.port = sock.getsockname()[1]
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name=f"ssh-decoy-{self.port}", daemon=True
        )
        self._thread.start()
        log.info("SSH decoy listening on %s:%s", self._host, self.port)
        return self

    def _run(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # socket closed during shutdown
            try:
                conn.close()  # never speak SSH, never read a byte of payload
                try:
                    self._on_hit(addr[0], self.port)
                except Exception:  # noqa: BLE001 - recording must not kill the loop
                    log.exception("SSH decoy hit handler failed")
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None


def start_from_env(on_hit: Callable[[str, int], None]) -> Optional[SSHDecoyServer]:
    """Start the listener when enabled via env; ``None`` when disabled."""
    if not env_enabled():
        return None
    server = SSHDecoyServer(env_host(), env_port(), on_hit)
    try:
        return server.start()
    except OSError as exc:
        log.warning("SSH decoy not started (%s)", exc)
        return None
