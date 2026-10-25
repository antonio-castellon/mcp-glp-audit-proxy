"""Optional failed-authentication limit for the HTTPS listener.

Off unless listen.auth_failure_limit is set. The stdio channel does not use it.
A successful authentication does not lift a block that is already running.
"""

from __future__ import annotations

import time
from typing import Any

from .config import AuthFailureLimit


class AuthGate:
    def __init__(self, limit: AuthFailureLimit | None, now: Any = None) -> None:
        self.limit = limit
        self.now = now or time.monotonic
        self.failures: dict[str, list[float]] = {}
        self.block_until: dict[str, float] = {}

    def begin(self, address: str, identity: str) -> str:
        """Return open, blocked, or unblocked (the block just ended)."""
        if self.limit is None:
            return "open"
        moment = float(self.now())
        keys = self._keys(address, identity)
        blocked = False
        expired: list[str] = []
        for key in keys:
            until = self.block_until.get(key)
            if until is None:
                continue
            if moment >= until:
                expired.append(key)
            else:
                blocked = True
        if blocked:
            return "blocked"
        if expired:
            for key in expired:
                self.block_until.pop(key, None)
                self.failures.pop(key, None)
            return "unblocked"
        return "open"

    def fail(self, address: str, identity: str) -> bool:
        """Count one failure. True the first time the limit is reached."""
        if self.limit is None:
            return False
        moment = float(self.now())
        opened = False
        for key in self._keys(address, identity):
            if key in self.block_until and moment < self.block_until[key]:
                continue
            window = self.limit.window_seconds
            stamps = [item for item in self.failures.get(key, []) if moment - item < window]
            stamps.append(moment)
            self.failures[key] = stamps
            if len(stamps) >= self.limit.max_failures and key not in self.block_until:
                self.block_until[key] = moment + self.limit.block_seconds
                opened = True
        return opened

    def success(self, address: str, identity: str) -> None:
        """Clear the failure window. Leave a running block in place."""
        if self.limit is None:
            return
        moment = float(self.now())
        for key in self._keys(address, identity):
            until = self.block_until.get(key)
            if until is not None and moment < until:
                continue
            self.failures.pop(key, None)

    def _keys(self, address: str, identity: str) -> list[str]:
        limit = self.limit
        if limit is None:
            raise RuntimeError("auth limit is not configured")
        mode = limit.key
        if mode == "address":
            return [f"address:{address}"]
        if mode == "identity":
            return [f"identity:{identity}"]
        return [f"both:{address}|{identity}"]
