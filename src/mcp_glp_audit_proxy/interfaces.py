"""Plugin contracts. Pro implements these; Community ships one of each.

Entry points are factories. Selection and the factory signatures are described
in docs/PLUGINS.md. This repository does not ship a Pro implementation.
"""

from __future__ import annotations

from typing import Any, Protocol


class AuditStore(Protocol):
    """Append-only audit storage. Implementations must not offer update or delete."""

    def health(self) -> bool: ...

    def read_entries(self) -> list[dict[str, Any]]: ...

    def append_event(self, event: dict[str, Any]) -> dict[str, Any]: ...


class Signer(Protocol):
    """Checkpoint signer. Community ships an unsigned signer; Pro ships Ed25519 / ECDSA."""

    name: str

    def sign(self, payload: bytes) -> dict[str, Any]: ...

    def verify(
        self,
        payload: bytes,
        signature: dict[str, Any],
        public_key: bytes | None = None,
    ) -> bool:
        """Return true when ``signature`` covers ``payload``.

        ``verify --pubkey`` passes the pinned key as ``public_key``. The
        Community unsigned signer returns false when a key is passed.
        """
        ...


class Reporter(Protocol):
    """Renders an export. Community ships JSON and plain text. PDF and CSV are Pro."""

    name: str
    media_type: str

    def render(self, document: dict[str, Any]) -> bytes: ...


class IdentityProvider(Protocol):
    """Names the principal for this process.

    Community returns the principal the process was already given (environment
    or config). This is not an identity provider. SSO and OAuth are Pro plugins
    in the same entry-point group.
    """

    name: str

    def resolve(self) -> dict[str, str]:
        """Return {"id", "name", "role"}."""
