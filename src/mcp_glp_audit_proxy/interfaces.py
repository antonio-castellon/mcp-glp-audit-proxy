"""Plugin contracts. Pro implements these; Community ships one of each."""

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

    def verify(self, payload: bytes, signature: dict[str, Any]) -> bool: ...


class Reporter(Protocol):
    """Renders an export. Community ships JSON and plain text. PDF and CSV are Pro."""

    name: str
    media_type: str

    def render(self, document: dict[str, Any]) -> bytes: ...
