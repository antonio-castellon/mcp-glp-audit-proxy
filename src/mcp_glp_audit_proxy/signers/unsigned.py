"""Checkpoint signer that records the head without a signature.

Ed25519 and ECDSA P-256 live in the Pro package and register under the
same entry-point group. Keys are never written to the log by this signer
because it has no keys.
"""

from __future__ import annotations

from typing import Any


class UnsignedSigner:
    name = "unsigned"

    def sign(self, payload: bytes) -> dict[str, Any]:
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("checkpoint payload must be bytes")
        return {
            "algorithm": None,
            "key_id": None,
            "label": "unsigned",
            "signed": False,
            "value": None,
        }

    def verify(self, payload: bytes, signature: dict[str, Any]) -> bool:
        # An unsigned checkpoint has no signature to check. Chain hashes are
        # the Community integrity control. A signed checkpoint is verified by
        # the Pro signer that produced it.
        del payload
        return signature.get("signed") is False and signature.get("value") is None
