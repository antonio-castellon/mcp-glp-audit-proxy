"""Ed25519 check for an offline licence file.

The signature is over the RFC 8785 bytes of the licence object with the
``signature`` field removed. The public key below is the trust anchor.
The private key is not in this repository. Nothing here opens a socket.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonicalize
from .errors import LicenceError

# Raw 32-byte Ed25519 public key. Replace this constant to rotate the trust anchor.
LICENCE_PUBLIC_KEY = bytes.fromhex(
    "8b81069ec1a5f561e2bd0b335c9b32e202e3b02a7c56a0232859c625051759a6"
)
LICENCE_KEY_ID = "mcp-glp-audit-proxy-licence"


def signed_payload(raw: dict[str, Any]) -> bytes:
    """Canonical bytes covered by the licence signature."""
    body = {key: value for key, value in raw.items() if key != "signature"}
    return canonicalize(body)


def verify_ed25519_licence(raw: dict[str, Any], *, public_key: bytes | None = None) -> None:
    """Raise LicenceError unless ``raw`` carries a valid Ed25519 signature."""
    signature = raw.get("signature", None)
    if not isinstance(signature, dict):
        raise LicenceError("licence signature must be an object")
    if signature.get("algorithm") != "ed25519":
        raise LicenceError("licence signature algorithm must be ed25519")
    value = signature.get("value")
    if not isinstance(value, str) or not value.strip():
        raise LicenceError("licence signature value must be base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LicenceError("licence signature value must be base64") from exc
    if len(decoded) != 64:
        raise LicenceError("licence signature is invalid")
    key_bytes = LICENCE_PUBLIC_KEY if public_key is None else public_key
    if not isinstance(key_bytes, (bytes, bytearray)) or len(key_bytes) != 32:
        raise LicenceError("licence trust anchor is not an Ed25519 public key")
    try:
        Ed25519PublicKey.from_public_bytes(bytes(key_bytes)).verify(decoded, signed_payload(raw))
    except (InvalidSignature, ValueError) as exc:
        raise LicenceError("licence signature is invalid") from exc
