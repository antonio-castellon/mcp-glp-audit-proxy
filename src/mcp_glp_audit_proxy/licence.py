"""Offline licence checks. Nothing here opens a socket.

Two file shapes are accepted.

* JSON. An Ed25519 signature over the RFC 8785 bytes of the object with the
  ``signature`` field removed. The trust anchor is ``LICENCE_PUBLIC_KEY``.
* LM1 text. Three lines: ``LM1``, base64 of the RFC 8785 JSON body, and base64
  of an RSA-2048 PSS signature over those raw body bytes. PSS uses MGF1 with
  SHA-256 and a salt length equal to the SHA-256 digest. The trust anchor is
  the PEM SubjectPublicKeyInfo in ``LICENCE_RSA_PUBLIC_PEM``.

Both shapes carry a fingerprint. It is the lowercase SHA-256 hex of the RFC
8785 bytes of ``[client_id, app, sorted licensed entry-point names]``. The app
id is ``mcp-glp-audit-proxy``. There is no machine id in that array.

TEST TRUST ANCHORS. Replace ``LICENCE_PUBLIC_KEY`` and ``LICENCE_RSA_PUBLIC_PEM``
before issuing customer licences. The private keys are not in this repository.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .canonical import canonicalize, sha256_hex
from .errors import LicenceError

# TEST TRUST ANCHORS. Replace both before issuing customer licences.
# The private keys are not in this repository.
LICENCE_PUBLIC_KEY = bytes.fromhex(
    "8b81069ec1a5f561e2bd0b335c9b32e202e3b02a7c56a0232859c625051759a6"
)
LICENCE_KEY_ID = "mcp-glp-audit-proxy-licence"
LICENCE_APP = "mcp-glp-audit-proxy"
LICENCE_KINDS = frozenset({"30d", "365d", "perpetual"})
LICENCE_RSA_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmbqqoHuPlSeAy1NoMM+P
ciKPVTkHY6Sp6IcCsNSWbtU9a497X7j+rfnK3Zvml4xgVPoYiCiveGwu241kPoxg
iq3/rC/4PgkUIUa5x53pKcaHyF5AyLckyDwlxjyuAJAVu6tqxf1u0VrncWw8IyYV
6XbgZnvczOk4n1IKZ+X3+cCF34DI0kjfh8G/rQO8jq5GnmtUwnVCMIpK/ohrdhak
9pNoiHO3Prnlv0a+rTZGt10Z3NF0dbu3ysSnrLSkT8s8e0JpKDMBbB9oJgkxDR/s
8ARq0DWNaIUllwXlCEu7qxs5WdkvAB2hoxibLO+9CiYMnCKxpzZzC9WR8PU8iUCo
HwIDAQAB
-----END PUBLIC KEY-----
"""


@dataclass(frozen=True)
class LicenceBody:
    """A verified licence body. ``fingerprint`` is None when the file is not bound."""

    features: list[str]
    fingerprint: str | None
    expires_at: datetime | None


def licence_fingerprint(client_id: str, plugin_names: Iterable[str]) -> str:
    """Lowercase SHA-256 hex of ``[client_id, app, sorted names]`` in RFC 8785."""
    if not isinstance(client_id, str) or not client_id:
        raise LicenceError("licence client_id is required")
    names = sorted(set(plugin_names))
    if not all(isinstance(name, str) and name for name in names):
        raise LicenceError("licence fingerprint plugins must be names")
    return sha256_hex(canonicalize([client_id, LICENCE_APP, names]))


def fingerprint_matches(claimed: str, expected: str) -> bool:
    if not isinstance(claimed, str) or len(claimed) != len(expected):
        return False
    return hmac.compare_digest(claimed, expected)


def signed_payload(raw: dict[str, Any]) -> bytes:
    """Canonical bytes covered by an Ed25519 licence signature."""
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


def verify_lm1(text: str, *, public_pem: bytes | None = None) -> dict[str, Any]:
    """Verify an LM1 file and return its JSON body.

    The signature is over the raw body bytes, which must already be RFC 8785.
    """
    if not text.endswith("\n"):
        raise LicenceError("licence LM1 text must be three lines")
    lines = text.split("\n")
    if len(lines) != 4 or lines[0] != "LM1" or lines[3] != "":
        raise LicenceError("licence LM1 text must be three lines")
    body = _b64_line(lines[1], "licence LM1 body must be base64")
    signature = _b64_line(lines[2], "licence LM1 signature must be base64")
    if len(signature) != 256:
        raise LicenceError("licence signature is invalid")
    pem = LICENCE_RSA_PUBLIC_PEM.encode("ascii") if public_pem is None else public_pem
    _verify_rsa_pss(body, signature, pem)
    try:
        parsed = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LicenceError("licence LM1 body must be JSON") from exc
    if not isinstance(parsed, dict):
        raise LicenceError("licence LM1 body must be a JSON object")
    if canonicalize(parsed) != body:
        raise LicenceError("licence LM1 body is not canonical")
    return parsed


def _b64_line(value: str, message: str) -> bytes:
    if not value or value.strip() != value:
        raise LicenceError(message)
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LicenceError(message) from exc


def _verify_rsa_pss(body: bytes, signature: bytes, pem: bytes) -> None:
    if not isinstance(pem, (bytes, bytearray)) or not pem.strip():
        raise LicenceError("licence trust anchor is not an RSA-2048 public key")
    try:
        key = load_pem_public_key(bytes(pem))
    except (ValueError, TypeError) as exc:
        raise LicenceError("licence trust anchor is not an RSA-2048 public key") from exc
    if not isinstance(key, RSAPublicKey) or key.key_size != 2048:
        raise LicenceError("licence trust anchor is not an RSA-2048 public key")
    try:
        key.verify(
            signature,
            body,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise LicenceError("licence signature is invalid") from exc


def parse_expiry(value: Any, *, label: str) -> datetime:
    """Parse an RFC 3339 timestamp. The clock comparison is done by the caller."""
    if not isinstance(value, str) or not value.strip():
        raise LicenceError(f"licence {label} must be an RFC3339 timestamp")
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LicenceError(f"licence {label} must be an RFC3339 timestamp") from exc
    if moment.tzinfo is None:
        raise LicenceError(f"licence {label} must include a time zone")
    return moment


def assert_not_expired(moment: datetime | None, *, now: datetime | None) -> None:
    if moment is None:
        return
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    if current >= moment:
        raise LicenceError("licence expired")


def lm1_body(raw: dict[str, Any]) -> LicenceBody:
    """Read features, fingerprint, kind and expiry from a verified LM1 object."""
    fingerprint = raw.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        raise LicenceError("licence fingerprint is required")
    kind = raw.get("kind")
    if kind not in LICENCE_KINDS:
        raise LicenceError("licence kind must be 30d, 365d or perpetual")
    if "features" not in raw:
        raise LicenceError("licence features must be a list of strings")
    features = _feature_list(raw.get("features"))
    if kind == "perpetual":
        if raw.get("expiry", None) is not None:
            raise LicenceError("perpetual licence has an expiry")
        return LicenceBody(features=features, fingerprint=fingerprint, expires_at=None)
    if "expiry" not in raw or raw.get("expiry") is None:
        raise LicenceError("licence expiry is required")
    return LicenceBody(
        features=features,
        fingerprint=fingerprint,
        expires_at=parse_expiry(raw.get("expiry"), label="expiry"),
    )


def _feature_list(features: Any) -> list[str]:
    if not isinstance(features, list) or not all(isinstance(item, str) for item in features):
        raise LicenceError("licence features must be a list of strings")
    return list(features)
