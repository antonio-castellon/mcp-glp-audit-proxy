"""Offline licence checks. Nothing here opens a socket.

Three file shapes are accepted.

* JSON. An Ed25519 signature over the RFC 8785 bytes of the object with the
  ``signature`` field removed. The trust anchor is ``LICENCE_PUBLIC_KEY``.
* LM1 text. Three lines: ``LM1``, base64 of the JSON body, and base64 of an
  RSA-2048 PSS signature over those raw body bytes. The body is
  ``json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False)``
  encoded as UTF-8. PSS uses MGF1 with SHA-256 and a salt length equal to the
  SHA-256 digest. The trust anchor is the PEM SubjectPublicKeyInfo in
  ``LICENCE_RSA_PUBLIC_PEM``. The signature is checked against the raw body
  bytes. This module does not re-encode that JSON.
* LM2 text. Three lines: ``LM2``, base64 of the raw JSON body, and base64 of
  a 64-byte Ed25519 signature over those body bytes. The public key is 32
  raw bytes. ``LICENCE_LM2_PUBLIC_KEY`` is an empty placeholder and fails
  closed until it is replaced. The signature is checked against the decoded
  body bytes. Those bytes must also equal
  ``json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False)``
  encoded as UTF-8. Any other text that starts with ``LM`` is rejected.

Each shape carries a fingerprint. It is the lowercase SHA-256 hex of the RFC
8785 bytes of ``[client_id, app, sorted licensed entry-point names]``. The app
id is ``mcp-glp-audit-proxy``. There is no machine id in that array.

TEST TRUST ANCHORS. Replace ``LICENCE_PUBLIC_KEY`` and ``LICENCE_RSA_PUBLIC_PEM``
before issuing customer licences. Replace ``LICENCE_LM2_PUBLIC_KEY`` before
issuing LM2 licences. The private keys are not in this repository.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
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
# Empty until the production LM2 public key is installed. Fails closed.
LICENCE_LM2_PUBLIC_KEY = b""
LICENCE_KEY_ID = "mcp-glp-audit-proxy-licence"
LICENCE_APP = "mcp-glp-audit-proxy"
LICENCE_KINDS = frozenset({"trial", "year", "perpetual"})
_LM1_FIELDS = frozenset(
    {
        "app",
        "expires",
        "fingerprint",
        "holder",
        "issued",
        "kind",
        "updates_until",
        "version",
    }
)
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_LM2_FIELDS = _LM1_FIELDS | {"alg"}
_LM2_FEATURE = re.compile(r"^[a-z][a-z0-9._-]{0,47}$")
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
    """A verified licence body. ``fingerprint`` is None when the file is not bound.

    ``grant_installed`` is set for LM1, and for LM2 when ``features`` is
    absent. A matching fingerprint then enables the ``licence_feature`` of
    each installed licensed plugin. LM2 with a ``features`` list enables
    only that list.
    """

    features: list[str]
    fingerprint: str | None
    expires_at: datetime | date | None
    grant_installed: bool = False


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

    The signature is over the raw body bytes. Those bytes are not re-encoded.
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


def assert_not_expired(moment: datetime | date | None, *, now: datetime | None) -> None:
    if moment is None:
        return
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    if isinstance(moment, datetime):
        if current >= moment:
            raise LicenceError("licence expired")
        return
    if current.date() > moment:
        raise LicenceError("licence expired")


def parse_iso_date(value: Any, *, label: str) -> date:
    """Parse ``YYYY-MM-DD``. The clock comparison is done by the caller."""
    if not isinstance(value, str) or not _ISO_DATE.fullmatch(value):
        raise LicenceError(f"licence {label} must be an ISO date")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise LicenceError(f"licence {label} must be an ISO date") from exc


def lm1_body(raw: dict[str, Any]) -> LicenceBody:
    """Read an issuer LM1 object. It has no feature list and no ``expiry`` field."""
    if set(raw) != _LM1_FIELDS:
        raise LicenceError("licence LM1 fields do not match the issuer")
    if raw.get("app") != LICENCE_APP:
        raise LicenceError("licence app must be mcp-glp-audit-proxy")
    fingerprint = raw.get("fingerprint")
    if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
        raise LicenceError("licence fingerprint is invalid")
    if raw.get("kind") not in LICENCE_KINDS:
        raise LicenceError("licence kind must be trial, year or perpetual")
    holder = raw.get("holder")
    if not isinstance(holder, str) or not _EMAIL.fullmatch(holder):
        raise LicenceError("licence holder must be an email")
    parse_iso_date(raw.get("issued"), label="issued")
    parse_iso_date(raw.get("updates_until"), label="updates_until")
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, (int, str)) or version == "":
        raise LicenceError("licence version is required")
    expires = raw.get("expires")
    expires_on = None if expires is None else parse_iso_date(expires, label="expires")
    return LicenceBody(
        features=[],
        fingerprint=fingerprint,
        expires_at=expires_on,
        grant_installed=True,
    )


def verify_lm2(text: str, *, public_key: bytes | None = None) -> dict[str, Any]:
    """Verify an LM2 file and return its JSON body.

    The signature covers the decoded body bytes. Those bytes must also be
    the compact sorted JSON encoding of the parsed object.
    """
    if not text.endswith("\n"):
        raise LicenceError("licence LM2 text must be three lines")
    lines = text.split("\n")
    if len(lines) != 4 or lines[0] != "LM2" or lines[3] != "":
        raise LicenceError("licence LM2 text must be three lines")
    body = _b64_line(lines[1], "licence LM2 body must be base64")
    signature = _b64_line(lines[2], "licence LM2 signature must be base64")
    if len(signature) != 64:
        raise LicenceError("licence signature is invalid")
    key_bytes = LICENCE_LM2_PUBLIC_KEY if public_key is None else public_key
    if not isinstance(key_bytes, (bytes, bytearray)) or len(key_bytes) != 32:
        raise LicenceError("licence trust anchor is not an Ed25519 public key")
    try:
        Ed25519PublicKey.from_public_bytes(bytes(key_bytes)).verify(signature, body)
    except (InvalidSignature, ValueError) as exc:
        raise LicenceError("licence signature is invalid") from exc
    try:
        parsed = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LicenceError("licence LM2 body must be JSON") from exc
    if not isinstance(parsed, dict):
        raise LicenceError("licence LM2 body must be a JSON object")
    canonical = json.dumps(
        parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if body != canonical:
        raise LicenceError("licence LM2 body is not canonical")
    return parsed


def lm2_body(raw: dict[str, Any]) -> LicenceBody:
    """Read an LM2 object. ``features``, when present, is the enabled list."""
    if not _LM2_FIELDS <= set(raw) <= (_LM2_FIELDS | {"features"}):
        raise LicenceError("licence LM2 fields do not match the issuer")
    if raw.get("alg") != "ed25519":
        raise LicenceError("licence alg must be ed25519")
    if raw.get("app") != LICENCE_APP:
        raise LicenceError("licence app must be mcp-glp-audit-proxy")
    fingerprint = raw.get("fingerprint")
    if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
        raise LicenceError("licence fingerprint is invalid")
    if raw.get("kind") not in LICENCE_KINDS:
        raise LicenceError("licence kind must be trial, year or perpetual")
    holder = raw.get("holder")
    if not isinstance(holder, str) or not _EMAIL.fullmatch(holder):
        raise LicenceError("licence holder must be an email")
    parse_iso_date(raw.get("issued"), label="issued")
    parse_iso_date(raw.get("updates_until"), label="updates_until")
    version = raw.get("version")
    if isinstance(version, bool) or not isinstance(version, (int, str)) or version == "":
        raise LicenceError("licence version is required")
    expires = raw.get("expires")
    expires_on = None if expires is None else parse_iso_date(expires, label="expires")
    if "features" not in raw:
        return LicenceBody(
            features=[],
            fingerprint=fingerprint,
            expires_at=expires_on,
            grant_installed=True,
        )
    features = raw.get("features")
    if not isinstance(features, list) or not features:
        raise LicenceError("licence features must be a non-empty list")
    if len(features) > 64:
        raise LicenceError("licence features must be at most 64")
    if not all(isinstance(item, str) and _LM2_FEATURE.fullmatch(item) for item in features):
        raise LicenceError("licence feature name is invalid")
    return LicenceBody(
        features=sorted(set(features)),
        fingerprint=fingerprint,
        expires_at=expires_on,
        grant_installed=False,
    )
