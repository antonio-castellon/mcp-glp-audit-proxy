"""Production licence trust anchors. Nothing here opens a socket.

The only shipped keys are in ``release_trust.json``. Import ``trusted_keys``
from this module. Do not keep a second copy of the file.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .errors import LicenceError

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ED25519_FIELDS = frozenset({"key_id", "algorithm", "public_hex"})
_RSA_FIELDS = frozenset({"key_id", "algorithm", "public_pem"})


@dataclass(frozen=True)
class TrustedKey:
    """One production public key from ``release_trust.json``."""

    key_id: str
    algorithm: str
    public_hex: str | None = None
    public_pem: str | None = None

    def ed25519_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public key."""
        if self.algorithm != "ed25519" or self.public_hex is None:
            raise LicenceError("licence trust anchor is not an Ed25519 public key")
        return bytes.fromhex(self.public_hex)

    def rsa_pem_bytes(self) -> bytes:
        """ASCII PEM of an RSA-2048 SubjectPublicKeyInfo."""
        if self.algorithm != "rsa-pss-sha256" or self.public_pem is None:
            raise LicenceError("licence trust anchor is not an RSA-2048 public key")
        return self.public_pem.encode("ascii")


def trusted_keys() -> tuple[TrustedKey, ...]:
    """Return every production trust anchor shipped in this package.

    The file is read on each call. A missing or malformed file raises
    ``LicenceError`` and no key is trusted.
    """
    try:
        text = files("mcp_glp_audit_proxy").joinpath("release_trust.json").read_text(encoding="utf-8")
    except (OSError, UnicodeError, FileNotFoundError) as exc:
        raise LicenceError("licence trust file is missing or malformed") from exc
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LicenceError("licence trust file is missing or malformed") from exc
    return _keys_from_document(document)


def trusted_key(key_id: str) -> TrustedKey:
    """Return the production key with this ``key_id``."""
    for key in trusted_keys():
        if key.key_id == key_id:
            return key
    raise LicenceError(f"licence trust anchor {key_id} is not in the trust file")


def _keys_from_document(document: object) -> tuple[TrustedKey, ...]:
    if not isinstance(document, dict) or set(document) != {"keys"}:
        raise LicenceError("licence trust file is missing or malformed")
    rows = document.get("keys")
    if not isinstance(rows, list) or not rows:
        raise LicenceError("licence trust file is missing or malformed")
    parsed: list[TrustedKey] = []
    seen: set[str] = set()
    for row in rows:
        key = _one_key(row)
        if key.key_id in seen:
            raise LicenceError("licence trust file is missing or malformed")
        seen.add(key.key_id)
        parsed.append(key)
    return tuple(parsed)


def _one_key(row: object) -> TrustedKey:
    if not isinstance(row, dict):
        raise LicenceError("licence trust file is missing or malformed")
    key_id = row.get("key_id")
    algorithm = row.get("algorithm")
    if not isinstance(key_id, str) or not key_id or not isinstance(algorithm, str):
        raise LicenceError("licence trust file is missing or malformed")
    if algorithm == "ed25519":
        if set(row) != _ED25519_FIELDS:
            raise LicenceError("licence trust file is missing or malformed")
        public_hex = row.get("public_hex")
        if not isinstance(public_hex, str) or not _HEX64.fullmatch(public_hex):
            raise LicenceError("licence trust file is missing or malformed")
        raw = bytes.fromhex(public_hex)
        try:
            Ed25519PublicKey.from_public_bytes(raw)
        except ValueError as exc:
            raise LicenceError("licence trust file is missing or malformed") from exc
        return TrustedKey(key_id=key_id, algorithm=algorithm, public_hex=public_hex)
    if algorithm == "rsa-pss-sha256":
        if set(row) != _RSA_FIELDS:
            raise LicenceError("licence trust file is missing or malformed")
        public_pem = row.get("public_pem")
        if not isinstance(public_pem, str) or not public_pem.strip():
            raise LicenceError("licence trust file is missing or malformed")
        try:
            loaded = load_pem_public_key(public_pem.encode("ascii"))
        except (UnicodeEncodeError, ValueError, TypeError) as exc:
            raise LicenceError("licence trust file is missing or malformed") from exc
        if not isinstance(loaded, RSAPublicKey) or loaded.key_size != 2048:
            raise LicenceError("licence trust file is missing or malformed")
        return TrustedKey(key_id=key_id, algorithm=algorithm, public_pem=public_pem)
    raise LicenceError("licence trust file is missing or malformed")
