"""RFC 8785 canonical JSON and the SHA-256 entry hash.

The rfc8785 package is pinned in pyproject.toml. Hashes are over the canonical
bytes of the entry with entry_hash removed, so another language can recompute
them from schema/jcs-test-vectors.json and the audit-record schema.
"""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785

HASH_ALGO = "sha-256"
CANON = "rfc8785"
GENESIS = "0" * 64
# New records use 1.2.0. 1.0.0 and 1.1.0 lines stay valid in the same chain.
# 1.1.0 adds record status "reviewed" and approval.status "reviewed".
# 1.2.0 adds transport, channel, flow, and the http object.
SCHEMA_VERSION = "1.2.0"
ACCEPTED_SCHEMA_VERSIONS = frozenset({"1.0.0", "1.1.0", "1.2.0"})


def canonicalize(value: Any) -> bytes:
    return rfc8785.dumps(value)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seal(entry: dict[str, Any], prev_hash: str) -> dict[str, Any]:
    """Return a copy of entry with prev_hash and entry_hash filled in."""
    body = dict(entry)
    body.pop("entry_hash", None)
    body["prev_hash"] = prev_hash
    body["hash_algo"] = HASH_ALGO
    body["canonicalization"] = CANON
    digest = sha256_hex(canonicalize(body))
    body["entry_hash"] = digest
    return body


def args_hash(tool: str, arguments: dict[str, Any]) -> str:
    """Bind an approval to the exact tool call it authorises."""
    payload = {"arguments": arguments, "tool": tool}
    return sha256_hex(canonicalize(payload))
