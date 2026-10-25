"""Request-body hash and optional JSON-path redaction.

``body_mode`` chooses what is stored next to the hash:

- ``hash_only`` stores the SHA-256 and no body bytes
- ``redacted`` stores a JSON copy with the configured paths replaced
- ``full`` stores the plaintext body

The SHA-256 of the raw bytes is always recorded. A non-JSON body cannot be
redacted by a JSON path, so redacted mode stores no plaintext for it.
Binary that is not UTF-8 is hashed and not stored, including in ``full`` mode.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

REDACTED = "***"
BODY_MODES = frozenset({"hash_only", "redacted", "full"})
_CREDENTIAL_MARKERS = (
    "authorization",
    "cookie",
    "token",
    "secret",
    "api-key",
    "apikey",
    "password",
    "passwd",
)


class _NotJson:
    pass


_NOT_JSON = _NotJson()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prepare_value(
    value: Any,
    *,
    mode: str,
    redact_paths: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    """Hash one JSON value and store it the same way ``prepare_body`` stores a body.

    ``hash_only`` stores no value. ``redacted`` stores a JSON copy. ``full`` stores
    the value. The SHA-256 is of the RFC 8785 bytes.
    """
    from .canonical import canonicalize
    from .canonical import sha256_hex as canon_hex

    if mode not in BODY_MODES:
        raise ValueError(f"unknown body_mode {mode!r}")
    digest = canon_hex(canonicalize(value))
    if mode == "hash_only" or value is None:
        stored: Any = None
    elif mode == "full":
        stored = value
    else:
        stored = redact(value, redact_paths)
    return {"sha256": digest, "value": stored, "mode": mode}


def prepare_body(raw: bytes, *, mode: str, redact_paths: list[str] | tuple[str, ...]) -> dict[str, Any]:
    """Return body_sha256, body, and body_mode for one HTTP body."""
    if mode not in BODY_MODES:
        raise ValueError(f"unknown body_mode {mode!r}")
    digest = sha256_hex(raw)
    parsed = _parse_json(raw)
    if mode == "hash_only":
        stored: Any = None
    elif mode == "full":
        stored = parsed if parsed is not _NOT_JSON else _utf8(raw)
    elif parsed is _NOT_JSON:
        stored = None
    else:
        stored = redact(parsed, redact_paths)
    return {"body_sha256": digest, "body": stored, "body_mode": mode}


def is_credential_header(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in _CREDENTIAL_MARKERS)


def filter_headers(headers: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Drop credential headers. Return the kept map and the dropped names.

    Values of dropped headers are discarded. Kept names are stored in lower case.
    """
    kept: dict[str, str] = {}
    stripped: list[str] = []
    for key, value in headers.items():
        if is_credential_header(key):
            stripped.append(key.lower())
            continue
        kept[key.lower()] = value
    return kept, stripped


def redact(value: Any, paths: list[str] | tuple[str, ...]) -> Any:
    cloned = copy.deepcopy(value)
    for path in paths:
        _redact_path(cloned, _tokens(path))
    return cloned


def _parse_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _NOT_JSON


def _utf8(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _tokens(path: str) -> list[str]:
    if not path.startswith("$"):
        raise ValueError(f"redact path must start with $: {path}")
    body = path[1:]
    if body.startswith("."):
        body = body[1:]
    tokens: list[str] = []
    if not body:
        return tokens
    for part in body.split("."):
        if part.endswith("[*]") and part != "[*]":
            tokens.append(part[: -len("[*]")])
            tokens.append("*")
        elif part in {"[*]", "*"}:
            tokens.append("*")
        elif part:
            tokens.append(part)
    return tokens


def _redact_path(node: Any, tokens: list[str]) -> None:
    if not tokens:
        return
    head, rest = tokens[0], tokens[1:]
    if head == "*":
        if isinstance(node, list):
            if not rest:
                for index in range(len(node)):
                    node[index] = REDACTED
            else:
                for item in node:
                    _redact_path(item, rest)
        return
    if not isinstance(node, dict) or head not in node:
        return
    if not rest:
        node[head] = REDACTED
        return
    _redact_path(node[head], rest)
