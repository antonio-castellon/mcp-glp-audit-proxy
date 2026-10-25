"""HTTPS identity for the Community edition.

A request is accepted only after mTLS, a static bearer token, or both.
The bearer is read from a mode 0600 file and compared without putting it
in a log line. OIDC and SSO are not implemented. A licensed plugin can
register in ``mcp_glp_audit_proxy.auth``; this module does not call one.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from ..errors import ConfigurationError


def cert_fingerprint(der: bytes) -> str:
    """Lowercase SHA-256 hex of the client certificate DER."""
    return hashlib.sha256(der).hexdigest()


def same_secret(presented: str, expected: str) -> bool:
    """Compare two strings without an early return on the first differing byte."""
    left = hashlib.sha256(presented.encode("utf-8")).digest()
    right = hashlib.sha256(expected.encode("utf-8")).digest()
    return hmac.compare_digest(left, right)


def read_bearer(path: Path) -> str:
    """Return the single-line token. Refuse a file that is not mode 0600."""
    assert_mode_0600(path)
    text = path.read_text(encoding="utf-8")
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text or "\n" in text or "\r" in text:
        raise ConfigurationError("bearer token file must contain one line")
    return text


def assert_mode_0600(path: Path) -> None:
    if not path.is_file():
        raise ConfigurationError(f"bearer token file not found: {path}")
    if os.name == "nt":
        # Windows cannot store a POSIX 0600 mode. The open still does not log the bytes.
        return
    mode = path.stat().st_mode & 0o777
    if mode != 0o600:
        raise ConfigurationError(
            f"bearer token file {path} must be mode 0600 (found {mode:04o})"
        )
