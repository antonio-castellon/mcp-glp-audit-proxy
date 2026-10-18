"""TLS 1.3 (RFC 9846) for remote upstreams. Cleartext remote URLs are refused."""

from __future__ import annotations

import ssl
from urllib.parse import urlparse

from .errors import TlsRequired


def require_https(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise TlsRequired(
            f"remote transports require TLS 1.3 (https); refused {url!r}"
        )
    return url


def tls13_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context
