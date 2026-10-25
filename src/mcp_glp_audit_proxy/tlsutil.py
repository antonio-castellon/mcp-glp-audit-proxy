"""TLS 1.3 for remote upstreams and the HTTPS listener.

Cleartext URLs are refused. Hostname checks and certificate verification
stay on. There is no argument that turns them off. ``ca_file`` adds one
trust anchor and, when set, is the only trust anchor for that context.
"""

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


def tls13_context(ca_file: str | None = None) -> ssl.SSLContext:
    """Client context. TLS 1.3 only. Verification is always required."""
    if ca_file:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=ca_file)
    else:
        context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context
