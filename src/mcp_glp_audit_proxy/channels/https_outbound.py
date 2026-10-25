"""HTTPS client for API and LLM upstreams.

TLS 1.3 only. Certificate verification and hostname checks stay on.
Redirects are not followed, so a redirect cannot leave https.
"""

from __future__ import annotations

import http.client
import ssl
from urllib.parse import urlsplit

from ..errors import TlsRequired, UpstreamError
from ..tlsutil import require_https, tls13_context


class HttpsApiClient:
    """One origin. ``ca_file`` is that upstream's trust anchor when set."""

    def __init__(
        self,
        origin: str,
        *,
        ca_file: str | None,
        headers: dict[str, str] | None,
        timeout: float,
        max_body_bytes: int,
    ) -> None:
        self.origin = require_https(origin).rstrip("/")
        self.ca_file = ca_file
        self.headers = {str(key): str(value) for key, value in (headers or {}).items()}
        self.timeout = timeout
        self.max_body_bytes = max_body_bytes

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None,
    ) -> tuple[int, str, bytes]:
        """Return status, content-type, and at most ``max_body_bytes`` of the body."""
        target = path if path.startswith("/") else "/" + path
        url = self.origin + target
        require_https(url)
        context = tls13_context(self.ca_file)
        _require_verified(context)
        parts = urlsplit(url)
        port = parts.port or 443
        outbound = {"accept": "application/json, text/plain"}
        if body:
            outbound["content-type"] = "application/json"
        outbound.update(self.headers)
        if parts.scheme != "https":
            raise TlsRequired(f"remote transports require TLS 1.3 (https); refused {url!r}")
        connection = http.client.HTTPSConnection(
            parts.hostname or "",
            port,
            context=context,
            timeout=self.timeout,
        )
        try:
            connection.request(method, parts.path + _query(parts.query), body=body or None, headers=outbound)
            response = connection.getresponse()
            raw = response.read(self.max_body_bytes + 1)
            if len(raw) > self.max_body_bytes:
                raise UpstreamError("upstream body exceeds size limit")
            content_type = response.getheader("Content-Type") or "application/octet-stream"
            return response.status, content_type.split(";")[0].strip(), raw
        except UpstreamError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise UpstreamError(f"https upstream failed: {exc.__class__.__name__}") from exc
        finally:
            connection.close()


def _query(query: str) -> str:
    if not query:
        return ""
    return "?" + query


def _require_verified(context: ssl.SSLContext) -> None:
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise TlsRequired("TLS verification cannot be disabled")
    if context.minimum_version != ssl.TLSVersion.TLSv1_3:
        raise TlsRequired("remote transports require TLS 1.3")
