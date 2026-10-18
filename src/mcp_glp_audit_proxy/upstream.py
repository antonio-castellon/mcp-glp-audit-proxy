"""Upstream MCP sessions. Speaks legacy initialize and 2026-07-28 server/discover.

Client tokens are never copied onto the upstream request. Each backend uses
only the credentials in its own config. Stdio children inherit the SDK's
small environment allow-list, not the proxy process environment.
"""

from __future__ import annotations

import json
import select
import subprocess
from typing import Any, Protocol
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from mcp.client.stdio import StdioServerParameters, get_default_environment

from . import __version__
from .errors import TlsRequired, UpstreamError
from .tlsutil import require_https, tls13_context

MODERN_VERSION = "2026-07-28"
LEGACY_VERSION = "2025-11-25"
TRACE_KEYS = ("traceparent", "tracestate", "baggage")
SECRET_META = {
    "authorization",
    "token",
    "access_token",
    "api_key",
    "api-key",
    "password",
    "secret",
    "cookie",
}


class Transport(Protocol):
    response_session_id: str | None

    def send(self, message: dict[str, Any], *, session_id: str | None = None) -> None: ...

    def receive(self) -> dict[str, Any]: ...

    def close(self) -> None: ...


def split_meta(meta: dict[str, Any] | None) -> tuple[dict[str, Any], list[str]]:
    """Drop transport credentials. Return the cleaned meta and the removed key names."""
    if not meta:
        return {}, []
    cleaned: dict[str, Any] = {}
    stripped: list[str] = []
    for key, value in meta.items():
        if key.lower() in SECRET_META:
            stripped.append(key)
            continue
        cleaned[key] = value
    return cleaned, stripped


def forward_meta(host_meta: dict[str, Any] | None, *, modern: bool) -> dict[str, Any]:
    """Meta sent upstream: our identity, plus W3C trace keys if the host set them."""
    cleaned, _stripped = split_meta(host_meta)
    forwarded: dict[str, Any] = {}
    if modern:
        forwarded["io.modelcontextprotocol/protocolVersion"] = MODERN_VERSION
        forwarded["io.modelcontextprotocol/clientInfo"] = {
            "name": "mcp-glp-audit-proxy",
            "version": __version__,
        }
        forwarded["io.modelcontextprotocol/clientCapabilities"] = {}
    for key in TRACE_KEYS:
        if key in cleaned:
            forwarded[key] = cleaned[key]
    return forwarded


class StdioTransport:
    """Newline-delimited JSON-RPC over a child process."""

    def __init__(self, params: StdioServerParameters, *, timeout: float = 60.0) -> None:
        env = get_default_environment()
        if params.env:
            env.update(params.env)
        # shell stays off. The command is operator config, not a tool argument.
        self.proc = subprocess.Popen(  # noqa: S603  # nosec B603
            [params.command, *params.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            cwd=params.cwd,
            text=True,
            bufsize=1,
        )
        self.response_session_id: str | None = None
        self._params = params
        self.timeout = timeout

    def send(self, message: dict[str, Any], *, session_id: str | None = None) -> None:
        del session_id  # stdio has no session header
        if self.proc.stdin is None:
            raise UpstreamError("upstream stdin is closed")
        self.proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def receive(self) -> dict[str, Any]:
        if self.proc.stdout is None:
            raise UpstreamError("upstream stdout is closed")
        ready, _, _ = select.select([self.proc.stdout], [], [], self.timeout)
        if not ready:
            raise UpstreamError(f"upstream timed out after {self.timeout}s")
        line = self.proc.stdout.readline()
        if not line:
            raise UpstreamError("upstream closed stdout")
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise UpstreamError(f"upstream sent non-JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise UpstreamError("upstream sent a non-object")
        return parsed

    def close(self) -> None:
        if self.proc.stdin is not None:
            try:
                self.proc.stdin.close()
            except OSError:
                pass
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class HttpsTransport:
    """JSON-RPC POST to an https upstream. TLS 1.3 only. No client-token passthrough."""

    def __init__(self, url: str, headers: dict[str, str] | None = None, timeout: float = 30) -> None:
        self.url = require_https(url)
        # Headers come from this backend's config only. Callers must not pass
        # the MCP client's Authorization value in here.
        self.headers = {str(key): str(value) for key, value in (headers or {}).items()}
        self.timeout = timeout
        self.response_session_id: str | None = None
        self._buffered: dict[str, Any] | None = None

    def send(self, message: dict[str, Any], *, session_id: str | None = None) -> None:
        payload = json.dumps(message).encode("utf-8")
        headers = {
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
        }
        headers.update(self.headers)
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        if urlparse(self.url).scheme != "https":
            raise TlsRequired(f"remote transports require TLS 1.3 (https); refused {self.url!r}")
        request = Request(self.url, data=payload, headers=headers, method="POST")  # noqa: S310  # nosec B310
        try:
            with urlopen(request, context=tls13_context(), timeout=self.timeout) as response:  # noqa: S310  # nosec B310
                self.response_session_id = response.headers.get("Mcp-Session-Id")
                raw = response.read()
        except Exception as exc:  # urllib.error.URLError and friends
            raise UpstreamError(f"https upstream failed: {exc}") from exc
        if not raw:
            self._buffered = {}
            return
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpstreamError(f"https upstream sent non-JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise UpstreamError("https upstream sent a non-object")
        self._buffered = parsed

    def receive(self) -> dict[str, Any]:
        if self._buffered is None:
            raise UpstreamError("https upstream returned nothing")
        buffered = self._buffered
        self._buffered = None
        return buffered

    def close(self) -> None:
        return None


class JsonRpcUpstream:
    def __init__(self, name: str, transport: Transport, protocol: str = "auto") -> None:
        self.name = name
        self.transport = transport
        self.prefer = protocol
        self.protocol_version: str | None = None
        self.session_id: str | None = None
        self._ready = False
        self._next_id = 0

    def ensure(self) -> None:
        if self._ready:
            return
        if self.prefer in {"auto", "modern"}:
            response = self._request(
                "server/discover",
                {"_meta": self._identity_meta()},
            )
            result = response.get("result") if isinstance(response, dict) else None
            if isinstance(result, dict) and (
                "supportedVersions" in result or result.get("resultType") == "complete"
            ):
                self.protocol_version = MODERN_VERSION
                self.session_id = None
                self._ready = True
                return
            if self.prefer == "modern":
                raise UpstreamError(f"{self.name}: modern discovery failed: {response}")
        response = self._request(
            "initialize",
            {
                "protocolVersion": LEGACY_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-glp-audit-proxy", "version": __version__},
            },
        )
        if "error" in response or "result" not in response:
            raise UpstreamError(f"{self.name}: initialize failed: {response}")
        result = response["result"]
        self.protocol_version = str(result.get("protocolVersion") or LEGACY_VERSION)
        if self.protocol_version >= MODERN_VERSION:
            self.session_id = None
        else:
            header = getattr(self.transport, "response_session_id", None)
            body = result.get("sessionId") if isinstance(result, dict) else None
            self.session_id = header or body
        self._notify("notifications/initialized", {})
        self._ready = True

    def list_tools(self) -> list[dict[str, Any]]:
        return self._listed("tools/list", "tools")

    def list_resources(self) -> list[dict[str, Any]]:
        return self._listed("resources/list", "resources")

    def list_prompts(self) -> list[dict[str, Any]]:
        return self._listed("prompts/list", "prompts")

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        host_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.ensure()
        params: dict[str, Any] = {"name": name, "arguments": arguments}
        meta = forward_meta(host_meta, modern=self.protocol_version == MODERN_VERSION)
        if meta:
            params["_meta"] = meta
        return self._request("tools/call", params, session_id=self._header_session())

    def read_resource(self, uri: str, host_meta: dict[str, Any] | None = None) -> dict[str, Any]:
        self.ensure()
        params: dict[str, Any] = {"uri": uri}
        meta = forward_meta(host_meta, modern=self.protocol_version == MODERN_VERSION)
        if meta:
            params["_meta"] = meta
        return self._request("resources/read", params, session_id=self._header_session())

    def get_prompt(
        self,
        name: str,
        arguments: dict[str, Any] | None,
        host_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.ensure()
        params: dict[str, Any] = {"name": name}
        if arguments:
            params["arguments"] = arguments
        meta = forward_meta(host_meta, modern=self.protocol_version == MODERN_VERSION)
        if meta:
            params["_meta"] = meta
        return self._request("prompts/get", params, session_id=self._header_session())

    def close(self) -> None:
        self.transport.close()

    def _listed(self, method: str, key: str) -> list[dict[str, Any]]:
        self.ensure()
        params: dict[str, Any] = {}
        if self.protocol_version == MODERN_VERSION:
            params["_meta"] = self._identity_meta()
        response = self._request(method, params, session_id=self._header_session())
        if "error" in response:
            raise UpstreamError(f"{self.name}: {method} failed: {response['error']}")
        values = (response.get("result") or {}).get(key) or []
        if not isinstance(values, list):
            raise UpstreamError(f"{self.name}: {method} did not return a list")
        return values

    def _header_session(self) -> str | None:
        if self.protocol_version == MODERN_VERSION:
            return None
        return self.session_id

    def _identity_meta(self) -> dict[str, Any]:
        return {
            "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": "mcp-glp-audit-proxy",
                "version": __version__,
            },
        }

    def _request(
        self,
        method: str,
        params: dict[str, Any] | None,
        *,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        self._next_id += 1
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            message["params"] = params
        self.transport.send(message, session_id=session_id)
        return self.transport.receive()

    def _notify(self, method: str, params: dict[str, Any] | None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.transport.send(message, session_id=self._header_session())


