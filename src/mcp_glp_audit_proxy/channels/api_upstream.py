"""Expose configured HTTPS endpoints as MCP tools (mcp2api and mcp2llm)."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import quote

from ..bodyutil import filter_headers, prepare_body
from ..config import EndpointConfig
from ..errors import UpstreamError
from .https_outbound import HttpsApiClient

_WRITE = frozenset({"POST", "PUT", "PATCH"})


class ApiUpstream:
    """Not a JSON-RPC session. ``kind`` is ``api`` or ``llm`` for the audit record."""

    def __init__(
        self,
        *,
        name: str,
        kind: str,
        url: str,
        ca_file: str | None,
        headers: dict[str, str] | None,
        timeout: float,
        endpoints: list[EndpointConfig],
        body_mode: str,
        redact_paths: list[str] | tuple[str, ...],
        max_body_bytes: int,
    ) -> None:
        self.name = name
        self.kind = kind
        self.protocol_version: str | None = None
        self.session_id: str | None = None
        self.endpoints = {item.tool: item for item in endpoints}
        self.body_mode = body_mode
        self.redact_paths = list(redact_paths)
        self.max_body_bytes = max_body_bytes
        self._client = HttpsApiClient(
            url,
            ca_file=ca_file,
            headers=headers,
            timeout=timeout,
            max_body_bytes=max_body_bytes,
        )
        self.last_http: dict[str, Any] | None = None

    def ensure(self) -> None:
        return None

    def list_tools(self) -> list[dict[str, Any]]:
        listed = []
        for endpoint in self.endpoints.values():
            names = _placeholders(endpoint.path)
            properties = {name: {"type": "string"} for name in names}
            if endpoint.method in _WRITE:
                properties["body"] = {"type": "object"}
            listed.append(
                {
                    "name": endpoint.tool,
                    "description": f"{endpoint.method} {endpoint.path}",
                    "inputSchema": {
                        "type": "object",
                        "properties": properties,
                        "required": names,
                        "additionalProperties": False if endpoint.method not in _WRITE else True,
                    },
                }
            )
        return listed

    def list_resources(self) -> list[dict[str, Any]]:
        return []

    def list_prompts(self) -> list[dict[str, Any]]:
        return []

    def read_resource(self, uri: str, host_meta: dict[str, Any] | None = None) -> dict[str, Any]:
        del uri, host_meta
        raise UpstreamError(f"{self.name}: HTTPS API upstreams have no resources")

    def get_prompt(
        self,
        name: str,
        arguments: dict[str, Any] | None,
        host_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del name, arguments, host_meta
        raise UpstreamError(f"{self.name}: HTTPS API upstreams have no prompts")

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        host_meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del host_meta  # client tokens are not copied onto the upstream request
        endpoint = self.endpoints.get(name)
        if endpoint is None:
            raise UpstreamError(f"{self.name}: unknown endpoint {name}")
        path, body = _request_parts(endpoint, arguments)
        raw = b"" if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        if len(raw) > self.max_body_bytes:
            raise UpstreamError("request body exceeds size limit")
        prepared = prepare_body(raw, mode=self.body_mode, redact_paths=self.redact_paths)
        kept, stripped = filter_headers(dict(self._client.headers))
        started = time.perf_counter()
        status: int | None = None
        try:
            status, _content_type, response_body = self._client.request(endpoint.method, path, raw or None)
        except UpstreamError:
            self.last_http = _http_view(
                endpoint,
                path,
                kept,
                stripped,
                prepared,
                status,
                started,
                self.kind,
            )
            raise
        self.last_http = _http_view(
            endpoint,
            path,
            kept,
            stripped,
            prepared,
            status,
            started,
            self.kind,
        )
        response_hash = prepare_body(response_body, mode="hash_only", redact_paths=())["body_sha256"]
        text = response_body.decode("utf-8", errors="replace")
        client_result: dict[str, Any] = {
            "content": [{"type": "text", "text": text}],
            "isError": status >= 400,
        }
        stored: dict[str, Any] = {"status": status, "response_sha256": response_hash, "kind": self.kind}
        if self.body_mode == "full":
            stored["response_body"] = text
        return {"result": client_result, "_audit_result": stored}

    def close(self) -> None:
        return None


def _http_view(
    endpoint: EndpointConfig,
    path: str,
    headers: dict[str, str],
    stripped: list[str],
    prepared: dict[str, Any],
    status: int | None,
    started: float,
    kind: str,
) -> dict[str, Any]:
    concrete = path.split("?", 1)[0]
    return {
        "body": prepared["body"],
        "body_mode": prepared["body_mode"],
        "body_sha256": prepared["body_sha256"],
        "headers": headers,
        "kind": kind,
        "latency_ms": int((time.perf_counter() - started) * 1000),
        "method": endpoint.method,
        "path": concrete,
        "route": endpoint.path,
        "status": status,
        "stripped_credential_headers": stripped,
    }


def _placeholders(path: str) -> list[str]:
    names: list[str] = []
    for part in path.split("/"):
        if part.startswith("{") and part.endswith("}") and len(part) > 2:
            names.append(part[1:-1])
    return names


def _request_parts(endpoint: EndpointConfig, arguments: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    params: dict[str, str] = {}
    for name in _placeholders(endpoint.path):
        value = arguments.get(name)
        if not isinstance(value, str) or not value:
            raise UpstreamError(f"missing path argument {name}")
        params[name] = value
    path = endpoint.path
    for name, value in params.items():
        path = path.replace("{" + name + "}", quote(value, safe=""))
    if endpoint.method not in _WRITE and endpoint.method != "DELETE":
        return path, None
    body = arguments.get("body")
    if isinstance(body, dict):
        return path, body
    rest = {key: value for key, value in arguments.items() if key not in params}
    return path, rest or None
