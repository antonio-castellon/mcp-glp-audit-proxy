"""In-process and subprocess fake MCP server for both protocol eras.

Run as a script for a stdio subprocess:

    python tests/fake_upstream_server.py legacy
    python tests/fake_upstream_server.py modern
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any


class FakeUpstreamApp:
    """Tiny MCP server. legacy speaks initialize; modern speaks server/discover."""

    def __init__(self, era: str = "legacy") -> None:
        if era not in {"legacy", "modern"}:
            raise ValueError(era)
        self.era = era
        self.calls: list[dict[str, Any]] = []
        self.initialized = False
        self.discovered = False
        self.session_id = "up-sess" if era == "legacy" else None

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        self.calls.append(message)
        method = message.get("method")
        if self.era == "modern" and method == "initialize":
            return _error(message, -32601, "method not found")
        if self.era == "legacy" and method == "server/discover":
            return _error(message, -32601, "method not found")
        if method == "notifications/initialized":
            self.initialized = True
            return None
        if method == "server/discover":
            self.discovered = True
            return _result(
                message,
                {
                    "resultType": "complete",
                    "supportedVersions": ["2026-07-28"],
                    "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {
                            "name": "fake-excel",
                            "version": "0",
                        }
                    },
                },
            )
        if method == "initialize":
            self.initialized = True
            version = (message.get("params") or {}).get("protocolVersion")
            result: dict[str, Any] = {
                "protocolVersion": version,
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": "fake-excel", "version": "0"},
            }
            if self.session_id:
                result["sessionId"] = self.session_id
            return _result(message, result)
        if method == "tools/list":
            return _result(message, {"tools": _tools()})
        if method == "resources/list":
            return _result(
                message,
                {"resources": [{"uri": "cell://A1", "name": "A1", "description": "cell"}]},
            )
        if method == "prompts/list":
            return _result(
                message,
                {"prompts": [{"name": "review", "description": "review a cell"}]},
            )
        if method == "resources/read":
            return _result(
                message,
                {"contents": [{"uri": "cell://A1", "text": "42"}]},
            )
        if method == "prompts/get":
            return _result(
                message,
                {"messages": [{"role": "user", "content": {"type": "text", "text": "review"}}]},
            )
        if method == "tools/call":
            return self._call(message)
        return _error(message, -32601, "method not found")

    def _call(self, message: dict[str, Any]) -> dict[str, Any]:
        params = message.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        meta = params.get("_meta") or {}
        if name == "boom":
            return _error(message, -32000, "boom")
        if name == "soft_fail":
            return _result(
                message,
                {"content": [{"type": "text", "text": "nope"}], "isError": True},
            )
        if name == "write_cell":
            return _result(
                message,
                {
                    "content": [{"type": "text", "text": "saved"}],
                    "isError": False,
                    "structuredContent": {"saved": True, "value": arguments.get("value")},
                },
            )
        if name == "echo_env":
            lowered = {str(key).lower() for key in meta}
            return _result(
                message,
                {
                    "content": [{"type": "text", "text": "echo"}],
                    "isError": False,
                    "structuredContent": {
                        "explicit_ok": os.environ.get("EXPLICIT_OK"),
                        "has_authorization": "authorization" in lowered,
                        "meta_keys": sorted(meta.keys()),
                        "parent_secret": os.environ.get("GLP_PARENT_SECRET"),
                        "traceparent": meta.get("traceparent"),
                    },
                },
            )
        return _result(
            message,
            {
                "content": [{"type": "text", "text": f"value:{arguments.get('cell', '')}"}],
                "isError": False,
            },
        )


def _tools() -> list[dict[str, Any]]:
    schema = {"type": "object", "additionalProperties": True}
    return [
        {"name": "read_cell", "description": "Read a cell", "inputSchema": schema},
        {"name": "write_cell", "description": "Write a cell", "inputSchema": schema},
        {"name": "boom", "description": "Fail", "inputSchema": schema},
        {"name": "soft_fail", "description": "Tool error", "inputSchema": schema},
        {"name": "echo_env", "description": "Echo meta and env flags", "inputSchema": schema},
    ]


def _result(message: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message.get("id"), "result": payload}


def _error(message: dict[str, Any], code: int, text: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": code, "message": text}}


def main() -> None:
    era = sys.argv[1] if len(sys.argv) > 1 else "legacy"
    app = FakeUpstreamApp(era)
    for line in sys.stdin:
        if not line.strip():
            continue
        message = json.loads(line)
        response = app.handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
