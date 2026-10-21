#!/usr/bin/env python3
"""Tiny stdio MCP server for the hello-world guides.

One read tool, hello(name), and one write tool, save_note(text).
save_note appends a line to hello-notes.txt in the process working directory.
The proxy config names this upstream "lab", so the host sees lab__hello and
lab__save_note. This process speaks initialize (legacy). It does not listen
on a port.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

NOTES = Path("hello-notes.txt")


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        message = json.loads(line)
        response = handle(message)
        if response is None:
            continue
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def handle(message: dict) -> dict | None:
    method = message.get("method")
    if "id" not in message:
        return None
    if method == "initialize":
        version = (message.get("params") or {}).get("protocolVersion")
        return _result(
            message,
            {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "hello-upstream", "version": "0"},
            },
        )
    if method == "tools/list":
        return _result(message, {"tools": [_hello_tool(), _save_tool()]})
    if method == "tools/call":
        return _call(message)
    return _error(message, -32601, "method not found")


def _call(message: dict) -> dict:
    params = message.get("params") or {}
    name = params.get("name")
    arguments = params.get("arguments") or {}
    if name == "hello":
        who = arguments.get("name")
        text = f"Hello, {who}." if isinstance(who, str) and who.strip() else "Hello."
        return _result(message, {"content": [{"type": "text", "text": text}], "isError": False})
    if name == "save_note":
        text = arguments.get("text")
        if not isinstance(text, str) or not text.strip():
            return _result(
                message,
                {"content": [{"type": "text", "text": "text is required"}], "isError": True},
            )
        with NOTES.open("a", encoding="utf-8") as handle:
            handle.write(text.strip() + "\n")
        return _result(
            message,
            {"content": [{"type": "text", "text": f"Saved: {text.strip()}"}], "isError": False},
        )
    return _error(message, -32602, f"unknown tool {name}")


def _hello_tool() -> dict:
    return {
        "name": "hello",
        "description": "Say hello to a person. Read only.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
            "additionalProperties": False,
        },
    }


def _save_tool() -> dict:
    return {
        "name": "save_note",
        "description": "Append one line to hello-notes.txt in the working directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "additionalProperties": False,
        },
    }


def _result(message: dict, payload: dict) -> dict:
    return {"jsonrpc": "2.0", "id": message.get("id"), "result": payload}


def _error(message: dict, code: int, text: str) -> dict:
    return {"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": code, "message": text}}


if __name__ == "__main__":
    main()
