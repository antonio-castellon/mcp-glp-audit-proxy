"""stdio entrypoint. Identity comes from the environment, per the MCP auth spec."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any

from mcp.client.stdio import StdioServerParameters

from .config import Settings, load_settings
from .errors import AuditStoreError, ConfigurationError
from .features import FeatureSet
from .proxy import MAX_MESSAGE_BYTES, AuditProxy
from .sdkcheck import assert_mcp_floor
from .storage.jsonl import JsonlAuditStore
from .upstream import HttpsTransport, JsonRpcUpstream, StdioTransport


def build_proxy(settings: Settings, features: FeatureSet | None = None) -> AuditProxy:
    flags = features or FeatureSet.load(settings.licence_path)
    if "storage.jsonl" not in flags.enabled:
        raise ConfigurationError("Community JSONL storage is not enabled")
    store = JsonlAuditStore(
        settings.audit_path,
        checkpoint_every=settings.checkpoint_every,
        legal_hold=settings.retention.legal_hold,
    )
    upstreams = [_build_upstream(item) for item in settings.upstreams or []]
    return AuditProxy(settings, store, upstreams, features=flags)


def serve_stdio(proxy: AuditProxy) -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )
    try:
        proxy.startup()
    except (ConfigurationError, AuditStoreError) as exc:
        print(f"mcp-glp-audit-proxy: refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    if proxy.features.unavailable:
        print(
            "mcp-glp-audit-proxy: licence requested features with no plugin: "
            + ", ".join(proxy.features.unavailable),
            file=sys.stderr,
        )
    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            if len(line.encode("utf-8")) > MAX_MESSAGE_BYTES:
                response = proxy.reject_oversized_line(len(line.encode("utf-8")))
                if response is not None:
                    _write(response)
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                _write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
                continue
            if not isinstance(message, dict):
                _write({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}})
                continue
            try:
                response = proxy.handle(message)
            except Exception as exc:  # last resort: do not forward, do not die silently
                if proxy.settings.fail_closed:
                    proxy._dead = True
                logging.getLogger("mcp_glp_audit_proxy.technical").exception("proxy handle failed")
                response = {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {
                        "code": -32000,
                        "message": "audit log unavailable; request was not completed",
                        "data": {"detail": str(exc), "reason": "fail_closed"},
                    },
                }
            if response is not None:
                _write(response)
    finally:
        proxy.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="mcp-glp-audit-proxy")
    parser.add_argument(
        "--config",
        default=os.environ.get("GLP_CONFIG", "config.json"),
        help="Path to the JSON config file",
    )
    args = parser.parse_args(argv)
    try:
        assert_mcp_floor()
        settings = load_settings(args.config)
        proxy = build_proxy(settings)
    except (ConfigurationError, OSError, ValueError, RuntimeError) as exc:
        print(f"mcp-glp-audit-proxy: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    serve_stdio(proxy)


def _build_upstream(item: Any) -> JsonRpcUpstream:
    if item.transport == "https":
        if not item.url:
            raise ConfigurationError(f"upstream {item.name}: https transport requires url")
        transport = HttpsTransport(item.url, item.headers)
    else:
        if not item.command:
            raise ConfigurationError(f"upstream {item.name}: stdio transport requires command")
        params = StdioServerParameters(
            command=item.command,
            args=list(item.args or []),
            env=dict(item.env or {}),
            cwd=item.cwd,
        )
        transport = StdioTransport(params)
    return JsonRpcUpstream(item.name, transport, item.protocol)


def _write(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()
