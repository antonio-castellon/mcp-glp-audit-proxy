"""Host and upstream protocol eras, session ids, and credential handling."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from conftest import call_tool


def _legacy_handshake(proxy, session_id: str | None = "host-sess") -> None:
    params = {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "cursor", "version": "1.2.3"},
    }
    if session_id:
        params["_meta"] = {"mcp.session.id": session_id}
    response = proxy.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params}
    )
    assert response["result"]["protocolVersion"] == "2025-11-25"
    assert proxy.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_legacy_host_and_legacy_upstream_record_session_ids(build) -> None:
    stack = build(era="legacy", protocol="legacy")
    proxy = stack["proxies"]["operator"]
    _legacy_handshake(proxy)
    listed = proxy.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = [item["name"] for item in listed["result"]["tools"]]
    assert "excel__read_cell" in names
    assert "glp_verify_chain" not in names  # operator is not QA
    methods = [item["method"] for item in stack["fake"].calls]
    assert "server/discover" not in methods
    assert "initialize" in methods
    assert methods.count("notifications/initialized") == 1
    response = call_tool(proxy, "excel__read_cell", {"cell": "A1"})
    assert response["result"]["content"][0]["text"].startswith("value:")
    entry = [item for item in stack["store"].read_entries() if item.get("tool") == "excel__read_cell"][-1]
    assert entry["protocol_version"] == "2025-11-25"
    assert entry["session_id"] == "host-sess"
    assert entry["upstream_protocol_version"] == "2025-11-25"
    assert entry["upstream_session_id"] == "up-sess"
    assert entry["client"]["name"] == "cursor"
    assert entry["record_class"] == "access"
    init = [item for item in stack["store"].read_entries() if item["method"] == "initialize"][-1]
    assert init["record_class"] == "technical"
    assert init["session_id"] == "host-sess"


def test_modern_host_has_no_session_and_ignores_a_session_hint(build) -> None:
    stack = build(era="modern", protocol="auto")
    proxy = stack["proxies"]["operator"]
    discovered = proxy.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "grok", "version": "9"},
                    "mcp.session.id": "should-ignore",
                }
            },
        }
    )
    assert discovered["result"]["supportedVersions"] == ["2026-07-28"]
    assert "sessionId" not in discovered["result"]
    meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "grok", "version": "9"},
        "mcp.session.id": "should-ignore",
        "gen_ai.request.model": "grok-4",
        "traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
        "authorization": "Bearer client-secret",
    }
    response = call_tool(proxy, "excel__echo_env", {}, meta)
    body = response["result"]["structuredContent"]
    assert body["has_authorization"] is False
    assert body["traceparent"].startswith("00-")
    entry = [item for item in stack["store"].read_entries() if item.get("tool") == "excel__echo_env"][-1]
    assert entry["protocol_version"] == "2026-07-28"
    assert entry["session_id"] is None
    assert entry["upstream_protocol_version"] == "2026-07-28"
    assert entry["upstream_session_id"] is None
    assert entry["client"]["model_id"] == "grok-4"
    assert entry["traceparent"].startswith("00-")
    assert "authorization" in entry["stripped_credential_fields"]
    blob = json.dumps(entry)
    assert "client-secret" not in blob
    methods = [item["method"] for item in stack["fake"].calls]
    assert "server/discover" in methods
    assert "initialize" not in methods
    discover = [item for item in stack["store"].read_entries() if item["method"] == "server/discover"][-1]
    assert discover["session_id"] is None
    assert discover["record_class"] == "technical"


def test_modern_host_against_legacy_upstream_falls_back(build) -> None:
    stack = build(era="legacy", protocol="auto")
    proxy = stack["proxies"]["operator"]
    meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "claude", "version": "3"},
        "mcp.session.id": "nope",
    }
    response = call_tool(proxy, "excel__read_cell", {"cell": "C3"}, meta)
    assert response["result"]["isError"] is False
    methods = [item["method"] for item in stack["fake"].calls]
    assert "server/discover" in methods
    assert "initialize" in methods
    entry = [item for item in stack["store"].read_entries() if item.get("tool") == "excel__read_cell"][-1]
    assert entry["protocol_version"] == "2026-07-28"
    assert entry["session_id"] is None
    assert entry["upstream_protocol_version"] == "2025-11-25"
    assert entry["upstream_session_id"] == "up-sess"


def test_resources_and_prompts_are_logged(build) -> None:
    stack = build(era="modern", protocol="modern")
    proxy = stack["proxies"]["operator"]
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    listed = proxy.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {"_meta": meta}}
    )
    assert listed["result"]["resources"][0]["uri"] == "excel:cell://A1"
    read = proxy.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": {"uri": "excel:cell://A1", "_meta": meta},
        }
    )
    assert read["result"]["contents"][0]["text"] == "42"
    prompts = proxy.handle(
        {"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {"_meta": meta}}
    )
    assert prompts["result"]["prompts"][0]["name"] == "excel__review"
    got = proxy.handle(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "prompts/get",
            "params": {"name": "excel__review", "_meta": meta},
        }
    )
    assert got["result"]["messages"]
    methods = {entry["method"] for entry in stack["store"].read_entries()}
    assert {"resources/list", "resources/read", "prompts/list", "prompts/get"} <= methods
    qa = stack["proxies"]["qa"].handle(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "resources/read",
            "params": {"uri": "excel:cell://A1", "_meta": meta},
        }
    )
    assert "error" in qa


def test_stdio_subprocess_upstream_does_not_inherit_parent_secrets(tmp_path: Path) -> None:
    script = Path(__file__).resolve().parent / "fake_upstream_server.py"
    from mcp_glp_audit_proxy.config import Principal, Retention, Settings
    from mcp_glp_audit_proxy.policy import Policy
    from mcp_glp_audit_proxy.proxy import AuditProxy
    from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore
    from mcp_glp_audit_proxy.upstream import JsonRpcUpstream, StdioTransport
    from mcp.client.stdio import StdioServerParameters

    os.environ["GLP_PARENT_SECRET"] = "super-secret"
    for era in ("legacy", "modern"):
        protocol = "legacy" if era == "legacy" else "modern"
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(script), era],
            env={"EXPLICIT_OK": "1"},
        )
        upstream = JsonRpcUpstream("excel", StdioTransport(params), protocol)
        try:
            store = JsonlAuditStore(tmp_path / f"{era}.jsonl", checkpoint_every=0)
            settings = Settings(
                principal=Principal(id="operator-1", name="Ada Analyst", role="operator"),
                retention=Retention(),
                policy=Policy(allow=["*"], deny=[], write_tools=[], require_reason_for_writes=False),
                audit_path=store.path,
                export_dir=tmp_path / "exports",
            )
            proxy = AuditProxy(
                settings,
                store,
                [upstream],
                clock_probe=lambda: {"detail": "yes", "ntp_synchronized": True, "source": "test"},
            )
            proxy.startup()
            meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"} if era == "modern" else None
            if era == "legacy":
                _legacy_handshake(proxy, session_id=None)
            response = call_tool(proxy, "excel__echo_env", {}, meta)
            body = response["result"]["structuredContent"]
            assert body["explicit_ok"] == "1"
            assert body["parent_secret"] is None
            assert body["has_authorization"] is False
        finally:
            upstream.close()
            os.environ.pop("GLP_PARENT_SECRET", None)


def test_proxy_stdio_speaks_discover(tmp_path: Path) -> None:
    config = {
        "principal": {"id": "qa-1", "name": "Cara QA", "role": "qa"},
        "retention": {"profile": "swiss_glp", "min_months": 6, "years_after_study": 10},
        "policy": {"allow": [], "deny": [], "write_tools": []},
        "audit": {"path": "audit.jsonl", "fail_closed": True, "checkpoint_every": 0},
        "upstreams": [],
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GLP_"):
            env.pop(key)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "--config", str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=tmp_path,
    )
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "0"},
            }
        },
    }
    assert proc.stdin is not None
    out, err = proc.communicate(json.dumps(message) + "\n", timeout=20)
    assert proc.returncode == 0, err
    response = json.loads(out.strip().splitlines()[0])
    assert response["result"]["supportedVersions"] == ["2026-07-28"]
    assert "client-secret" not in err
