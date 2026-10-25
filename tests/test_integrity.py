"""A broken chain refuses startup and stops the process."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from mcp_glp_audit_proxy.alerts import write_critical_alert
from mcp_glp_audit_proxy.chain import verify_bytes
from mcp_glp_audit_proxy.errors import AuditStoreError
from mcp_glp_audit_proxy.records import SYSTEM_PRINCIPAL, build_event
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore

from conftest import assemble, call_tool

SRC = str(Path(__file__).resolve().parents[1] / "src")


def _fill(path: Path) -> None:
    store = JsonlAuditStore(path, checkpoint_every=0)
    for index in range(3):
        store.append_event(
            build_event(
                method="tools/call",
                record_class="access",
                status="ok",
                server="excel",
                principal=SYSTEM_PRINCIPAL,
                client={"id": "proxy", "name": "proxy", "version": "0"},
                protocol_version=None,
                session_id=None,
                tool="excel__read_cell",
                arguments={"patient": "PATIENT-SECRET-XYZ", "n": index},
                result={"n": index},
            )
        )


def _config(directory: Path, audit: Path, *, fail_closed: bool = True, alert: list[str] | None = None) -> Path:
    path = directory / "config.json"
    audit_block: dict = {"path": str(audit), "fail_closed": fail_closed, "checkpoint_every": 0}
    if alert is not None:
        audit_block["alert_command"] = alert
    path.write_text(
        json.dumps(
            {
                "principal": {"id": "operator-1", "name": "Ada Analyst", "role": "operator"},
                "policy": {"allow": ["*"], "deny": [], "write_tools": []},
                "audit": audit_block,
                "upstreams": [],
            }
        ),
        encoding="utf-8",
    )
    return path


def _start(config: Path) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GLP_"):
            env.pop(key)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "--config", str(config)],
        input=b"",
        capture_output=True,
        env=env,
        check=False,
        timeout=20,
    )


def test_deleted_line_refuses_startup_and_writes_alert(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _fill(audit)
    lines = audit.read_text(encoding="utf-8").splitlines(keepends=True)
    tampered = "".join(lines[:1] + lines[2:]).encode()
    audit.write_bytes(tampered)
    (Path(str(audit) + ".head")).write_bytes((Path(str(audit) + ".head")).read_bytes())
    expect = verify_bytes(tampered)
    assert expect.kind == "missing"
    before = audit.read_bytes()
    completed = _start(_config(tmp_path, audit))
    assert completed.returncode == 3
    assert b"refusing to start" in completed.stderr
    assert audit.read_bytes() == before
    alert = json.loads(Path(str(audit) + ".alert.json").read_text(encoding="utf-8"))
    assert alert["kind"] == "missing"
    assert alert["first_bad_line"] == expect.first_bad_line
    assert alert["last_good_seq"] == expect.last_good_seq
    assert alert["last_good_timestamp"] == expect.last_good_timestamp
    assert "PATIENT-SECRET-XYZ" not in json.dumps(alert)
    if os.name != "nt":
        assert (Path(str(audit) + ".alert.json").stat().st_mode & 0o777) == 0o600


def test_edited_truncated_and_head_mismatch(tmp_path: Path) -> None:
    edited = tmp_path / "edited"
    edited.mkdir()
    audit = edited / "audit.jsonl"
    _fill(audit)
    raw = audit.read_bytes()
    audit.write_bytes(raw.replace(b"PATIENT-SECRET-XYZ", b"PATIENT-SECRET-XYY", 1))
    completed = _start(_config(edited, audit))
    assert completed.returncode == 3
    alert = json.loads(Path(str(audit) + ".alert.json").read_text(encoding="utf-8"))
    assert alert["kind"] == "edited"
    assert "PATIENT-SECRET" not in json.dumps(alert)

    truncated = tmp_path / "truncated"
    truncated.mkdir()
    audit = truncated / "audit.jsonl"
    _fill(audit)
    audit.write_bytes(audit.read_bytes()[:-8])
    completed = _start(_config(truncated, audit))
    assert completed.returncode == 3
    alert = json.loads(Path(str(audit) + ".alert.json").read_text(encoding="utf-8"))
    assert alert["kind"] == "truncated"

    mismatch = tmp_path / "head"
    mismatch.mkdir()
    audit = mismatch / "audit.jsonl"
    _fill(audit)
    head = Path(str(audit) + ".head")
    payload = json.loads(head.read_text(encoding="utf-8"))
    payload["seq"] = 1
    head.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    completed = _start(_config(mismatch, audit))
    assert completed.returncode == 3
    assert b"head" in completed.stderr
    alert = json.loads(Path(str(audit) + ".alert.json").read_text(encoding="utf-8"))
    assert alert["kind"] == "head_mismatch"


def test_runtime_stop_exits_3_even_when_fail_closed_is_false(tmp_path: Path) -> None:
    from test_stdio_e2e import _env, _rpc, _spawn

    audit = tmp_path / "audit.jsonl"
    config = {
        "principal": {"id": "operator-1", "name": "Ada Analyst", "role": "operator"},
        "policy": {"allow": ["excel__read_cell"], "deny": [], "write_tools": []},
        "audit": {"path": str(audit), "fail_closed": False, "checkpoint_every": 0},
        "upstreams": [
            {
                "name": "excel",
                "transport": "stdio",
                "protocol": "legacy",
                "command": sys.executable,
                "args": ["-c", "print('unused')"],
            }
        ],
    }
    # A real upstream is not required: tamper before the tool call, after startup.
    proc = _spawn(tmp_path, config)
    try:
        _rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}},
            },
        )
        raw = audit.read_bytes()
        audit.write_bytes(raw.replace(b"audit/startup", b"audit/startuP", 1))
        try:
            _rpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "excel__read_cell", "arguments": {"cell": "A1"}},
                },
            )
        except AssertionError:
            pass
    finally:
        proc.wait(timeout=8)
    assert proc.returncode == 3
    assert Path(str(audit) + ".alert.json").is_file()


def test_disk_full_does_not_exit_3(tmp_path: Path) -> None:
    stack = assemble(tmp_path)
    proxy = stack["proxies"]["operator"]

    def fail(event: dict) -> dict:
        raise AuditStoreError("disk full")

    proxy.store.append_event = fail  # type: ignore[method-assign]
    response = call_tool(proxy, "excel__read_cell", {"cell": "A1"})
    assert response["error"]["data"]["reason"] == "fail_closed"
    assert proxy._integrity_stop is False


def test_shutdown_is_skipped_on_a_broken_chain(tmp_path: Path) -> None:
    stack = assemble(tmp_path)
    proxy = stack["proxies"]["operator"]
    audit = stack["path"] / "audit.jsonl"
    before = audit.read_bytes()
    audit.write_bytes(before.replace(b"audit/startup", b"audit/startuP", 1))
    try:
        proxy.startup()
    except Exception:
        pass
    assert proxy.shutdown("eof") is None
    assert b"audit/shutdown" not in audit.read_bytes()


def test_alert_command_receives_the_path(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _fill(audit)
    report = verify_bytes(audit.read_bytes())
    marker = tmp_path / "hook.txt"
    script = (
        "import pathlib,sys; pathlib.Path(%r).write_text(pathlib.Path(sys.argv[1]).read_text())" % str(marker)
    )
    write_critical_alert(audit, report, command=(sys.executable, "-c", script))
    assert "PATIENT-SECRET-XYZ" not in marker.read_text(encoding="utf-8")
    assert "kind" in marker.read_text(encoding="utf-8")
