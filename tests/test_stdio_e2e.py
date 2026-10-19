"""Subprocess proxy: real stdio, real entry point, fake upstream."""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import threading
from pathlib import Path

FAKE = Path(__file__).resolve().parent / "fake_upstream_server.py"
SRC = str(Path(__file__).resolve().parents[1] / "src")


def test_allowed_denied_and_verify_cli(tmp_path: Path) -> None:
    log = tmp_path / "calls.log"
    proc = _spawn(
        tmp_path,
        _config(
            role="operator",
            allow=["excel__read_cell"],
            write_tools=[],
            command=[sys.executable, str(FAKE), "legacy"],
            call_log=log,
            audit="audit.jsonl",
        ),
    )
    try:
        _rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "e2e", "version": "0"},
                },
            },
        )
        allowed = _rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "excel__read_cell", "arguments": {"cell": "B2"}},
            },
        )
        assert "error" not in allowed
        assert "B2" in allowed["result"]["content"][0]["text"]
        denied = _rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "excel__write_cell", "arguments": {"cell": "B2", "value": 1}},
            },
        )
        assert denied["result"]["isError"] is True
        assert "denied" in denied["result"]["content"][0]["text"]
    finally:
        _stop(proc)
    audit = tmp_path / "audit.jsonl"
    text = audit.read_text(encoding="utf-8")
    assert "excel__read_cell" in text
    assert "denied" in text
    verified = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from mcp_glp_audit_proxy.cli import main; raise SystemExit(main(sys.argv[1:]))",
            str(audit),
            "--print-head",
        ],
        capture_output=True,
        text=True,
        env=_env(),
        check=False,
    )
    assert verified.returncode == 0, verified.stderr
    assert verified.stdout.startswith("seq=")
    assert "entry_hash=" in verified.stdout
    assert "chain ok" in verified.stderr


def test_approval_flow_across_two_processes(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    operator = _spawn(
        tmp_path,
        _config(
            role="operator",
            allow=["*"],
            write_tools=["excel__write_cell"],
            require_approval=True,
            command=[sys.executable, str(FAKE), "legacy"],
            audit=str(audit),
        ),
        name="operator.json",
    )
    try:
        held = _rpc(
            operator,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "excel__write_cell",
                    "arguments": {"cell": "A1", "value": 1},
                    "_meta": {"io.github.antonio-castellon/reason": "weigh the sample"},
                },
            },
        )
        text = held["result"]["content"][0]["text"]
        approval_id = text.split("approval_id=")[1].split()[0]
        approver = _spawn(
            tmp_path,
            _config(
                role="approver",
                allow=[],
                write_tools=[],
                command=None,
                audit=str(audit),
            ),
            name="approver.json",
        )
        try:
            approved = _rpc(
                approver,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "glp_approve",
                        "arguments": {"approval_id": approval_id, "meaning": "approved"},
                    },
                },
            )
            assert "error" not in approved
        finally:
            _stop(approver)
        done = _rpc(
            operator,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "excel__write_cell",
                    "arguments": {"cell": "A1", "value": 1},
                    "_meta": {
                        "io.github.antonio-castellon/reason": "weigh the sample",
                        "io.github.antonio-castellon/approvalId": approval_id,
                    },
                },
            },
        )
        assert done["result"]["structuredContent"]["saved"] is True
    finally:
        _stop(operator)


def test_upstream_crash_and_hang(tmp_path: Path) -> None:
    crash = tmp_path / "crash.py"
    crash.write_text("import sys\nsys.stdin.readline()\nsys.exit(0)\n", encoding="utf-8")
    proc = _spawn(
        tmp_path,
        _config(
            role="operator",
            allow=["*"],
            write_tools=[],
            command=[sys.executable, str(crash)],
            audit="crash.jsonl",
            timeout=2,
        ),
        name="crash.json",
    )
    try:
        failed = _rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "excel__read_cell", "arguments": {"cell": "A1"}},
            },
        )
        assert "upstream failed" in failed["error"]["message"]
        assert "closed stdout" in failed["error"]["message"]
    finally:
        _stop(proc)
    assert "failed" in (tmp_path / "crash.jsonl").read_text(encoding="utf-8")

    hang = tmp_path / "hang.py"
    hang.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    proc = _spawn(
        tmp_path,
        _config(
            role="operator",
            allow=["*"],
            write_tools=[],
            command=[sys.executable, str(hang)],
            audit="hang.jsonl",
            timeout=0.6,
        ),
        name="hang.json",
    )
    try:
        failed = _rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "excel__read_cell", "arguments": {"cell": "A1"}},
            },
            timeout=10,
        )
        assert "timed out" in failed["error"]["message"]
    finally:
        _stop(proc)


def test_audit_store_failure_latches_blocked(tmp_path: Path) -> None:
    log = tmp_path / "calls.log"
    proc = _spawn(
        tmp_path,
        _config(
            role="operator",
            allow=["*"],
            write_tools=[],
            command=[sys.executable, str(FAKE), "legacy"],
            call_log=log,
            audit="audit.jsonl",
        ),
    )
    try:
        first = _rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "excel__read_cell", "arguments": {"cell": "A1"}},
            },
        )
        assert "error" not in first
        os.chmod(tmp_path / "audit.jsonl", 0o444)
        before = _tool_calls(log)
        blocked = _rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "excel__read_cell", "arguments": {"cell": "A2"}},
            },
        )
        assert blocked["error"]["data"]["reason"] == "fail_closed"
        mid = _tool_calls(log)
        assert mid >= before
        again = _rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "excel__read_cell", "arguments": {"cell": "A3"}},
            },
        )
        assert again["error"]["data"]["reason"] == "fail_closed"
        assert _tool_calls(log) == mid
    finally:
        audit = tmp_path / "audit.jsonl"
        if audit.exists():
            os.chmod(audit, 0o644)
        _stop(proc)


def _tool_calls(path: Path) -> int:
    if not path.is_file():
        return 0
    return path.read_text(encoding="utf-8").splitlines().count("tools/call")


def _config(
    *,
    role: str,
    allow: list[str],
    write_tools: list[str],
    command: list[str] | None,
    audit: str,
    call_log: Path | None = None,
    require_approval: bool = False,
    timeout: float = 5,
) -> dict:
    names = {
        "operator": "Ada Analyst",
        "approver": "Ben Reviewer",
        "qa": "Cara QA",
        "admin": "Dan Admin",
    }
    upstreams = []
    if command is not None:
        env = {"GLP_CALL_LOG": str(call_log)} if call_log else {}
        upstreams.append(
            {
                "name": "excel",
                "transport": "stdio",
                "protocol": "legacy",
                "command": command[0],
                "args": command[1:],
                "timeout": timeout,
                "env": env,
            }
        )
    return {
        "principal": {"id": f"{role}-1", "name": names[role], "role": role},
        "policy": {
            "allow": allow,
            "deny": [],
            "write_tools": write_tools,
            "require_approval_for_writes": require_approval,
            "require_reason_for_writes": True,
        },
        "audit": {"path": audit, "fail_closed": True, "checkpoint_every": 0},
        "upstreams": upstreams,
    }


def _spawn(tmp_path: Path, config: dict, name: str = "config.json") -> subprocess.Popen:
    path = tmp_path / name
    path.write_text(json.dumps(config), encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "--config", str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_env(),
        cwd=tmp_path,
    )
    proc._stderr_buf = []  # type: ignore[attr-defined]

    def _drain() -> None:
        assert proc.stderr is not None
        proc._stderr_buf.append(proc.stderr.read())  # type: ignore[attr-defined]

    threading.Thread(target=_drain, daemon=True).start()
    return proc


def _rpc(proc: subprocess.Popen, message: dict, timeout: float = 15) -> dict:
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    proc.stdin.flush()
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    if not ready:
        err = "".join(getattr(proc, "_stderr_buf", []))
        raise AssertionError(f"no response for {message.get('method')}: {err}")
    line = proc.stdout.readline()
    if not line:
        err = "".join(getattr(proc, "_stderr_buf", []))
        raise AssertionError(f"stdout closed: {err} rc={proc.poll()}")
    return json.loads(line)


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if proc.stdin is not None:
        try:
            proc.stdin.close()
        except OSError:
            pass
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def _env() -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GLP_"):
            env.pop(key)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    return env
