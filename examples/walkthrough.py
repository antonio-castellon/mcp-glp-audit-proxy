#!/usr/bin/env python3
"""Run the hello upstream through the proxy and print the audit result.

From a checkout, with the package installed:

    python examples/walkthrough.py

The run uses a temporary log. It calls lab__hello, lab__save_note, and a
name that is not on the allow list. It then runs verify, tampers one line,
runs verify again, and restores the line. Approval stays off.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER = "REPLACE_WITH_ABSOLUTE_PATH"


def main() -> int:
    report = run()
    sys.stdout.write(report["text"])
    return 0 if report["ok"] else 1


def run() -> dict:
    """Execute the demo. Returns ok plus the full printed report."""
    config_template = json.loads((ROOT / "examples" / "config.json").read_text(encoding="utf-8"))
    if config_template["policy"]["require_approval_for_writes"] is not False:
        raise SystemExit("examples/config.json must leave the approval gate off")
    lines: list[str] = []
    ok = True

    def emit(line: str = "") -> None:
        lines.append(line)

    with tempfile.TemporaryDirectory(prefix="mcp-glp-hello-") as tmp:
        directory = Path(tmp)
        notes = directory / "notes"
        notes.mkdir()
        audit = directory / "audit.jsonl"
        config = json.loads(json.dumps(config_template).replace(PLACEHOLDER, str(ROOT)))
        config["audit"]["path"] = str(audit)
        config["export_dir"] = str(directory / "exports")
        upstream = config["upstreams"][0]
        upstream["command"] = sys.executable
        upstream["args"] = [str(ROOT / "examples" / "hello_upstream.py")]
        upstream["cwd"] = str(notes)
        config_path = directory / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")

        env = os.environ.copy()
        for key in list(env):
            if key.startswith("GLP_"):
                env.pop(key)
        env["GLP_CONFIG"] = str(config_path)
        env["GLP_PRINCIPAL_ID"] = "operator-1"
        env["GLP_PRINCIPAL_NAME"] = "Ada Analyst"
        env["GLP_PRINCIPAL_ROLE"] = "operator"

        proc = subprocess.Popen(
            [sys.executable, "-m", "mcp_glp_audit_proxy", "--config", str(config_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            cwd=directory,
        )
        stderr: list[str] = []

        def _drain() -> None:
            assert proc.stderr is not None
            stderr.append(proc.stderr.read())

        threading.Thread(target=_drain, daemon=True).start()
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
                        "clientInfo": {"name": "hello-walkthrough", "version": "0"},
                    },
                },
            )
            hello = _rpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "lab__hello", "arguments": {"name": "Ada"}},
                },
            )
            save = _rpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "lab__save_note",
                        "arguments": {"text": "bench 1 is clean"},
                    },
                },
            )
            denied = _rpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "lab__drop_all", "arguments": {}},
                },
            )
        finally:
            if proc.stdin is not None:
                proc.stdin.close()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

        hello_text = _tool_text(hello)
        save_text = _tool_text(save)
        denied_text = _tool_text(denied)
        emit("HELLO " + hello_text)
        emit("SAVE " + save_text)
        emit("DENIED " + denied_text)
        note_body = (notes / "hello-notes.txt").read_text(encoding="utf-8")
        emit("NOTES " + note_body.strip())
        if hello_text != "Hello, Ada." or save_text != "Saved: bench 1 is clean":
            ok = False
        if "denied by policy (allow:none)" not in denied_text:
            ok = False
        if stderr and stderr[0].strip():
            emit("PROXY_STDERR")
            emit(stderr[0].rstrip())

        records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines() if line]
        emit("LOG_COUNT " + str(len(records)))
        for record in records:
            if record.get("tool") in {"lab__hello", "lab__save_note", "lab__drop_all"}:
                emit("LOG_TOOL " + str(record.get("tool")))
                emit(_explain(record))

        verify_ok = _verify(audit, print_head=False)
        verify_head = _verify(audit, print_head=True)
        emit("VERIFY_RC " + str(verify_ok.returncode))
        emit("VERIFY_STDOUT")
        emit(verify_ok.stdout.rstrip())
        emit("VERIFY_STDERR")
        emit(verify_ok.stderr.rstrip())
        emit("PRINT_HEAD_RC " + str(verify_head.returncode))
        emit("PRINT_HEAD_STDOUT")
        emit(verify_head.stdout.rstrip())
        emit("PRINT_HEAD_STDERR")
        emit(verify_head.stderr.rstrip())
        if verify_ok.returncode != 0 or "chain ok " not in verify_ok.stderr:
            ok = False
        if verify_head.returncode != 0 or "entry_hash=" not in verify_head.stdout:
            ok = False

        original = audit.read_bytes()
        # The default body_mode is hash_only, so the greeting is not in the log.
        # Editing the stored tool name is enough to show the chain detects a change.
        tampered = original.replace(b"lab__hello", b"lab__hellO", 1)
        if tampered == original:
            emit("TAMPER_MISS")
            ok = False
        else:
            audit.write_bytes(tampered)
            broken = _verify(audit, print_head=False)
            emit("TAMPER_RC " + str(broken.returncode))
            emit("TAMPER_STDERR")
            emit(broken.stderr.rstrip())
            if broken.returncode == 0 or "chain invalid" not in broken.stderr:
                ok = False
            if "entry_hash mismatch" not in broken.stderr:
                ok = False
            audit.write_bytes(original)
            restored = _verify(audit, print_head=False)
            emit("RESTORE_RC " + str(restored.returncode))
            emit("RESTORE_STDERR")
            emit(restored.stderr.rstrip())
            if restored.returncode != 0 or "chain ok " not in restored.stderr:
                ok = False

    emit("OK" if ok else "FAIL")
    return {"ok": ok, "text": "\n".join(lines) + "\n"}


def _verify(audit: Path, *, print_head: bool) -> subprocess.CompletedProcess[str]:
    command = [sys.executable, "-m", "mcp_glp_audit_proxy", "verify", str(audit)]
    if print_head:
        command.append("--print-head")
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _explain(record: dict) -> str:
    principal = record.get("principal") or {}
    return "\n".join(
        [
            f"  principal.id={principal.get('id')} principal.name={principal.get('name')} principal.role={principal.get('role')}",
            f"  timestamp={record.get('timestamp')}",
            f"  tool={record.get('tool')} status={record.get('status')}",
            f"  arguments={json.dumps(record.get('arguments'), separators=(',', ':'))}",
            f"  result={json.dumps(record.get('result'), separators=(',', ':'))}",
            f"  prev_hash={record.get('prev_hash')}",
            f"  entry_hash={record.get('entry_hash')}",
        ]
    )


def _tool_text(message: dict) -> str:
    result = message.get("result") or {}
    content = result.get("content") or []
    if content and isinstance(content[0], dict):
        return str(content[0].get("text") or "")
    if "error" in message:
        return str(message["error"])
    return json.dumps(message)


def _rpc(proc: subprocess.Popen, message: dict) -> dict:
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()
    ready, _, _ = select.select([proc.stdout], [], [], 20)
    if not ready:
        raise SystemExit(f"no response for {message.get('method')}")
    line = proc.stdout.readline()
    if not line:
        raise SystemExit("proxy stdout closed")
    return json.loads(line)


if __name__ == "__main__":
    raise SystemExit(main())
