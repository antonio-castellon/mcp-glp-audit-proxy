"""Bounded reads: a missing newline cannot grow without a limit."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_glp_audit_proxy.anchor import verify_anchored
from mcp_glp_audit_proxy.framing import MAX_MESSAGE_BYTES, BoundedLineReader, LineTooLong
from mcp_glp_audit_proxy.upstream import JsonRpcUpstream, StdioTransport, UpstreamError
from mcp.client.stdio import StdioServerParameters


def test_bounded_reader_stops_at_the_limit() -> None:
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"ok\n")
    os.write(write_fd, b"0123456789")
    os.close(write_fd)
    reader = BoundedLineReader(os.fdopen(read_fd, "rb", buffering=0), 4)
    assert reader.readline() == b"ok\n"
    with pytest.raises(LineTooLong):
        reader.readline()


def test_bounded_reader_times_out() -> None:
    read_fd, write_fd = os.pipe()
    reader = BoundedLineReader(os.fdopen(read_fd, "rb", buffering=0), 100, timeout=0.2)
    try:
        with pytest.raises(TimeoutError):
            reader.readline()
    finally:
        os.close(write_fd)


def test_bounded_reader_returns_a_line_before_the_timeout() -> None:
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"hello\n")
    reader = BoundedLineReader(os.fdopen(read_fd, "rb", buffering=0), 100, timeout=2)
    try:
        assert reader.readline() == b"hello\n"
    finally:
        os.close(write_fd)


def test_host_stream_without_a_newline_ends_the_session(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "principal": {"id": "operator-1", "name": "Ada Analyst", "role": "operator"},
                "policy": {"allow": [], "deny": [], "write_tools": []},
                "audit": {"path": "audit.jsonl", "fail_closed": True, "checkpoint_every": 0},
                "upstreams": [],
            }
        ),
        encoding="utf-8",
    )
    env = _env()
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "--config", str(config)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=tmp_path,
    )
    payload = b"A" * (MAX_MESSAGE_BYTES + 1)
    try:
        out, err = proc.communicate(payload, timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    assert proc.returncode == 1, err
    response = json.loads(out.decode("utf-8").splitlines()[0])
    assert response["error"]["message"]
    audit = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "A" * 100 not in audit
    assert "message:size" in audit
    assert b"ending session" in err
    report = verify_anchored(tmp_path / "audit.jsonl")
    assert report.ok, report.errors


def test_upstream_stream_without_a_newline_is_refused(tmp_path: Path) -> None:
    script = tmp_path / "flood.py"
    script.write_text(
        "import sys, time\n"
        f"sys.stdout.buffer.write(b'B' * {MAX_MESSAGE_BYTES + 1})\n"
        "sys.stdout.buffer.flush()\n"
        "time.sleep(30)\n",
        encoding="utf-8",
    )
    transport = StdioTransport(
        StdioServerParameters(command=sys.executable, args=[str(script)]),
        timeout=5,
    )
    upstream = JsonRpcUpstream("excel", transport, "legacy")
    try:
        with pytest.raises(UpstreamError, match="exceeds size limit"):
            upstream.ensure()
    finally:
        transport.close()
    assert transport.proc.poll() is not None


def _env() -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GLP_"):
            env.pop(key)
    src = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    return env
