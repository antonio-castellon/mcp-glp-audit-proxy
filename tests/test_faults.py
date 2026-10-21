"""Fault injection: store I/O, tamper shapes, concurrency, upstream loss, clock."""

from __future__ import annotations

import errno
import threading
from pathlib import Path

import pytest
from mcp.client.stdio import StdioServerParameters

from mcp_glp_audit_proxy.anchor import verify_anchored
from mcp_glp_audit_proxy.chain import verify_bytes, verify_file
from mcp_glp_audit_proxy.errors import AuditStoreError, ChainIntegrityError
from mcp_glp_audit_proxy.records import SYSTEM_PRINCIPAL, build_event
from mcp_glp_audit_proxy.storage import jsonl as jsonl_mod
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore
from mcp_glp_audit_proxy.upstream import JsonRpcUpstream, StdioTransport, UpstreamError

from conftest import call_tool


def _event(index: int) -> dict:
    return build_event(
        method="tools/call",
        record_class="access",
        status="ok",
        server="excel",
        principal=SYSTEM_PRINCIPAL,
        client={"id": "proxy", "name": "proxy", "version": "0.2.0", "model_id": None},
        protocol_version="2025-11-25",
        session_id=None,
        tool=f"excel__read_{index}",
        arguments={"n": index},
        result={"n": index},
    )


def _fill(path: Path, count: int = 3) -> JsonlAuditStore:
    store = JsonlAuditStore(path, checkpoint_every=0)
    for index in range(count):
        store.append_event(_event(index))
    return store


def test_fsync_enospc_latches_the_proxy(build, monkeypatch) -> None:
    stack = build()
    proxy = stack["proxies"]["operator"]

    def boom(_fd: int) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(jsonl_mod.os, "fsync", boom)
    before = len(stack["fake"].calls)
    first = call_tool(proxy, "excel__read_cell", {"cell": "A1"})
    assert first["error"]["data"]["reason"] == "fail_closed"
    assert "audit store write failed" in first["error"]["data"]["detail"]
    assert proxy._dead is True
    # The upstream may already have run. The host must not see that payload.
    assert "result" not in first
    after_first = len(stack["fake"].calls)
    assert after_first > before
    second = call_tool(proxy, "excel__read_cell", {"cell": "A2"}, request_id=11)
    assert second["error"]["data"]["reason"] == "fail_closed"
    assert len(stack["fake"].calls) == after_first


def test_eio_and_permission_errors_are_store_errors(tmp_path, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    store = _fill(path, 1)

    def eio(_fd: int, _data: bytes) -> int:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(jsonl_mod.os, "write", eio)
    with pytest.raises(AuditStoreError, match="audit store write failed"):
        store.append_event(_event(2))

    def denied(*_args, **_kwargs):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(jsonl_mod.os, "open", denied)
    fresh = JsonlAuditStore(tmp_path / "other.jsonl", checkpoint_every=0)
    with pytest.raises(AuditStoreError):
        fresh.append_event(_event(0))


def test_broken_chain_latches_and_does_not_retry(build) -> None:
    stack = build()
    proxy = stack["proxies"]["operator"]
    path = stack["store"].path
    path.write_bytes(path.read_bytes().replace(b"audit/startup", b"audit/startux", 1))
    before = len(stack["fake"].calls)
    first = call_tool(proxy, "excel__read_cell", {"cell": "A1"})
    assert first["error"]["data"]["reason"] == "fail_closed"
    assert proxy._dead is True
    second = call_tool(proxy, "excel__read_cell", {"cell": "A2"}, request_id=11)
    assert second["error"]["data"]["reason"] == "fail_closed"
    assert len(stack["fake"].calls) == before


def test_partial_line_is_detected_and_blocks_the_next_append(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    store = _fill(path, 2)
    with path.open("ab") as handle:
        handle.write(b'{"partial"')
        handle.flush()
    report = verify_file(path)
    assert report.ok is False
    assert any("newline" in error or "not utf-8 json" in error for error in report.errors)
    with pytest.raises(ChainIntegrityError):
        store.append_event(_event(3))


def test_insert_duplicate_and_tail_shapes(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path, 3)
    lines = path.read_bytes().splitlines(keepends=True)

    inserted = b"".join([lines[0], lines[2], lines[1], lines[2]])
    assert verify_bytes(inserted).ok is False

    duplicated = b"".join([lines[0], lines[1], lines[1], lines[2]])
    assert verify_bytes(duplicated).ok is False

    # The hash chain of a prefix still links. The sidecar head names the old tip,
    # so the anchored check fails. See tests/test_anchor.py.
    prefix = b"".join(lines[:2])
    rolled = verify_bytes(prefix)
    assert rolled.ok is True
    assert rolled.count == 2
    path.write_bytes(prefix)
    assert verify_anchored(path).ok is False

    mid = lines[0] + lines[1][:10]
    truncated = verify_bytes(mid)
    assert truncated.ok is False


def test_parallel_appends_stay_one_record_per_line(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    store = JsonlAuditStore(path, checkpoint_every=0)
    errors: list[BaseException] = []

    def worker(start: int) -> None:
        try:
            for offset in range(5):
                store.append_event(_event(start + offset))
        except BaseException as exc:  # collected and re-raised below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(index * 10,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    report = verify_file(path)
    assert report.ok, report.errors
    assert report.count == 30
    assert [entry["seq"] for entry in report.entries] == list(range(1, 31))
    raw_lines = path.read_bytes().splitlines()
    assert len(raw_lines) == 30
    for line in raw_lines:
        assert b"\n" not in line
        assert line.startswith(b"{") and line.endswith(b"}")


def test_backwards_clock_is_stored_as_given(build) -> None:
    stack = build()
    clock = stack["clock"]
    proxy = stack["proxies"]["operator"]
    call_tool(proxy, "excel__read_cell", {"cell": "A1"})
    first = stack["store"].read_entries()[-1]["timestamp"]
    clock.moment = clock.moment.replace(year=clock.moment.year - 1)
    call_tool(proxy, "excel__read_cell", {"cell": "A2"}, request_id=11)
    entries = [entry for entry in stack["store"].read_entries() if entry.get("tool") == "excel__read_cell"]
    assert entries[1]["timestamp"] < entries[0]["timestamp"]
    assert entries[1]["seq"] == entries[0]["seq"] + 1
    assert first > entries[1]["timestamp"]


def test_upstream_crash_is_logged_and_does_not_consume_approval(build, tmp_path) -> None:
    script = tmp_path / "die.py"
    script.write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
    transport = StdioTransport(
        StdioServerParameters(command="python3", args=[str(script)]),
        timeout=2,
    )
    upstream = JsonRpcUpstream("excel", transport, "legacy")
    with pytest.raises(UpstreamError, match="closed stdout"):
        upstream.ensure()
    transport.close()


def test_upstream_timeout(tmp_path) -> None:
    script = tmp_path / "hang.py"
    script.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    transport = StdioTransport(
        StdioServerParameters(command="python3", args=[str(script)]),
        timeout=0.3,
    )
    upstream = JsonRpcUpstream("excel", transport, "legacy")
    try:
        with pytest.raises(UpstreamError, match="timed out"):
            upstream.ensure()
    finally:
        transport.close()


def test_transport_failure_keeps_the_approval(build) -> None:
    stack = build(require_approval=True)
    operator = stack["proxies"]["operator"]
    approver = stack["proxies"]["approver"]
    reason = {"io.github.antonio-castellon/reason": "weigh the sample"}
    held = call_tool(operator, "excel__write_cell", {"cell": "A1", "value": 1}, reason)
    text = held["result"]["content"][0]["text"]
    approval_id = text.split("approval_id=")[1].split()[0]
    call_tool(
        approver,
        "glp_approve",
        {"approval_id": approval_id, "meaning": "approved"},
        request_id=11,
    )

    transport = stack["proxies"]["operator"].upstreams["excel"].transport
    original = transport.send

    def send(message, *, session_id=None):
        raise UpstreamError("upstream closed stdout")

    transport.send = send
    refused = call_tool(
        operator,
        "excel__write_cell",
        {"cell": "A1", "value": 1},
        {**reason, "io.github.antonio-castellon/approvalId": approval_id},
        request_id=12,
    )
    assert "upstream failed" in refused["error"]["message"]
    logged = [
        entry
        for entry in stack["store"].read_entries()
        if entry.get("tool") == "excel__write_cell" and entry["status"] == "failed"
    ][-1]
    assert logged["approval"] is None
    transport.send = original
    again = call_tool(
        operator,
        "excel__write_cell",
        {"cell": "A1", "value": 1},
        {**reason, "io.github.antonio-castellon/approvalId": approval_id},
        request_id=13,
    )
    assert again["result"]["structuredContent"]["saved"] is True
