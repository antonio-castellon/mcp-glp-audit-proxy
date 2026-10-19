"""Sidecar head: truncated tails, lag of one, and startup refusal."""

from __future__ import annotations

import errno
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_glp_audit_proxy.anchor import read_head, verify_anchored, write_head
from mcp_glp_audit_proxy.chain import verify_bytes, verify_file
from mcp_glp_audit_proxy.cli import main as verify_main
from mcp_glp_audit_proxy.errors import AuditStoreError
from mcp_glp_audit_proxy.storage import jsonl as jsonl_mod
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore

from conftest import call_tool
from test_faults import _event, _fill


def test_truncating_whole_lines_fails_verification(tmp_path: Path, capsys) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path, 4)
    original = read_head(path)
    assert original is not None
    assert stat.S_IMODE(path.with_name(path.name + ".head").stat().st_mode) == 0o600
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:2]))
    report = verify_anchored(path)
    assert report.ok is False
    assert any("disagrees" in error for error in report.errors)
    assert verify_main([str(path), "--print-head"]) == 1
    assert "seq=" not in capsys.readouterr().out


def test_consistent_truncation_of_log_and_head_is_a_residual_risk(tmp_path: Path, capsys) -> None:
    """Both files moved together still verify. An external copy of the head would not match."""
    path = tmp_path / "audit.jsonl"
    _fill(path, 4)
    external = read_head(path)
    assert external is not None
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:2]))
    shortened = verify_bytes(path.read_bytes())
    assert shortened.ok is True
    tip = shortened.entries[-1]
    write_head(path, int(tip["seq"]), str(tip["entry_hash"]))
    report = verify_anchored(path)
    assert report.ok is True
    assert report.anchor_lag == 0
    assert verify_main([str(path), "--print-head"]) == 0
    printed = capsys.readouterr().out.strip().splitlines()[-1]
    assert printed == f"seq={tip['seq']} entry_hash={tip['entry_hash']}"
    assert printed != f"seq={external.seq} entry_hash={external.entry_hash}"


def test_corrupt_or_missing_head_fails(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = _fill(path, 2)
    head = path.with_name(path.name + ".head")
    head.write_text("{", encoding="utf-8")
    broken = verify_anchored(path)
    assert broken.ok is False
    assert any("unreadable" in error for error in broken.errors)
    with pytest.raises(AuditStoreError, match="unreadable"):
        store.append_event(_event(3))

    other = tmp_path / "other.jsonl"
    _fill(other, 1)
    other_head = other.with_name(other.name + ".head")
    other_head.unlink()
    missing = verify_anchored(other)
    assert missing.ok is False
    assert any("missing" in error for error in missing.errors)

    write_head(other, 1, "ab" * 32)
    mismatched = verify_anchored(other)
    assert mismatched.ok is False
    assert any("disagrees" in error for error in mismatched.errors)


def test_one_record_lag_is_recovered_not_a_false_alarm(tmp_path: Path, capsys, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    store = _fill(path, 3)
    entries = verify_file(path).entries
    previous = entries[-2]
    write_head(path, int(previous["seq"]), str(previous["entry_hash"]))
    lagged = verify_anchored(path)
    assert lagged.ok is True
    assert lagged.anchor_lag == 1
    assert lagged.count == 3
    assert verify_main([str(path), "--print-head"]) == 0
    captured = capsys.readouterr()
    assert "head lags by 1 verified record" in captured.err
    assert f"seq={entries[-1]['seq']} entry_hash={entries[-1]['entry_hash']}" in captured.out

    store.append_event(_event(8))
    repaired = verify_anchored(path)
    assert repaired.ok is True
    assert repaired.anchor_lag == 0
    assert read_head(path).seq == 4

    def fail_head(*_args, **_kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(jsonl_mod, "write_head", fail_head)
    sealed = store.append_event(_event(9))
    assert sealed["seq"] == 5
    assert read_head(path).seq == 4
    assert verify_anchored(path).anchor_lag == 1
    monkeypatch.undo()
    store.append_event(_event(10))
    assert read_head(path).seq == 6
    assert verify_anchored(path).anchor_lag == 0


def test_startup_disagreement_refuses_to_start(tmp_path: Path, build) -> None:
    stack = build()
    proxy = stack["proxies"]["operator"]
    path = stack["store"].path
    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:-1]))
    before = len(stack["fake"].calls)
    first = call_tool(proxy, "excel__read_cell", {"cell": "A1"})
    assert first["error"]["data"]["reason"] == "fail_closed"
    assert "head" in first["error"]["data"]["detail"]
    assert proxy._dead is True
    after = len(stack["fake"].calls)
    second = call_tool(proxy, "excel__read_cell", {"cell": "A2"}, request_id=11)
    assert second["error"]["data"]["reason"] == "fail_closed"
    assert len(stack["fake"].calls) == after

    fresh = JsonlAuditStore(path, checkpoint_every=0)
    with pytest.raises(AuditStoreError, match="head"):
        fresh.append_event(_event(1))

    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "principal": {"id": "operator-1", "name": "Ada Analyst", "role": "operator"},
                "policy": {"allow": [], "deny": [], "write_tools": []},
                "audit": {"path": str(path), "fail_closed": True, "checkpoint_every": 0},
                "upstreams": [],
            }
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GLP_"):
            env.pop(key)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(Path(__file__).resolve().parents[1] / "src"), env.get("PYTHONPATH", "")]
    )
    completed = subprocess.run(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "--config", str(config)],
        input=b"",
        capture_output=True,
        env=env,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 1
    assert b"refusing to start" in completed.stderr
    assert b"head" in completed.stderr


def test_settings_round_trip_and_clock_branches(tmp_path: Path, monkeypatch) -> None:
    """Config and clock branches that the proxy subprocess also exercises."""
    from mcp_glp_audit_proxy import clockutil
    from mcp_glp_audit_proxy.config import load_settings
    from mcp_glp_audit_proxy.errors import ConfigurationError

    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "principal": {"id": "qa-1", "name": "Cara QA", "role": "qa"},
                "retention": {"profile": "minimum", "min_months": 6, "years_after_study": 1},
                "policy": {"allow": ["excel__*"], "deny": ["excel__drop_*"], "write_tools": []},
                "audit": {"path": "audit.jsonl", "fail_closed": True, "checkpoint_every": 10},
                "require_ntp": False,
                "upstreams": [
                    {
                        "name": "excel",
                        "transport": "stdio",
                        "command": sys.executable,
                        "args": ["-c", "pass"],
                        "timeout": 1.5,
                        "env": {"EXPLICIT_OK": "1"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GLP_PRINCIPAL_ROLE", "operator")
    monkeypatch.setenv("GLP_PRINCIPAL_ID", "operator-9")
    monkeypatch.setenv("GLP_PRINCIPAL_NAME", "Ada Analyst")
    monkeypatch.setenv("GLP_FAIL_CLOSED", "false")
    loaded = load_settings(config)
    assert loaded.principal.role == "operator"
    assert loaded.fail_closed is False
    assert loaded.upstreams[0].timeout == 1.5
    assert loaded.audit_path.is_absolute()

    config.write_text("{", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_settings(config)
    with pytest.raises(ConfigurationError):
        load_settings(tmp_path / "missing.json")

    monkeypatch.setattr(clockutil.shutil, "which", lambda _name: None)
    assert clockutil.probe_clock()["ntp_synchronized"] is None

    monkeypatch.setattr(clockutil.shutil, "which", lambda _name: "/bin/timedatectl")

    def timed_out(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="timedatectl", timeout=2)

    monkeypatch.setattr(clockutil.subprocess, "run", timed_out)
    assert clockutil.probe_clock()["source"] == "unverified"

    class Completed:
        returncode = 0
        stdout = "yes\n"
        stderr = ""

    monkeypatch.setattr(clockutil.subprocess, "run", lambda *_a, **_k: Completed())
    assert clockutil.probe_clock()["ntp_synchronized"] is True

    class Failed:
        returncode = 1
        stdout = ""
        stderr = "no systemd"

    monkeypatch.setattr(clockutil.subprocess, "run", lambda *_a, **_k: Failed())
    assert clockutil.probe_clock()["ntp_synchronized"] is None
