"""Segment close records a reason and an approver, and links the previous head."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_glp_audit_proxy.cli import main as verify_main
from mcp_glp_audit_proxy.segments_cli import main as segment_main

from conftest import assemble


def _config(tmp_path: Path, audit: Path) -> Path:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "principal": {"id": "admin-1", "name": "Dan Admin", "role": "admin"},
                "audit": {"path": str(audit), "fail_closed": True},
            }
        ),
        encoding="utf-8",
    )
    return path


def test_segment_close_requires_reason_and_approver(tmp_path: Path, capsys) -> None:
    stack = assemble(tmp_path)
    audit = stack["path"] / "audit.jsonl"
    config = _config(tmp_path, audit)
    assert segment_main(["close", "--config", str(config), "--ticket", "T1", "--approved-by", "QA"]) == 2
    assert segment_main(["close", "--config", str(config), "--reason", "archive", "--ticket", "T1"]) == 2
    capsys.readouterr()


def test_intact_segment_links_and_broken_segment_is_recorded(tmp_path: Path, capsys) -> None:
    stack = assemble(tmp_path)
    audit = stack["path"] / "audit.jsonl"
    config = _config(tmp_path, audit)
    nxt = tmp_path / "next.jsonl"
    assert (
        segment_main(
            [
                "close",
                "--config",
                str(config),
                "--reason",
                "rotate",
                "--ticket",
                "T-1",
                "--approved-by",
                "TFM-1",
                "--output",
                str(nxt),
            ]
        )
        == 0
    )
    first = json.loads(nxt.read_text(encoding="utf-8").splitlines()[0])
    assert first["method"] == "audit/segment_start"
    assert first["arguments"]["approved_by"] == "TFM-1"
    assert first["arguments"]["reason"] == "rotate"
    assert first["arguments"]["previous_head_hash"] != "broken"
    assert verify_main(["--segments", str(audit), str(nxt)]) == 0
    capsys.readouterr()

    raw = audit.read_bytes()
    audit.write_bytes(raw.replace(b"audit/startup", b"audit/startuP", 1))
    broken_out = tmp_path / "after.jsonl"
    assert (
        segment_main(
            [
                "close",
                "--config",
                str(config),
                "--reason",
                "restore",
                "--ticket",
                "T-2",
                "--approved-by",
                "TFM-2",
                "--output",
                str(broken_out),
            ]
        )
        == 0
    )
    start = json.loads(broken_out.read_text(encoding="utf-8").splitlines()[0])
    assert start["arguments"]["previous_head_hash"] == "broken"
    assert start["arguments"]["approved_by"] == "TFM-2"
    assert verify_main(["--segments", str(audit), str(broken_out)]) == 1
    err = capsys.readouterr().err
    assert "broken" in err
