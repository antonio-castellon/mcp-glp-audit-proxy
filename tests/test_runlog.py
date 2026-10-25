"""Offline commands record a run block and a separate hash-chained run log."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mcp_glp_audit_proxy.archive import main as archive_main
from mcp_glp_audit_proxy.cli import main as verify_main
from mcp_glp_audit_proxy.regulatory import main as regulatory_main
from mcp_glp_audit_proxy.review import main as review_main
from mcp_glp_audit_proxy.runlog import main as verify_run_log

from conftest import assemble

TOKEN = "tok-run-secret"
BODY = "BODY-SECRET-XYZ"


def _config(directory: Path, audit: Path) -> Path:
    path = directory / "config.json"
    path.write_text(
        json.dumps(
            {
                "principal": {"id": "operator-1", "name": "Ada Analyst", "role": "operator"},
                "audit": {"path": str(audit), "fail_closed": True, "body_mode": "hash_only"},
            }
        ),
        encoding="utf-8",
    )
    return path


def _ready(tmp_path: Path) -> Path:
    stack = assemble(tmp_path)
    audit = stack["path"] / "audit.jsonl"
    stack["proxies"]["operator"].shutdown("eof")
    raw = audit.read_bytes()
    audit.write_bytes(raw.replace(b"audit trail stopped", f"audit trail stopped {BODY}".encode(), 1))
    # Rewriting the log breaks the chain. Keep the shutdown text free of the marker
    # and put the marker only in a sidecar the commands do not copy.
    audit.write_bytes(raw)
    (tmp_path / "note.txt").write_text(TOKEN + "\n" + BODY + "\n", encoding="utf-8")
    return audit


def test_each_offline_command_carries_a_run_block(tmp_path: Path) -> None:
    audit = _ready(tmp_path)
    digest = hashlib.sha256(audit.read_bytes()).hexdigest()
    last = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
    head = {"entry_hash": last["entry_hash"], "seq": last["seq"]}
    exported = tmp_path / "export.json"
    assert verify_main([str(audit), "--json-export", str(exported)]) == 0
    manifest = tmp_path / "manifest.json"
    assert archive_main([str(audit), "--out", str(manifest)]) == 0
    report = tmp_path / "report.json"
    config = _config(tmp_path, audit)
    assert regulatory_main(["--config", str(config), "--format", "json", "--out", str(report)]) == 0
    reviewed = tmp_path / "review.json"
    assert review_main([str(audit), "--out", str(reviewed)]) == 0
    checked = tmp_path / "checked.json"
    assert verify_main([str(audit), "--manifest", str(manifest), "--report-out", str(checked)]) == 0
    for path, expected_head in (
        (exported, head),
        (manifest, head),
        (reviewed, head),
        (checked, head),
    ):
        document = json.loads(path.read_text(encoding="utf-8"))
        run = document["run"]
        assert run["inputs"][0]["sha256"] == digest
        assert run["head"] == expected_head
        assert run["product_version"]
        assert run["started_at"].endswith("Z")
        assert run["finished_at"].endswith("Z")
    regulatory = json.loads(report.read_text(encoding="utf-8"))
    assert regulatory["run"]["head"] is None
    assert regulatory["run"]["inputs"][0]["sha256"] == hashlib.sha256(config.read_bytes()).hexdigest()
    assert regulatory["run"]["tool"] == "regulatory-report"


def test_run_log_links_and_detects_an_edit(tmp_path: Path) -> None:
    audit = _ready(tmp_path)
    run_log = tmp_path / "runs.jsonl"
    assert review_main([str(audit), "--out", str(tmp_path / "a.json"), "--run-log", str(run_log)]) == 0
    assert review_main([str(audit), "--out", str(tmp_path / "b.json"), "--run-log", str(run_log)]) == 0
    lines = run_log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert second["prev_hash"] == first["entry_hash"]
    assert verify_run_log([str(run_log)]) == 0
    tampered = lines[0].replace(first["run"]["tool"], "reviewX", 1)
    run_log.write_text(tampered + "\n" + lines[1] + "\n", encoding="utf-8")
    assert verify_run_log([str(run_log)]) == 1


def test_offline_commands_leave_the_live_log_unchanged(tmp_path: Path) -> None:
    audit = _ready(tmp_path)
    head = audit.with_name(audit.name + ".head")
    before = (audit.read_bytes(), head.read_bytes(), audit.stat().st_mtime_ns, head.stat().st_mtime_ns)
    run_log = tmp_path / "runs.jsonl"
    assert verify_main([str(audit), "--json-export", str(tmp_path / "export.json"), "--run-log", str(run_log)]) == 0
    assert archive_main([str(audit), "--out", str(tmp_path / "manifest.json"), "--run-log", str(run_log)]) == 0
    assert (audit.read_bytes(), head.read_bytes(), audit.stat().st_mtime_ns, head.stat().st_mtime_ns) == before


def test_run_block_has_no_token_or_body(tmp_path: Path) -> None:
    audit = _ready(tmp_path)
    out = tmp_path / "review.json"
    run_log = tmp_path / "runs.jsonl"
    assert review_main([str(audit), "--out", str(out), "--run-log", str(run_log)]) == 0
    blob = out.read_text(encoding="utf-8") + run_log.read_text(encoding="utf-8")
    assert TOKEN not in blob
    assert BODY not in blob
