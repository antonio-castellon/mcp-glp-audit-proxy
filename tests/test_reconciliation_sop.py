"""The reconciliation snippet in docs/RECONCILIATION_SOP.md must run as written."""

from __future__ import annotations

import os
import re
from pathlib import Path

from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.cli import main as verify_main
from mcp_glp_audit_proxy.records import SYSTEM_PRINCIPAL, build_event
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore

ROOT = Path(__file__).resolve().parents[1]
SOP = ROOT / "docs" / "RECONCILIATION_SOP.md"


def _snippet() -> str:
    text = SOP.read_text(encoding="utf-8")
    text.encode("ascii")
    block = re.search(
        r"<!-- reconciliation-snippet:start -->\n```python\n(.*?)```\n<!-- reconciliation-snippet:end -->",
        text,
        re.S,
    )
    assert block, "snippet markers missing"
    return block.group(1)


def test_sop_snippet_appends_a_verifiable_entry(tmp_path, capsys) -> None:
    audit = tmp_path / "data" / "audit.jsonl"
    store = JsonlAuditStore(audit)
    store.append_event(
        build_event(
            method="audit/startup",
            record_class="config",
            status="ok",
            server="proxy",
            principal=SYSTEM_PRINCIPAL,
            client={"id": "test"},
            protocol_version=None,
            session_id=None,
        )
    )
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        exec(compile(_snippet(), str(SOP), "exec"), {})
    finally:
        os.chdir(cwd)
    report = verify_file(audit)
    assert report.ok, report.errors
    last = report.entries[-1]
    assert last["method"] == "audit/reconciliation"
    assert last["record_class"] == "gxp_data"
    assert last["principal"]["role"] == "qa"
    assert last["result"]["head_hash_before"] == report.entries[-2]["entry_hash"]
    capsys.readouterr()
    assert verify_main([str(audit), "--method", "audit/reconciliation"]) == 0
    err = capsys.readouterr().err
    assert "chain ok entries=2 shown=1" in err


def test_sop_is_linked() -> None:
    assert "docs/RECONCILIATION_SOP.md" in (ROOT / "SAFETY.md").read_text(encoding="utf-8")
    assert "docs/RECONCILIATION_SOP.md" in (ROOT / "README.md").read_text(encoding="utf-8")
