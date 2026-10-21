"""The hello example stays an audit demo, including tamper detection."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUIDES = ROOT / "docs" / "manual-guides"
HOSTS = (
    "claude-desktop.md",
    "claude-code.md",
    "cursor.md",
    "vscode-copilot.md",
    "windsurf-cline-continue.md",
    "generic-stdio.md",
    "python-sdk.md",
    "langchain-langgraph.md",
    "openai-agents.md",
    "docker.md",
    "windows-lab-pc.md",
    "multi-user.md",
    "air-gapped.md",
)
TOPICS = (
    "anchoring-and-verification.md",
    "approval-workflow.md",
    "plugins.md",
    "troubleshooting.md",
)


def test_walkthrough_audits_and_detects_tamper() -> None:
    config = json.loads((ROOT / "examples" / "config.json").read_text(encoding="utf-8"))
    assert config["policy"]["require_approval_for_writes"] is False
    assert config["policy"]["require_reason_for_writes"] is False
    assert config["policy"]["allow"] == ["lab__hello", "lab__save_note"]
    completed = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "walkthrough.py")],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    text = completed.stdout
    assert completed.returncode == 0, completed.stderr + text
    assert "HELLO Hello, Ada." in text
    assert "SAVE Saved: bench 1 is clean" in text
    assert "DENIED denied by policy (allow:none)" in text
    assert "VERIFY_RC 0" in text
    assert "chain ok " in text
    assert "entry_hash=" in text
    assert "TAMPER_RC 1" in text
    assert "chain invalid" in text
    assert "entry_hash mismatch" in text
    assert "RESTORE_RC 0" in text
    assert text.strip().endswith("OK")


def test_module_verify_subcommand(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_bytes(b"")
    monkeypatch.setattr(
        sys,
        "argv",
        ["mcp-glp-audit-proxy", "verify", str(audit), "--print-head"],
    )
    from mcp_glp_audit_proxy.__main__ import main

    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 0


def test_guides_point_at_the_audit_hello() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    index = (GUIDES / "README.md").read_text(encoding="utf-8")
    quick = (GUIDES / "QUICKSTART.md").read_text(encoding="utf-8")
    assert "docs/manual-guides/QUICKSTART.md" in readme
    assert index.index("QUICKSTART.md") < index.index("claude-desktop.md")
    assert "Optional: four-eyes gate for write tools" in quick
    assert "chain invalid" in quick
    assert "entry_hash mismatch" in quick
    assert "denied by policy (allow:none)" in quick
    assert "Hello, Ada." in quick
    for name in HOSTS:
        page = (GUIDES / name).read_text(encoding="utf-8")
        hello = page.split("## Hello world", 1)[1].split("## Pitfalls", 1)[0]
        assert "lab__hello" in hello
        assert "lab__save_note" in hello
        assert "lab__drop_all" in hello
        assert "entry_hash" in hello
        assert "If it does not work" in hello
        assert "glp_approve" not in hello
        assert "four-eyes" not in hello.lower()
    for name in TOPICS:
        page = (GUIDES / name).read_text(encoding="utf-8")
        assert "## Hello world" not in page
    proxy = (GUIDES / "generic-stdio.md").read_text(encoding="utf-8")
    start = proxy.index("```json proxy\n", proxy.index("## Hello world"))
    body = proxy[start + len("```json proxy\n") :]
    body = body[: body.index("\n```")]
    file_text = (ROOT / "examples" / "config.json").read_text(encoding="utf-8").rstrip("\n")
    assert body == file_text
