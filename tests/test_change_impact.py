"""Change impact: changelog lines and a requirement subset of the OQ."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

from mcp_glp_audit_proxy.verification.oq import main

ROOT = Path(__file__).resolve().parents[1]


def test_oq_requirement_selects_mapped_tests(tmp_path: Path, monkeypatch) -> None:
    seen: dict[str, list[str]] = {}
    real_run = subprocess.run

    def fake_run(command, **kwargs):
        argv = list(command)
        if "--junitxml" not in argv:
            return real_run(command, **kwargs)
        seen["command"] = argv
        junit = Path(command[command.index("--junitxml") + 1])
        cases = []
        for node in command:
            if not str(node).startswith("tests/"):
                continue
            path, _, name = str(node).partition("::")
            cases.append(f'<testcase classname="x" name="{name}" file="{path}" time="0.01"/>')
        junit.write_text("<testsuite>" + "".join(cases) + "</testsuite>", encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("mcp_glp_audit_proxy.verification.oq.subprocess.run", fake_run)
    code = main(
        [
            "--requirement",
            "COV-1",
            "--junit",
            str(tmp_path / "junit.xml"),
            "--markdown",
            str(tmp_path / "oq.md"),
            "--json",
            str(tmp_path / "oq.json"),
            "--coverage-json",
            str(tmp_path / "coverage.json"),
        ]
    )
    assert code == 0, (tmp_path / "oq.md").read_text(encoding="utf-8") if (tmp_path / "oq.md").is_file() else seen
    command = seen["command"]
    assert "tests/test_chain.py::test_chain_links_and_matches_schema" in command
    assert "tests/test_tamper.py::test_modified_payload_is_detected" in command
    assert "tests/test_export.py::test_verify_cli_exports_only_a_valid_chain" in command
    joined = " ".join(command)
    assert "tests/test_auth_limit.py" not in joined
    text = (tmp_path / "oq.md").read_text(encoding="utf-8")
    assert "Requirement subset: COV-1" in text


def test_unknown_requirement_exits_2(tmp_path: Path, capsys) -> None:
    code = main(
        [
            "--requirement",
            "NO-SUCH",
            "--junit",
            str(tmp_path / "junit.xml"),
            "--markdown",
            str(tmp_path / "oq.md"),
            "--json",
            str(tmp_path / "oq.json"),
        ]
    )
    assert code == 2
    assert "unknown requirement: NO-SUCH" in capsys.readouterr().err
    assert not (tmp_path / "junit.xml").exists()


def test_changelog_from_0_4_0_names_impact() -> None:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for section in re.split(r"(?m)^## ", text):
        matched = re.match(r"(\d+)\.(\d+)\.(\d+)", section)
        if matched is None:
            continue
        version = tuple(int(part) for part in matched.groups())
        if version < (0, 4, 0):
            continue
        assert "Requirements affected:" in section
        assert "Effect on existing records:" in section
