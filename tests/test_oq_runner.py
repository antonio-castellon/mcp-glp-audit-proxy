"""The OQ report command: a passing run and a failing run."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from mcp_glp_audit_proxy.verification.oq import _canonical, main


def test_oq_report_happy_path(tmp_path: Path, monkeypatch) -> None:
    case = tmp_path / "test_ok_case.py"
    case.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    monkeypatch.setattr(
        "mcp_glp_audit_proxy.verification.oq.community_gaps",
        lambda _rtm, _results: [],
    )
    code, payload, markdown = _run(tmp_path, case)
    assert code == 0
    assert payload["counts"]["failed"] == 0
    assert payload["counts"]["passed"] >= 1
    assert payload["pytest_exit"] == 0
    digest = payload.pop("report_sha256")
    assert hashlib.sha256(_canonical(payload)).hexdigest() == digest
    markdown.encode("ascii")
    assert "designed to support glp" in markdown.lower()


def test_oq_report_failing_test_path(tmp_path: Path) -> None:
    case = tmp_path / "test_bad_case.py"
    case.write_text("def test_bad():\n    assert False, 'nope'\n", encoding="utf-8")
    code, payload, _markdown = _run(tmp_path, case)
    assert code == 1
    assert payload["counts"]["failed"] >= 1
    assert payload["pytest_exit"] != 0
    digest = payload.pop("report_sha256")
    assert hashlib.sha256(_canonical(payload)).hexdigest() == digest


def test_oq_report_module_entry(tmp_path: Path) -> None:
    case = tmp_path / "test_ok_case.py"
    case.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcp_glp_audit_proxy",
            "oq-report",
            "--junit",
            str(tmp_path / "junit.xml"),
            "--markdown",
            str(tmp_path / "oq.md"),
            "--json",
            str(tmp_path / "oq.json"),
            "--coverage-json",
            str(tmp_path / "coverage.json"),
            "--pytest-arg",
            str(case),
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    # A one-test run does not satisfy the matrix, so the command exits 1.
    # The entry point still writes the report.
    assert completed.returncode == 1, completed.stderr
    assert (tmp_path / "oq.md").is_file()
    assert "report_sha256" in (tmp_path / "oq.json").read_text(encoding="utf-8")


def _run(tmp_path: Path, case: Path) -> tuple[int, dict, str]:
    markdown = tmp_path / "oq.md"
    document = tmp_path / "oq.json"
    code = main(
        [
            "--junit",
            str(tmp_path / "junit.xml"),
            "--markdown",
            str(markdown),
            "--json",
            str(document),
            "--coverage-json",
            str(tmp_path / "coverage.json"),
            "--pytest-arg",
            str(case),
        ]
    )
    payload = json.loads(document.read_text(encoding="utf-8"))
    return code, payload, markdown.read_text(encoding="utf-8")
