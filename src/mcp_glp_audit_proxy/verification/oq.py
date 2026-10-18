"""Run the suite and write a verification report.

The report is evidence a customer can attach to their own records. It is
designed to support GLP / 21 CFR Part 11 / EU GMP Annex 11 workflows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import defusedxml.ElementTree as ET
from datetime import datetime, timezone
from importlib.metadata import distributions, version
from pathlib import Path
from typing import Any

from .. import __version__
from .rtm import community_gaps, junit_results, load_rtm

ROOT = Path(__file__).resolve().parents[3]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-glp-audit-proxy oq-report")
    parser.add_argument("--junit", type=Path, default=Path("junit.xml"))
    parser.add_argument("--markdown", type=Path, default=Path("oq-report.md"))
    parser.add_argument("--json", type=Path, dest="json_path", default=Path("oq-report.json"))
    parser.add_argument("--pytest-arg", action="append", default=[])
    args = parser.parse_args(argv)

    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--junitxml",
        str(args.junit),
        "--cov=mcp_glp_audit_proxy",
        "--cov-report=term-missing",
        "--cov-report=json:coverage.json",
        *args.pytest_arg,
    ]
    completed = subprocess.run(command, cwd=ROOT, check=False)  # noqa: S603  # nosec B603
    report = build_report(args.junit, pytest_exit=completed.returncode)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json_path.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_text(render_markdown(report), encoding="utf-8")
    args.json_path.write_text(render_json(report), encoding="utf-8")
    print(f"wrote {args.markdown}", file=sys.stderr)
    print(f"wrote {args.json_path}", file=sys.stderr)
    print(f"report_sha256 {report['report_sha256']}", file=sys.stderr)
    if completed.returncode != 0 or report["traceability_problems"]:
        return 1
    return 0


def build_report(junit_path: Path, *, pytest_exit: int) -> dict[str, Any]:
    results = junit_results(junit_path) if junit_path.is_file() else {}
    cases = _cases(junit_path) if junit_path.is_file() else []
    rtm = load_rtm()
    problems = community_gaps(rtm, results) if results else ["junit file missing"]
    passed = sum(1 for case in cases if case["status"] == "pass")
    failed = sum(1 for case in cases if case["status"] != "pass")
    body = {
        "title": "Community verification report",
        "statement": (
            "Evidence that supports a customer's own records. "
            "Designed to support GLP / 21 CFR Part 11 / EU GMP Annex 11 workflows."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": _environment(),
        "pytest_exit": pytest_exit,
        "counts": {
            "tests": len(cases),
            "passed": passed,
            "failed": failed,
            "requirements_community": _count(rtm, "community"),
            "requirements_pro": _count(rtm, "pro"),
            "requirements_customer": _count(rtm, "customer"),
            "requirements_gap": _count(rtm, "gap"),
        },
        "coverage_percent": _coverage_percent(),
        "cases": cases,
        "traceability_problems": problems,
    }
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    body["report_sha256"] = digest
    return body


def render_markdown(report: dict[str, Any]) -> str:
    env = report["environment"]
    counts = report["counts"]
    lines = [
        "# Community verification report",
        "",
        report["statement"],
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Package: mcp-glp-audit-proxy {env['package_version']}",
        f"- Python: {env['python']}",
        f"- OS: {env['os']}",
        f"- Git sha: {env['git_sha']}",
        f"- Tests: {counts['passed']} passed, {counts['failed']} failed, {counts['tests']} total",
        f"- Requirements: {counts['requirements_community']} community, "
        f"{counts['requirements_pro']} out of scope (Pro), "
        f"{counts['requirements_customer']} customer responsibility, "
        f"{counts['requirements_gap']} gap",
        f"- Line coverage: {report['coverage_percent']}",
        "",
        "## Cases",
        "",
        "| Test | Expected | Actual | Time |",
        "|---|---|---|---|",
    ]
    for case in report["cases"]:
        lines.append(
            f"| `{case['id']}` | pass | {case['status']} | {case['time']} |"
        )
    if report["traceability_problems"]:
        lines.extend(["", "## Traceability", ""])
        for problem in report["traceability_problems"]:
            lines.append(f"- {problem}")
    lines.extend(
        [
            "",
            "## Dependencies",
            "",
            "| Name | Version | SHA-256 |",
            "|---|---|---|",
        ]
    )
    for dep in env["dependencies"]:
        lines.append(f"| {dep['name']} | {dep['version']} | `{dep['sha256']}` |")
    lines.extend(["", f"Report SHA-256: `{report['report_sha256']}`", ""])
    text = "\n".join(lines)
    text.encode("ascii")
    return text


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def _cases(path: Path) -> list[dict[str, Any]]:
    tree = ET.parse(path)
    cases: list[dict[str, Any]] = []
    for case in tree.iter("testcase"):
        name = case.get("name") or ""
        file_name = case.get("file") or _file_from_class(case.get("classname") or "")
        status = "pass"
        detail = "pass"
        if case.find("failure") is not None:
            status = "fail"
            detail = (case.find("failure").get("message") or "fail")[:400]
        elif case.find("error") is not None:
            status = "error"
            detail = (case.find("error").get("message") or "error")[:400]
        elif case.find("skipped") is not None:
            status = "skip"
            detail = "skip"
        cases.append(
            {
                "id": f"{file_name}::{name}",
                "expected": "pass",
                "actual": detail if status != "pass" else "pass",
                "status": status,
                "time": case.get("time") or "0",
            }
        )
    return cases


def _file_from_class(classname: str) -> str:
    parts = classname.split(".")
    if len(parts) < 2:
        return classname
    return "/".join(parts[:-1] + [parts[-1] + ".py"])


def _environment() -> dict[str, Any]:
    return {
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "package_version": __version__,
        "git_sha": _git_sha(),
        "dependencies": _dependency_hashes(),
    }


def _git_sha() -> str:
    try:
        git = shutil.which("git")
        if not git:
            return "unknown"
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [git, "rev-parse", "HEAD"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return "unknown"
    if completed.returncode != 0:
        return "unknown"
    return completed.stdout.strip()


def _dependency_hashes() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    wanted = ("mcp", "rfc8785", "pytest", "hypothesis", "jsonschema", "PyYAML")
    seen = {item.metadata["Name"].lower(): item for item in distributions()}
    for name in wanted:
        dist = seen.get(name.lower())
        if dist is None:
            rows.append({"name": name, "version": "missing", "sha256": ""})
            continue
        digest = hashlib.sha256()
        files = dist.files or []
        for file_path in sorted(files, key=lambda item: str(item)):
            try:
                payload = file_path.locate().read_bytes()
            except OSError:
                continue
            digest.update(str(file_path).encode("utf-8"))
            digest.update(payload)
        rows.append(
            {
                "name": name,
                "version": dist.version,
                "sha256": digest.hexdigest(),
            }
        )
    # Touch version() so a missing install fails the same way as the floor check.
    version("mcp")
    return rows


def _coverage_percent() -> str:
    data = ROOT / "coverage.json"
    if data.is_file():
        try:
            parsed = json.loads(data.read_text(encoding="utf-8"))
            percent = parsed.get("totals", {}).get("percent_covered")
            if isinstance(percent, (int, float)):
                return f"{percent:.1f}"
        except json.JSONDecodeError:
            pass
    return "see pytest-cov output"


def _count(rtm: dict[str, Any], scope: str) -> int:
    return sum(1 for item in rtm["requirements"] if item.get("scope") == scope)


def _canonical(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
