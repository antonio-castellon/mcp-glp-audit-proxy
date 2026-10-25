"""Run the suite and write a verification report.

The report is evidence a customer can attach to their own records. It is
designed to support GLP / 21 CFR Part 11 / EU GMP Annex 11 workflows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
from .rtm import CheckoutError, checkout_root, community_gaps, junit_results, load_rtm

CHAIN_SMOKE = "tests/test_chain.py::test_chain_links_and_matches_schema"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-glp-audit-proxy-oq",
        description=(
            "Run the Community verification report. "
            "mcp-glp-audit-proxy-oq and `mcp-glp-audit-proxy oq-report` "
            "call this same runner. Neither name is deprecated."
        ),
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help=(
            "Repository root that contains tests/ and docs/verification/rtm.yaml. "
            "Required when this install is not a source checkout."
        ),
    )
    parser.add_argument("--junit", type=Path, default=Path("junit.xml"))
    parser.add_argument("--markdown", type=Path, default=Path("oq-report.md"))
    parser.add_argument("--json", type=Path, dest="json_path", default=Path("oq-report.json"))
    parser.add_argument("--coverage-json", type=Path, default=Path("coverage.json"))
    parser.add_argument("--pytest-arg", action="append", default=[])
    parser.add_argument(
        "--requirement",
        action="append",
        default=[],
        help="Run only the tests mapped to this RTM id, plus the chain smoke test. Repeatable.",
    )
    args = parser.parse_args(argv)
    try:
        root = checkout_root(args.repo_root)
    except CheckoutError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    subset = [item.strip() for item in args.requirement if item.strip()]
    selected: list[str] = []
    if subset:
        try:
            matrix = load_rtm(root / "docs" / "verification" / "rtm.yaml")
        except (OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        known = {item.get("id") for item in matrix["requirements"]}
        for ident in subset:
            if ident not in known:
                print(f"unknown requirement: {ident}", file=sys.stderr)
                return 2
        selected = tests_for(matrix, subset)
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--junitxml",
        str(args.junit),
        "--cov=mcp_glp_audit_proxy",
        "--cov-report=term-missing",
        "--cov-report=json:" + str(args.coverage_json),
        *(selected if subset else args.pytest_arg),
    ]
    # The nested suite must not write into this process's coverage data.
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("COVERAGE") or key.startswith("COV_"):
            env.pop(key, None)
    completed = subprocess.run(command, cwd=root, check=False, env=env)  # noqa: S603  # nosec B603
    coverage_path = args.coverage_json if args.coverage_json.is_absolute() else root / args.coverage_json
    report = build_report(
        args.junit,
        pytest_exit=completed.returncode,
        coverage_path=coverage_path,
        root=root,
        requirement_subset=subset,
    )
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


def tests_for(rtm: dict[str, Any], identifiers: list[str]) -> list[str]:
    """Mapped tests for the named RTM ids, plus the chain smoke test."""
    wanted = set(identifiers)
    nodes: list[str] = []
    for item in rtm["requirements"]:
        if item.get("id") not in wanted:
            continue
        for test_id in item.get("tests") or []:
            if test_id not in nodes:
                nodes.append(test_id)
    if CHAIN_SMOKE not in nodes:
        nodes.append(CHAIN_SMOKE)
    return nodes


def build_report(
    junit_path: Path,
    *,
    pytest_exit: int,
    coverage_path: Path | None = None,
    root: Path | None = None,
    requirement_subset: list[str] | None = None,
) -> dict[str, Any]:
    results = junit_results(junit_path) if junit_path.is_file() else {}
    cases = _cases(junit_path) if junit_path.is_file() else []
    rtm = load_rtm()
    subset = list(requirement_subset or [])
    if subset:
        wanted = set(subset)
        rtm = {
            **rtm,
            "requirements": [item for item in rtm["requirements"] if item.get("id") in wanted],
        }
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
        "environment": _environment(root),
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
        "coverage_percent": _coverage_percent(coverage_path),
        "cases": cases,
        "requirement_subset": subset,
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
    ]
    if report.get("requirement_subset"):
        lines.append("- Requirement subset: " + ", ".join(report["requirement_subset"]))
    lines.extend(
        [
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
    )
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


def _environment(root: Path | None = None) -> dict[str, Any]:
    return {
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "package_version": __version__,
        "git_sha": _git_sha(root),
        "dependencies": _dependency_hashes(),
    }


def _git_sha(root: Path | None = None) -> str:
    if root is None:
        try:
            root = checkout_root()
        except CheckoutError:
            return "unknown"
    try:
        git = shutil.which("git")
        if not git:
            return "unknown"
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [git, "rev-parse", "HEAD"],
            cwd=root,
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


def _coverage_percent(path: Path | None) -> str:
    if path is None or not path.is_file():
        return "see pytest-cov output"
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "see pytest-cov output"
    percent = parsed.get("totals", {}).get("percent_covered") if isinstance(parsed, dict) else None
    if isinstance(percent, (int, float)):
        return f"{percent:.1f}"
    return "see pytest-cov output"


def _count(rtm: dict[str, Any], scope: str) -> int:
    return sum(1 for item in rtm["requirements"] if item.get("scope") == scope)


def _canonical(body: dict[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
