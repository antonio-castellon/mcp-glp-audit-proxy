"""Load the requirements traceability matrix and check it against a JUnit file."""

from __future__ import annotations

import sys
import defusedxml.ElementTree as ET
from pathlib import Path
from typing import Any

import yaml

COMMUNITY_SCOPES = frozenset({"community"})
_CHECKOUT_MESSAGE = (
    "OQ runner: this command needs a source checkout. "
    "It runs pytest on tests/ and reads docs/verification/rtm.yaml. "
    "A PyPI install does not include that tree. "
    "Pass --repo-root PATH to the repository root, or run it from a clone."
)


class CheckoutError(Exception):
    """The OQ runner was not pointed at a source checkout."""


def is_checkout(root: Path) -> bool:
    return (root / "docs" / "verification" / "rtm.yaml").is_file() and (root / "tests").is_dir()


def checkout_root(explicit: Path | None = None) -> Path:
    """Return a repository root that contains the suite and the matrix.

    An editable install is found from this file. A wheel is not: pass
    ``explicit`` or run the command from a clone. Anything else raises
    CheckoutError before pytest starts.
    """
    if explicit is not None:
        root = explicit.expanduser().resolve()
        if not is_checkout(root):
            raise CheckoutError(_CHECKOUT_MESSAGE)
        return root
    candidates: list[Path] = []
    parents = Path(__file__).resolve().parents
    if len(parents) > 3:
        candidates.append(parents[3])
    candidates.append(Path.cwd())
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if is_checkout(resolved):
            return resolved
    raise CheckoutError(_CHECKOUT_MESSAGE)


def load_rtm(path: Path | None = None) -> dict[str, Any]:
    target = path or (checkout_root() / "docs" / "verification" / "rtm.yaml")
    raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("requirements"), list):
        raise ValueError("rtm.yaml must contain a requirements list")
    return raw


def junit_results(path: Path) -> dict[str, str]:
    """Map pytest node id -> pass|fail|skip|error."""
    tree = ET.parse(path)
    found: dict[str, str] = {}
    for case in tree.iter("testcase"):
        classname = case.get("classname") or ""
        name = case.get("name") or ""
        file_name = case.get("file")
        if file_name:
            node = f"{file_name}::{name}"
        else:
            module = classname.replace(".", "/")
            node = f"{module}.py::{name}"
        status = "pass"
        if case.find("failure") is not None:
            status = "fail"
        elif case.find("error") is not None:
            status = "error"
        elif case.find("skipped") is not None:
            status = "skip"
        found[node] = status
        # Also accept the classname form pytest uses in some versions.
        found[f"{classname}::{name}"] = status
    return found


def community_gaps(rtm: dict[str, Any], results: dict[str, str]) -> list[str]:
    """Community rows must point at tests that passed in this run."""
    problems: list[str] = []
    for item in rtm["requirements"]:
        scope = item.get("scope")
        if scope not in COMMUNITY_SCOPES:
            continue
        tests = item.get("tests") or []
        ident = item.get("id")
        if not tests:
            problems.append(f"{ident}: community requirement has no test")
            continue
        for test_id in tests:
            status = results.get(test_id)
            if status is None:
                problems.append(f"{ident}: test not in the junit file: {test_id}")
            elif status != "pass":
                problems.append(f"{ident}: test {test_id} is {status}")
    return problems


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m mcp_glp_audit_proxy.verification.rtm JUNIT.xml", file=sys.stderr)
        return 2
    try:
        matrix_path = checkout_root() / "docs" / "verification" / "rtm.yaml"
        problems = community_gaps(load_rtm(matrix_path), junit_results(Path(args[0])))
    except CheckoutError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print(f"traceability ok ({matrix_path})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
