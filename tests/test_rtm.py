"""The traceability file must name real tests for every community row."""

from __future__ import annotations

from pathlib import Path

from mcp_glp_audit_proxy.verification.rtm import load_rtm

ROOT = Path(__file__).resolve().parents[1]
BANNED = ("certified", "compliant", "validated")


def test_community_rows_name_real_tests() -> None:
    rtm = load_rtm()
    seen: set[str] = set()
    for item in rtm["requirements"]:
        ident = item["id"]
        assert ident not in seen
        seen.add(ident)
        scope = item["scope"]
        assert scope in {"community", "pro", "customer", "gap"}
        blob = f"{item['statement']} {item['source']}".lower()
        for word in BANNED:
            assert word not in blob
        if scope != "community":
            assert item["tests"] == []
            continue
        assert item["tests"], ident
        assert item["modules"]
        for test_id in item["tests"]:
            path, _, name = test_id.partition("::")
            file_path = ROOT / path
            assert file_path.is_file(), test_id
            assert f"def {name}" in file_path.read_text(encoding="utf-8"), test_id


def test_verification_docs_avoid_banned_words() -> None:
    paths = [
        ROOT / "docs" / "verification" / "RTM.md",
        ROOT / "docs" / "verification" / "rtm.yaml",
        ROOT / "docs" / "verification" / "SECURITY_REVIEW.md",
    ]
    paths.extend((ROOT / "src" / "mcp_glp_audit_proxy" / "verification").rglob("*.py"))
    for path in paths:
        text = path.read_text(encoding="utf-8").lower()
        text.encode("ascii")
        for word in BANNED:
            assert word not in text, f"{word} in {path}"
