"""README, registry metadata, and the open-core boundary."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PRO_IMPORTS = (
    "psycopg",
    "boto3",
    "reportlab",
    "nacl",
    "botocore",
    "pymssql",
    "pyodbc",
)


def test_readme_is_ascii_and_states_the_boundary() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme.encode("ascii")
    assert readme.startswith("mcp-name: io.github.antonio-castellon/mcp-glp-audit-proxy\n")
    assert "## Regulatory coverage" in readme
    assert "designed to support" in readme
    lowered = readme.lower()
    assert "certified" not in lowered
    assert "compliant" not in lowered
    assert "github.io" not in lowered
    private_pro = "https://github.com/antonio-castellon/" + "mcp-glp-audit-proxy-pro"
    assert private_pro not in readme
    assert "private, access for licensed customers" not in readme
    assert "Pro is available as a licensed / paid service" in readme
    assert "mailto:antonio@castellon.ch" in readme
    assert "GLP Lab Data Pack" in readme
    assert "Community" in readme and "Pro" in readme
    coverage = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    coverage_lower = coverage.lower()
    assert "certified" not in coverage_lower
    assert "compliant" not in coverage_lower
    assert private_pro not in coverage
    assert "Pro is available as a licensed / paid service" in coverage
    assert "mailto:antonio@castellon.ch" in coverage
    forbidden = private_pro
    text_suffixes = {".md", ".py", ".json", ".toml", ".yml", ".yaml", ".txt", ".example"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in text_suffixes:
            continue
        if any(part in {".git", "__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8")
        assert forbidden not in text, path
    safety = (ROOT / "SAFETY.md").read_text(encoding="utf-8")
    safety.encode("ascii")
    assert "certified compliant" not in safety
    plugins = (ROOT / "docs" / "PLUGINS.md").read_text(encoding="utf-8")
    plugins.encode("ascii")


def test_source_has_no_pro_implementations() -> None:
    src = ROOT / "src"
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "certified compliant" not in text
        for name in PRO_IMPORTS:
            assert f"import {name}" not in text
            assert f"from {name}" not in text


def test_registry_metadata_matches_the_package() -> None:
    server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert server["name"] == "io.github.antonio-castellon/mcp-glp-audit-proxy"
    assert server["version"] == "0.3.2"
    assert server["packages"][0]["version"] == "0.3.2"
    assert len(server["description"]) <= 100
    assert 'version = "0.3.2"' in pyproject
    init = (ROOT / "src" / "mcp_glp_audit_proxy" / "__init__.py").read_text(encoding="utf-8")
    assert '__version__ = "0.3.2"' in init
    assert "mcp>=2.2.0,<3" in pyproject
    assert (ROOT / "docs" / "STANDARDS.md").is_file()
    assert (ROOT / "docs" / "COVERAGE.md").is_file()
    assert (ROOT / "schema" / "audit-record.schema.json").is_file()
    assert (ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")


def test_community_pro_table_is_filled() -> None:
    """Every Community/Pro cell has a mark. Pro includes each Community capability."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index("| Capability | Community (this repo) | Pro (licensed service) |")
    rows = []
    for line in readme[start:].splitlines()[2:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        assert len(cells) == 3, line
        rows.append(cells)
    assert len(rows) >= 20
    has = ":white_check_mark:"
    lacks = ":x:"
    for capability, community, pro in rows:
        assert capability
        for cell in (community, pro):
            assert cell.startswith(has) or cell.startswith(lacks), cell
            assert cell.strip() not in {"", "yes", "later"}
        assert "planned" not in community and "planned" not in pro
        assert community in {has, lacks}, capability
        if capability == "FIPS 140-3 mode":
            assert pro == ":x: on request"
        else:
            assert pro.startswith(has), capability
        if community == has:
            assert pro.startswith(has), capability
    by_name = {capability: (community, pro) for capability, community, pro in rows}
    for name in (
        "DE / FR / EN report templates",
        "Old/new value capture for write tools",
        "Merkle log with inclusion / consistency proofs",
        "OpenTelemetry spans (technical telemetry, not the audit record)",
    ):
        assert by_name[name] == (":x:", ":white_check_mark:"), name
    # The capability table lives in the README only.
    for path in (ROOT / "docs").rglob("*.md"):
        text = path.read_text(encoding="utf-8")
        assert "Proxy core, both protocol eras" not in text
