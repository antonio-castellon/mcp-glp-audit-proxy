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
    assert "https://github.com/antonio-castellon/mcp-glp-audit-proxy-pro" in readme
    assert "(private, access for licensed customers)" in readme
    assert "mailto:antonio@castellon.ch" in readme
    assert "GLP Lab Data Pack" in readme
    assert "Community" in readme and "Pro" in readme
    coverage = (ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    coverage_lower = coverage.lower()
    assert "certified" not in coverage_lower
    assert "compliant" not in coverage_lower
    assert "mailto:antonio@castellon.ch" in coverage
    assert "(private, access for licensed customers)" in coverage
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
    assert server["version"] == "0.1.0"
    assert len(server["description"]) <= 100
    assert 'version = "0.1.0"' in pyproject
    assert "mcp>=2.2.0,<3" in pyproject
    assert (ROOT / "docs" / "STANDARDS.md").is_file()
    assert (ROOT / "docs" / "COVERAGE.md").is_file()
    assert (ROOT / "schema" / "audit-record.schema.json").is_file()
    assert (ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")
