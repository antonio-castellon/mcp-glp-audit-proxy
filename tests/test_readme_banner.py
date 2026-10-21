"""README banner, shields, and the short repo-hygiene pages."""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "docs" / "images"
RAW = "https://raw.githubusercontent.com/antonio-castellon/mcp-glp-audit-proxy/main/docs/images"
NAME = "mcp-glp-audit-proxy"
TAGLINE = "Tamper-evident audit trail for MCP tool calls - Community edition"


def _renderer():
    path = IMAGES / "render_banner.py"
    spec = importlib.util.spec_from_file_location("render_banner", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_banner_matches_the_renderer() -> None:
    module = _renderer()
    svg = (IMAGES / "banner.svg").read_text(encoding="utf-8")
    assert svg == module.render_svg()
    assert NAME in svg
    assert TAGLINE in svg
    assert "certified" not in svg.lower()
    assert "compliant" not in svg.lower()
    png = (IMAGES / "banner.png").read_bytes()
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    width, height = struct.unpack(">II", png[16:24])
    assert (width, height) == (module.WIDTH, module.HEIGHT)
    assert (module.WIDTH, module.HEIGHT) == (1280, 320)


def test_readme_top_is_badges_then_banner_then_title() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme.encode("ascii")
    assert readme.startswith("mcp-name: io.github.antonio-castellon/mcp-glp-audit-proxy\n")
    badges = readme.index("https://img.shields.io/github/v/release/antonio-castellon/mcp-glp-audit-proxy")
    licence = readme.index('href="LICENSE"')
    python = readme.index("python-3.11%20%7C%203.12%20%7C%203.13")
    mcp = readme.index("MCP-proxy-1e4652")
    banner = readme.index(f"{RAW}/banner.png")
    svg = readme.index(f"{RAW}/banner.svg")
    title = readme.index("\n# mcp-glp-audit-proxy\n")
    assert badges < licence < python < mcp < svg < banner < title
    assert TAGLINE in readme
    assert "docs/images/flow.png" in readme
    assert "github.io" not in readme.lower()
    lowered = readme.lower()
    assert "certified" not in lowered
    assert "compliant" not in lowered


def test_hygiene_pages_are_english_and_ascii() -> None:
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    conduct = (ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    for text in (contributing, conduct, security):
        text.encode("ascii")
        lowered = text.lower()
        assert "certified" not in lowered
        assert "compliant" not in lowered
    assert "Open an issue first" in contributing
    assert "Branch from `main`" in contributing
    assert "secrets or tokens" in contributing
    assert "Tests and CI must stay green" in contributing
    assert "read-only by default" in contributing
    assert "allowlists" in contributing
    assert "Criticise the code, not the person" in conduct
    assert "privately via GitHub" in conduct
    assert "Never paste tokens or keys" in security
    assert "Advisories" in security
    assert "not in an open issue" in security
    assert "version and the client" in security
    assert not (ROOT / "NOTICE").exists()
    assert not (ROOT / "NOTICE.md").exists()
    assert (ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License\n")
