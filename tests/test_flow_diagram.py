"""The README flow picture keeps every label from the old ASCII diagram."""

from __future__ import annotations

import importlib.util
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = ROOT / "docs" / "images"
RAW = "https://raw.githubusercontent.com/antonio-castellon/mcp-glp-audit-proxy/main/docs/images"

PHRASES = (
    "host (Claude, Cursor, Grok, self-hosted LLM)",
    "stdio JSON-RPC",
    "mcp-glp-audit-proxy",
    "policy (allow / deny, reason, human approval)",
    "audit (append-only JSONL, RFC 8785, SHA-256 chain)",
    "stdio or HTTPS (TLS 1.3)",
    "upstream MCP servers (Excel, ELN, LIMS, databases, instruments)",
    "client / agent",
    "approval",
    "audit writer",
    "JSONL log",
    ".head sidecar",
    "off-host anchor",
)


def _renderer():
    path = IMAGES / "render_flow.py"
    spec = importlib.util.spec_from_file_location("render_flow", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _visible(svg: str) -> str:
    text = re.sub(r"<[^>]+>", " ", svg)
    return re.sub(r"\s+", " ", text)


def test_committed_picture_matches_the_renderer() -> None:
    module = _renderer()
    svg = (IMAGES / "flow.svg").read_text(encoding="utf-8")
    mmd = (IMAGES / "flow.mmd").read_text(encoding="utf-8")
    assert svg == module.render_svg()
    assert mmd == module.render_mmd()
    visible = _visible(svg)
    for phrase in PHRASES:
        assert phrase in visible
        assert phrase in mmd
    png = (IMAGES / "flow.png").read_bytes()
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    width, height = struct.unpack(">II", png[16:24])
    assert (width, height) == (module.WIDTH * 2, module.HEIGHT * 2)


def test_readme_uses_the_absolute_picture_and_drops_the_ascii_fence() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme.encode("ascii")
    assert f"{RAW}/flow.svg" in readme
    assert f"{RAW}/flow.png" in readme
    assert 'type="image/svg+xml"' in readme
    for phrase in PHRASES:
        assert phrase in readme
    assert "|  stdio JSON-RPC" not in readme
    assert "|  stdio or HTTPS (TLS 1.3)" not in readme
    assert "github.io" not in readme.lower()
