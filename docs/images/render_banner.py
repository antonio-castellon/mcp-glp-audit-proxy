#!/usr/bin/env python3
"""Render the README application banner.

Edit the strings in this file, then re-run it from a checkout:

    python3 docs/images/render_banner.py

The script writes two files next to itself:

- banner.svg   deterministic picture, 1280 by 320
- banner.png   raster of that SVG at the same size, for hosts that do not show SVG

The PNG is drawn with ffmpeg's librsvg when ffmpeg is on PATH, and with
headless Chrome otherwise. Text uses Inter, then Segoe UI, Helvetica, Arial.
The banner has its own dark background so the light type stays readable on
a light or dark page.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
WIDTH = 1280
HEIGHT = 320

# Same ink and paper as the flow diagram, inverted for a header band.
INK = "#1c2830"
PAPER = "#f4f2ec"
FIELD = "#1b3c48"
FIELD_EDGE = "#2d5563"
NAME_COLOR = "#f6f4ef"
TAG_COLOR = "#d3e0e4"
MOTIF = "#d5e2e6"
CARD_LINE = "#d9d3c7"
HEADER = "#1e4652"
MUTED = "#4a5963"
FONT = "Inter, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "'DejaVu Sans Mono', ui-monospace, Consolas, monospace"

NAME = "mcp-glp-audit-proxy"
TAGLINE = "Tamper-evident audit trail for MCP tool calls - Community edition"

# Decorative chain. Eight hex digits, not a real entry hash.
LINKS = (
    ("01", "a3f1c90e"),
    ("02", "9c02b71d"),
    ("03", "71be44aa"),
    ("04", "e4d80c15"),
)


def render_svg() -> str:
    """Deterministic SVG. The name and tagline are single text lines."""
    parts: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}" role="img">',
        f"<title>{_esc(NAME)}</title>",
        f"<desc>{_esc(TAGLINE)}. Hash chain and shield.</desc>",
        f'<rect width="{WIDTH}" height="{HEIGHT}" fill="{FIELD}"/>',
        f'<rect x="0" y="{HEIGHT - 3}" width="{WIDTH}" height="3" fill="{FIELD_EDGE}"/>',
        f'<text x="64" y="142" fill="{NAME_COLOR}" font-family="{FONT}" '
        f'font-size="46" font-weight="600">{_esc(NAME)}</text>',
        f'<text x="64" y="188" fill="{TAG_COLOR}" font-family="{FONT}" '
        f'font-size="20" font-weight="500">{_esc(TAGLINE)}</text>',
    ]
    _shield(parts, 760, 104, 78, 104)
    _chain(parts, 862, 116)
    parts.append("</svg>")
    parts.append("")
    return "\n".join(parts)


def _shield(parts: list[str], x: int, y: int, w: int, h: int) -> None:
    """A plain shield with three linked nodes. No wordmark inside."""
    right = x + w
    mid = x + w / 2
    top = y + 8
    path = (
        f"M {mid:.1f} {y + h:.1f} "
        f"C {x + w * 0.18:.1f} {y + h * 0.74:.1f} {x:.1f} {y + h * 0.56:.1f} {x:.1f} {y + h * 0.34:.1f} "
        f"L {x:.1f} {top + 6:.1f} "
        f"Q {x:.1f} {y:.1f} {x + w * 0.16:.1f} {y:.1f} "
        f"L {x + w * 0.84:.1f} {y:.1f} "
        f"Q {right:.1f} {y:.1f} {right:.1f} {top + 6:.1f} "
        f"L {right:.1f} {y + h * 0.34:.1f} "
        f"C {right:.1f} {y + h * 0.56:.1f} {x + w * 0.82:.1f} {y + h * 0.74:.1f} {mid:.1f} {y + h:.1f} Z"
    )
    parts.append(f'<path d="{path}" fill="#245566" stroke="{MOTIF}" stroke-width="1.5"/>')
    nodes = (mid - 16, mid, mid + 16)
    node_y = y + 42
    parts.append(
        f'<line x1="{nodes[0]:.1f}" y1="{node_y}" x2="{nodes[2]:.1f}" y2="{node_y}" '
        f'stroke="{MOTIF}" stroke-width="1.5"/>'
    )
    for node_x in nodes:
        parts.append(
            f'<circle cx="{node_x:.1f}" cy="{node_y}" r="3.2" fill="{PAPER}"/>'
        )


def _chain(parts: list[str], x: int, y: int) -> None:
    card_w = 84
    card_h = 80
    gap = 16
    for index, (seq, digest) in enumerate(LINKS):
        left = x + index * (card_w + gap)
        if index:
            joint = left - gap
            mid_y = y + card_h / 2
            parts.append(
                f'<line x1="{joint}" y1="{mid_y}" x2="{left}" y2="{mid_y}" '
                f'stroke="{MOTIF}" stroke-width="1.5"/>'
            )
        parts.append(f'<clipPath id="card-{index}"><rect x="{left}" y="{y}" width="{card_w}" height="{card_h}" rx="8"/></clipPath>')
        parts.append(f'<g clip-path="url(#card-{index})">')
        parts.append(
            f'<rect x="{left}" y="{y}" width="{card_w}" height="{card_h}" fill="{PAPER}"/>'
        )
        parts.append(
            f'<rect x="{left}" y="{y}" width="{card_w}" height="7" fill="{HEADER}"/>'
        )
        parts.append("</g>")
        parts.append(
            f'<rect x="{left}" y="{y}" width="{card_w}" height="{card_h}" rx="8" '
            f'fill="none" stroke="{CARD_LINE}"/>'
        )
        cx = left + card_w / 2
        parts.append(
            f'<text x="{cx}" y="{y + 32}" text-anchor="middle" fill="{MUTED}" '
            f'font-family="{MONO}" font-size="12">{seq}</text>'
        )
        parts.append(
            f'<text x="{cx}" y="{y + 58}" text-anchor="middle" fill="{INK}" '
            f'font-family="{MONO}" font-size="13">{digest}</text>'
        )


def write_all() -> None:
    svg = HERE / "banner.svg"
    png = HERE / "banner.png"
    svg.write_text(render_svg(), encoding="utf-8")
    _write_png(svg, png)


def _write_png(svg: Path, png: Path) -> None:
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is not None:
        subprocess.run(
            [ffmpeg, "-y", "-i", str(svg), "-frames:v", "1", "-update", "1", str(png)],
            check=True,
            capture_output=True,
        )
        return
    _write_png_chrome(svg, png)


def _write_png_chrome(svg: Path, png: Path) -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
    if chrome is None:
        raise SystemExit("ffmpeg or Google Chrome is required to rasterize banner.png")
    html = HERE / ".banner-preview.html"
    try:
        html.write_text(
            "\n".join(
                [
                    "<!DOCTYPE html>",
                    '<html><head><meta charset="utf-8">',
                    "<style>",
                    "html,body{margin:0;padding:0;background:#1b3c48;overflow:hidden}",
                    f"img{{display:block;width:{WIDTH}px;height:{HEIGHT}px;border:0}}",
                    "</style></head>",
                    f'<body><img src="{svg.name}" width="{WIDTH}" height="{HEIGHT}" alt=""></body>',
                    "</html>",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        subprocess.run(
            [
                chrome,
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--hide-scrollbars",
                "--virtual-time-budget=4000",
                "--timeout=8000",
                "--force-device-scale-factor=1",
                f"--screenshot={png}",
                f"--window-size={WIDTH},{HEIGHT}",
                html.as_uri(),
            ],
            check=True,
            cwd=HERE,
            timeout=25,
        )
    finally:
        html.unlink(missing_ok=True)


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


if __name__ == "__main__":
    write_all()
    print(f"wrote {HERE / 'banner.svg'}")
    print(f"wrote {HERE / 'banner.png'}")
    sys.exit(0)
