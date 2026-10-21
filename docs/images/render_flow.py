#!/usr/bin/env python3
"""Render the README flow diagram.

Edit the strings in this file, then re-run it from a checkout:

    python3 docs/images/render_flow.py

The script writes three files next to itself:

- flow.mmd   editable graph of the same labels
- flow.svg   deterministic picture
- flow.png   2x raster of that SVG, for hosts that do not show SVG

The PNG is drawn with ffmpeg's librsvg when ffmpeg is on PATH, and with
headless Chrome otherwise. Text uses Inter, then Segoe UI, Helvetica, Arial.
The picture has its own light background so it stays readable on a light or
dark page.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
WIDTH = 1280
HEIGHT = 576

INK = "#1c2830"
MUTED = "#4a5963"
LINE = "#2c3d48"
CANVAS = "#f4f2ec"
FRAME = "#d9d3c7"
HOST_FILL = "#f7f8f8"
HOST_STROKE = "#5d6e7a"
PROXY_FILL = "#e6eef0"
PROXY_HEADER = "#1e4652"
CARD = "#ffffff"
CARD_STROKE = "#c5d0d4"
UP_FILL = "#f2f6f0"
UP_STROKE = "#4d674f"
FILE_FILL = "#fffcf7"
FILE_STROKE = "#8d8172"
ANCHOR_FILL = "#f7f1e8"
ANCHOR_STROKE = "#7a624c"
FONT = "Inter, 'Segoe UI', Helvetica, Arial, sans-serif"

# Every ASCII label from the README diagram, plus the file, sidecar, and anchor.
HOST = "host (Claude, Cursor, Grok, self-hosted LLM)"
ARROW_IN = "stdio JSON-RPC"
PROXY = "mcp-glp-audit-proxy"
POLICY = "policy (allow / deny, reason, human approval)"
AUDIT = "audit (append-only JSONL, RFC 8785, SHA-256 chain)"
ARROW_OUT = "stdio or HTTPS (TLS 1.3)"
UPSTREAM = "upstream MCP servers (Excel, ELN, LIMS, databases, instruments)"
CLIENT = "client / agent"
APPROVAL = "approval"
WRITER = "audit writer"
JSONL = "JSONL log"
HEAD = ".head sidecar"
ANCHOR = "off-host anchor"

# Layout. The main path is left to right. The log, sidecar, and anchor sit below.
HOST_BOX = (28, 130, 236, 148)
PROXY_BOX = (430, 20, 400, 368)
UPSTREAM_BOX = (1000, 116, 248, 176)
JSONL_BOX = (446, 424, 176, 104)
HEAD_BOX = (638, 424, 176, 104)
ANCHOR_BOX = (1000, 412, 248, 128)
ARROW_Y = 204


def render_mmd() -> str:
    """Mermaid form of the same graph. The picture is rendered from render_svg."""
    return "\n".join(
        [
            "%% Editable labels live in render_flow.py. Re-run that script to refresh",
            "%% flow.mmd, flow.svg, and flow.png together.",
            "flowchart LR",
            f'  host["{HOST}"]',
            f'  client["{CLIENT}"]',
            f'  subgraph proxy["{PROXY}"]',
            "    direction TB",
            f'    policy["{POLICY}"]',
            f'    approval["{APPROVAL}"]',
            f'    writer["{WRITER}"]',
            f'    audit["{AUDIT}"]',
            "  end",
            f'  upstream["{UPSTREAM}"]',
            f'  jsonl["{JSONL}"]',
            f'  head["{HEAD}"]',
            f'  anchor["{ANCHOR}"]',
            f'  host -->|"{ARROW_IN}"| proxy',
            f'  proxy -->|"{ARROW_OUT}"| upstream',
            "  client --- host",
            "  writer --> audit",
            "  audit --> jsonl",
            "  jsonl --> head",
            "  head --> anchor",
            "",
        ]
    )


def render_svg() -> str:
    """Deterministic SVG. Coordinates are the layout; labels come from the constants."""
    hx, hy, hw, hh = HOST_BOX
    px, py, pw, ph = PROXY_BOX
    ux, uy, uw, uh = UPSTREAM_BOX
    jx, jy, jw, jh = JSONL_BOX
    sx, sy, sw, sh = HEAD_BOX
    ax, ay, aw, ah = ANCHOR_BOX
    parts: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" '
        f'viewBox="0 0 {WIDTH} {HEIGHT}" role="img">',
        f"<title>{_esc(PROXY)} flow</title>",
        "<desc>"
        + _esc(
            f"{CLIENT}. {HOST}. {ARROW_IN}. {PROXY}. {POLICY}. {APPROVAL}. {WRITER}. {AUDIT}. "
            f"{ARROW_OUT}. {UPSTREAM}. {JSONL}. {HEAD}. {ANCHOR}."
        )
        + "</desc>",
        "<defs>",
        '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">',
        f'<path d="M 0 1.2 L 10 5 L 0 8.8 z" fill="{LINE}"/>',
        "</marker>",
        f'<clipPath id="proxy-clip"><rect x="{px}" y="{py}" width="{pw}" height="{ph}" rx="16"/></clipPath>',
        "</defs>",
        f'<rect width="{WIDTH}" height="{HEIGHT}" fill="{CANVAS}"/>',
        f'<rect x="8" y="8" width="{WIDTH - 16}" height="{HEIGHT - 16}" rx="18" fill="none" stroke="{FRAME}"/>',
    ]

    _card(parts, hx, hy, hw, hh, HOST_FILL, HOST_STROKE)
    _kicker(parts, hx + hw // 2, hy + 36, CLIENT)
    _lines(
        parts,
        hx + hw // 2,
        hy + 68,
        ["host (Claude, Cursor,", "Grok, self-hosted LLM)"],
        15,
        INK,
        "600",
    )

    _arrow(parts, hx + hw, ARROW_Y, px, ARROW_Y)
    _lines(parts, (hx + hw + px) // 2, ARROW_Y - 16, [ARROW_IN], 13, MUTED, "500")

    parts.append('<g clip-path="url(#proxy-clip)">')
    parts.append(f'<rect x="{px}" y="{py}" width="{pw}" height="{ph}" fill="{PROXY_FILL}"/>')
    parts.append(f'<rect x="{px}" y="{py}" width="{pw}" height="48" fill="{PROXY_HEADER}"/>')
    parts.append("</g>")
    parts.append(
        f'<rect x="{px}" y="{py}" width="{pw}" height="{ph}" rx="16" fill="none" '
        f'stroke="{PROXY_HEADER}" stroke-width="1.5"/>'
    )
    _lines(parts, px + pw // 2, py + 30, [PROXY], 16, "#ffffff", "600")

    _card(parts, 446, 84, 368, 84, CARD, CARD_STROKE)
    _lines(
        parts,
        630,
        118,
        ["policy (allow / deny,", "reason, human approval)"],
        15,
        INK,
        "500",
    )

    _card(parts, 446, 180, 368, 56, CARD, CARD_STROKE)
    _lines(parts, 630, 213, [APPROVAL], 16, INK, "600")

    _card(parts, 446, 248, 368, 108, CARD, CARD_STROKE)
    _kicker(parts, 630, 276, WRITER)
    _lines(
        parts,
        630,
        304,
        ["audit (append-only JSONL,", "RFC 8785, SHA-256 chain)"],
        15,
        INK,
        "500",
    )

    _arrow(parts, px + pw, ARROW_Y, ux, ARROW_Y)
    _lines(
        parts,
        (px + pw + ux) // 2,
        ARROW_Y - 36,
        ["stdio or HTTPS", "(TLS 1.3)"],
        13,
        MUTED,
        "500",
    )

    _card(parts, ux, uy, uw, uh, UP_FILL, UP_STROKE)
    _lines(
        parts,
        ux + uw // 2,
        uy + 62,
        ["upstream MCP servers", "(Excel, ELN, LIMS,", "databases, instruments)"],
        15,
        INK,
        "500",
    )

    # The audit writer appends the log and then the sidecar. The anchor is the external copy.
    _arrow(parts, jx + jw // 2, 356, jx + jw // 2, jy)
    _arrow(parts, sx + sw // 2, 356, sx + sw // 2, sy)
    _card(parts, jx, jy, jw, jh, FILE_FILL, FILE_STROKE)
    _lines(parts, jx + jw // 2, jy + 46, [JSONL, "append-only"], 15, INK, "600")
    _card(parts, sx, sy, sw, sh, FILE_FILL, FILE_STROKE)
    _lines(parts, sx + sw // 2, sy + 46, [HEAD, "seq, entry_hash"], 15, INK, "600")

    _arrow(parts, sx + sw, ay + ah // 2, ax, ay + ah // 2)
    _lines(parts, (sx + sw + ax) // 2, ay + ah // 2 - 14, ["external copy"], 12, MUTED, "500")
    _card(parts, ax, ay, aw, ah, ANCHOR_FILL, ANCHOR_STROKE)
    _lines(
        parts,
        ax + aw // 2,
        ay + 46,
        [ANCHOR, "ticket, email, or", "LIMS record"],
        15,
        INK,
        "600",
    )

    parts.append("</svg>")
    parts.append("")
    return "\n".join(parts)


def write_all() -> None:
    mmd = HERE / "flow.mmd"
    svg = HERE / "flow.svg"
    png = HERE / "flow.png"
    mmd.write_text(render_mmd(), encoding="utf-8")
    svg.write_text(render_svg(), encoding="utf-8")
    _write_png(svg, png)


def _write_png(svg: Path, png: Path) -> None:
    """Rasterize at 2x. Librsvg keeps the SVG coordinates and uses the width attribute."""
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is not None:
        _write_png_ffmpeg(ffmpeg, svg, png)
        return
    _write_png_chrome(svg, png)


def _write_png_ffmpeg(ffmpeg: str, svg: Path, png: Path) -> None:
    text = svg.read_text(encoding="utf-8")
    text = text.replace(f'width="{WIDTH}"', f'width="{WIDTH * 2}"', 1)
    text = text.replace(f'height="{HEIGHT}"', f'height="{HEIGHT * 2}"', 1)
    with tempfile.TemporaryDirectory() as tmp:
        doubled = Path(tmp) / "flow.svg"
        doubled.write_text(text, encoding="utf-8")
        subprocess.run(
            [ffmpeg, "-y", "-i", str(doubled), "-frames:v", "1", "-update", "1", str(png)],
            check=True,
            capture_output=True,
        )


def _write_png_chrome(svg: Path, png: Path) -> None:
    chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
    if chrome is None:
        raise SystemExit("ffmpeg or Google Chrome is required to rasterize flow.png")
    html = HERE / ".flow-preview.html"
    try:
        html.write_text(
            "\n".join(
                [
                    "<!DOCTYPE html>",
                    '<html><head><meta charset="utf-8">',
                    "<style>",
                    "html,body{margin:0;padding:0;background:#f4f2ec;overflow:hidden}",
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
                "--force-device-scale-factor=2",
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


def _card(parts: list[str], x: int, y: int, w: int, h: int, fill: str, stroke: str) -> None:
    parts.append(
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{fill}" stroke="{stroke}"/>'
    )


def _kicker(parts: list[str], x: int, y: int, text: str) -> None:
    parts.append(
        f'<text x="{x}" y="{y}" text-anchor="middle" fill="{MUTED}" '
        f'font-family="{FONT}" font-size="12" font-weight="600" letter-spacing="0.6">{_esc(text)}</text>'
    )


def _lines(parts: list[str], x: int, y: int, lines: list[str], size: int, fill: str, weight: str) -> None:
    chunks = [
        f'<text x="{x}" y="{y}" text-anchor="middle" fill="{fill}" '
        f'font-family="{FONT}" font-size="{size}" font-weight="{weight}">'
    ]
    for index, line in enumerate(lines):
        dy = 0 if index == 0 else int(size * 1.35)
        chunks.append(f'<tspan x="{x}" dy="{dy}">{_esc(line)}</tspan>')
    chunks.append("</text>")
    parts.append("".join(chunks))


def _arrow(parts: list[str], x1: int, y1: int, x2: int, y2: int) -> None:
    parts.append(
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{LINE}" stroke-width="1.5" '
        f'marker-end="url(#arrow)"/>'
    )


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


if __name__ == "__main__":
    write_all()
    print(f"wrote {HERE / 'flow.mmd'}")
    print(f"wrote {HERE / 'flow.svg'}")
    print(f"wrote {HERE / 'flow.png'}")
    sys.exit(0)
