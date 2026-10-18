"""Refuse to run on an mcp SDK build affected by GHSA-84m7-p3x7-pcfv."""

from __future__ import annotations

from importlib.metadata import version


# Affected ranges: >=1.8.0,<1.30.0 and >=2.0.0,<2.2.0.
# This package stays on the patched 2.x line and below 3.
_MIN = (2, 2, 0)
_MAX_EXCLUSIVE = (3, 0, 0)


def parse_version(value: str) -> tuple[int, int, int]:
    parts: list[int] = []
    for piece in value.split(".")[:3]:
        digits = ""
        for char in piece:
            if char.isdigit():
                digits += char
            else:
                break
        parts.append(int(digits or "0"))
    while len(parts) < 3:
        parts.append(0)
    return parts[0], parts[1], parts[2]


def assert_mcp_floor() -> tuple[int, int, int]:
    """Import mcp and reject versions inside GHSA-84m7-p3x7-pcfv."""
    import mcp  # noqa: F401  # the dependency is required at runtime

    raw = version("mcp")
    parsed = parse_version(raw)
    if parsed < _MIN or parsed >= _MAX_EXCLUSIVE:
        raise RuntimeError(
            f"mcp {raw} is outside the supported window >=2.2.0,<3. "
            "GHSA-84m7-p3x7-pcfv affects 1.8.0 through 1.29.1 and 2.0.0 through 2.1.1."
        )
    return parsed
