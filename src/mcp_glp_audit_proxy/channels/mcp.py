"""MCP channel. Stdio in, stdio or HTTPS MCP upstreams out.

The implementation stays in ``server``, ``proxy``, and ``upstream`` so the
existing entry points and tests keep their import paths. This module is the
adapter name those pieces are reached by.
"""

from __future__ import annotations

from ..server import build_proxy, serve_stdio

__all__ = ["build_proxy", "serve_stdio"]
