"""Channel adapters. The hash chain does not know which socket the call used.

``mcp`` is the stdio JSON-RPC adapter (and the existing HTTPS MCP upstream).
``https_inbound`` is the TLS 1.3 reverse proxy. ``https_outbound`` calls an
HTTPS API or an OpenAI-compatible LLM API. ``api_upstream`` exposes those
calls as MCP tools.

The core modules (canonical JSON, the hash chain, JSONL storage, anchors,
checkpoints, the verify CLI, plugin interfaces, features, wiring, reporters,
and the policy and approval engine) stay importable at their existing paths.
"""

from __future__ import annotations

__all__ = ["mcp"]
