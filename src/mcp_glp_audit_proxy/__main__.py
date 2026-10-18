"""python -m mcp_glp_audit_proxy - start the stdio MCP proxy."""

from __future__ import annotations


def main() -> None:
    from .server import main as run

    run()


if __name__ == "__main__":
    main()
