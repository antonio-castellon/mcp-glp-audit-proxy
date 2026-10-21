"""python -m mcp_glp_audit_proxy - start the stdio MCP proxy."""

from __future__ import annotations


def main() -> None:
    import sys

    # Same runner as the mcp-glp-audit-proxy-oq console script.
    if len(sys.argv) > 1 and sys.argv[1] == "oq-report":
        from .verification.oq import main as report

        raise SystemExit(report(sys.argv[2:]))
    from .server import main as run

    run()


if __name__ == "__main__":
    main()
