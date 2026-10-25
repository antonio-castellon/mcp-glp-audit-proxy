"""python -m mcp_glp_audit_proxy - start the stdio MCP proxy."""

from __future__ import annotations


def main() -> None:
    import sys

    # Same runner as the mcp-glp-audit-proxy-oq console script.
    if len(sys.argv) > 1 and sys.argv[1] == "oq-report":
        from .verification.oq import main as report

        raise SystemExit(report(sys.argv[2:]))
    # Same runner as the mcp-glp-audit-proxy-verify console script.
    if len(sys.argv) > 1 and sys.argv[1] == "verify":
        from .cli import main as verify

        raise SystemExit(verify(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        from .wizard import init_main

        raise SystemExit(init_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "config":
        from .wizard import config_main

        raise SystemExit(config_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "regulatory-report":
        from .regulatory import main as regulatory_main

        raise SystemExit(regulatory_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "archive-manifest":
        from .archive import main as archive_main

        raise SystemExit(archive_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "segment":
        from .segments_cli import main as segment_main

        raise SystemExit(segment_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "review":
        from .review import main as review_main

        raise SystemExit(review_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "archive-transfer":
        from .archive import transfer_main

        raise SystemExit(transfer_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "verify-run-log":
        from .runlog import main as runlog_main

        raise SystemExit(runlog_main(sys.argv[2:]))
    from .server import main as run

    run()


if __name__ == "__main__":
    main()
