"""python -m mcp_glp_audit_proxy.verification"""

from __future__ import annotations

from .oq import main


def run() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    run()
