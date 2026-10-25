"""Offline `segment close`. The proxy must be stopped. The old file is not deleted."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import load_settings
from .errors import ConfigurationError
from .segments import close_segment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-glp-audit-proxy segment")
    sub = parser.add_subparsers(dest="command")
    close = sub.add_parser("close")
    close.add_argument("--config", type=Path, required=True)
    close.add_argument("--reason", default="")
    close.add_argument("--ticket", default="")
    close.add_argument("--approved-by", default="")
    close.add_argument("--output", type=Path, default=None)
    close.add_argument("--previous", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.command != "close":
        parser.print_help(sys.stderr)
        return 2
    if not str(args.reason).strip() or not str(args.approved_by).strip() or not str(args.ticket).strip():
        print(
            "segment close requires --reason, --ticket, and --approved-by",
            file=sys.stderr,
        )
        return 2
    try:
        settings = load_settings(args.config)
        destination = close_segment(
            settings,
            reason=str(args.reason),
            ticket=str(args.ticket),
            approved_by=str(args.approved_by),
            previous=args.previous,
            output=args.output,
        )
    except (ConfigurationError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(destination)
    return 0
