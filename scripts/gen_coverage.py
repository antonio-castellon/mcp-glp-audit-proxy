"""Compare docs/COVERAGE.md with the regulatory map.

The map is the source for ids, clauses, and editions. This script fails when
the coverage table drifts from that map. It does not rewrite the prose.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / "docs" / "COVERAGE.md"
MAP = ROOT / "src" / "mcp_glp_audit_proxy" / "data" / "regulatory_map.json"
_ROW = re.compile(r"^\| (\d+) \|")


def coverage_rows(text: str | None = None) -> list[dict[str, str]]:
    body = text if text is not None else COVERAGE.read_text(encoding="utf-8")
    rows = []
    for line in body.splitlines():
        if _ROW.match(line) is None:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 7 or not cells[0].isdigit():
            continue
        clause = cells[2]
        matched = re.match(r"\[([^\]]+)\]", clause)
        rows.append(
            {
                "clause": matched.group(1) if matched else clause,
                "edition": cells[5],
                "id": cells[0],
                "instrument": cells[1],
            }
        )
    return rows


def drift() -> list[str]:
    mapping = json.loads(MAP.read_text(encoding="utf-8"))
    by_id = {str(entry["id"]): entry for entry in mapping["entries"]}
    problems = []
    seen: set[str] = set()
    for row in coverage_rows():
        seen.add(row["id"])
        entry = by_id.get(row["id"])
        if entry is None:
            problems.append(f"coverage id {row['id']} is missing from the regulatory map")
            continue
        if str(entry.get("clause")) != row["clause"]:
            problems.append(
                f"id {row['id']} clause {entry.get('clause')!r} != coverage {row['clause']!r}"
            )
        if str(entry.get("edition")) != row["edition"]:
            problems.append(
                f"id {row['id']} edition {entry.get('edition')!r} != coverage {row['edition']!r}"
            )
    for ident in by_id:
        if ident not in seen:
            problems.append(f"regulatory map id {ident} is missing from COVERAGE.md")
    instruments = " ".join(row["instrument"] for row in coverage_rows())
    if "AGIT Archiving" not in instruments or "AGIT Acquisition" not in instruments:
        problems.append("COVERAGE.md does not name both AGIT documents")
    return problems


def main() -> int:
    problems = drift()
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print(f"coverage matches {MAP.name} ({len(coverage_rows())} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
