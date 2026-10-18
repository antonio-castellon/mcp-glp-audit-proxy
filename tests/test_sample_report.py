"""The committed sample report is internally consistent and ASCII."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from mcp_glp_audit_proxy.verification.oq import _canonical

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "docs" / "verification" / "sample"
BANNED = ("certified", "compliant", "validated")


def test_sample_report_hash_and_wording() -> None:
    payload = json.loads((SAMPLE / "oq-report.json").read_text(encoding="utf-8"))
    digest = payload.pop("report_sha256")
    assert hashlib.sha256(_canonical(payload)).hexdigest() == digest
    text = (SAMPLE / "oq-report.md").read_text(encoding="utf-8")
    text.encode("ascii")
    (SAMPLE / "oq-report.json").read_text(encoding="utf-8").encode("ascii")
    lowered = text.lower()
    for word in BANNED:
        assert word not in lowered
    assert "designed to support glp / 21 cfr part 11 / eu gmp annex 11 workflows" in lowered
    assert payload["counts"]["failed"] == 0
