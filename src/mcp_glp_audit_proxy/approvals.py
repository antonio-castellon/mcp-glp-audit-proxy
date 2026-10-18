"""Approval state reconstructed from the append-only log.

An approval is labelled 'approval'. It is not an electronic signature.
Part 11 signature manifestation, IdP re-authentication and cryptographic
binding are Pro features.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class ApprovalRecord:
    approval_id: str
    tool: str
    args_hash: str
    requested_by: str
    status: str
    approver_id: str | None
    approver_name: str | None
    approver_role: str | None
    meaning: str | None
    decided_at: str | None
    expires_at: str
    requested_seq: int


def load_approvals(entries: list[dict[str, Any]]) -> dict[str, ApprovalRecord]:
    found: dict[str, ApprovalRecord] = {}
    for entry in entries:
        approval = entry.get("approval")
        if not isinstance(approval, dict) or not approval.get("approval_id"):
            continue
        approval_id = str(approval["approval_id"])
        if entry.get("status") == "pending_approval":
            found[approval_id] = ApprovalRecord(
                approval_id=approval_id,
                tool=str(approval.get("tool") or entry.get("tool") or ""),
                args_hash=str(approval.get("args_hash") or ""),
                requested_by=str((entry.get("principal") or {}).get("id") or ""),
                status="pending",
                approver_id=None,
                approver_name=None,
                approver_role=None,
                meaning=None,
                decided_at=None,
                expires_at=str(approval.get("expires_at") or ""),
                requested_seq=int(entry.get("seq") or 0),
            )
            continue
        current = found.get(approval_id)
        if current is None:
            continue
        if entry.get("method") == "glp_approve" and entry.get("status") in {"approved", "rejected"}:
            principal = entry.get("principal") or {}
            current.status = str(entry["status"])
            current.approver_id = principal.get("id")
            current.approver_name = principal.get("name")
            current.approver_role = principal.get("role")
            current.meaning = approval.get("meaning")
            current.decided_at = entry.get("timestamp")
            continue
        if entry.get("status") == "ok" and approval.get("status") == "consumed":
            current.status = "consumed"
    return found


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)
