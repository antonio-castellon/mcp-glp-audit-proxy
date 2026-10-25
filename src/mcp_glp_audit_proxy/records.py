"""Audit-record builder. The store assigns seq, prev_hash and entry_hash."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from .canonical import CANON, HASH_ALGO, SCHEMA_VERSION

SYSTEM_PRINCIPAL = {
    "id": "system",
    "name": "mcp-glp-audit-proxy",
    "role": "system",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_timestamp(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


def build_event(
    *,
    method: str,
    record_class: str,
    status: str,
    server: str,
    principal: dict[str, Any],
    client: dict[str, Any],
    protocol_version: str | None,
    session_id: str | None,
    tool: str | None = None,
    arguments: dict[str, Any] | None = None,
    result: Any = None,
    error: dict[str, Any] | None = None,
    policy_action: str = "allow",
    policy_rule: str = "",
    reason: str | None = None,
    approval: dict[str, Any] | None = None,
    upstream_protocol_version: str | None = None,
    upstream_session_id: str | None = None,
    stripped_credential_fields: list[str] | None = None,
    traceparent: str | None = None,
    timestamp: str | None = None,
    record_id: str | None = None,
    transport: str = "stdio",
    channel: str = "mcp",
    flow: str | None = None,
    http: dict[str, Any] | None = None,
    arguments_sha256: str | None = None,
    result_sha256: str | None = None,
) -> dict[str, Any]:
    return {
        "approval": approval,
        "arguments": arguments,
        "arguments_sha256": arguments_sha256,
        "canonicalization": CANON,
        "client": {
            "id": client.get("id") or "unknown",
            "model_id": client.get("model_id"),
            "name": client.get("name"),
            "version": client.get("version"),
        },
        "error": error,
        "channel": channel,
        "flow": flow,
        "hash_algo": HASH_ALGO,
        "http": http,
        "method": method,
        "policy_decision": {"action": policy_action, "rule": policy_rule},
        "principal": {
            "id": principal["id"],
            "name": principal.get("name"),
            "role": principal["role"],
        },
        "protocol_version": protocol_version,
        "reason": reason,
        "record_class": record_class,
        "record_id": record_id or str(uuid.uuid4()),
        "result": result,
        "result_sha256": result_sha256,
        "schema_version": SCHEMA_VERSION,
        "server": server,
        "session_id": session_id,
        "status": status,
        "stripped_credential_fields": list(stripped_credential_fields or []),
        "timestamp": timestamp or format_timestamp(utc_now()),
        "tool": tool,
        "traceparent": traceparent,
        "transport": transport,
        "upstream_protocol_version": upstream_protocol_version,
        "upstream_session_id": upstream_session_id,
        "utc_offset": "+00:00",
    }
