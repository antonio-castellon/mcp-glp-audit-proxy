"""Searchable electronic export (JSON). PDF and CSV reporters are Pro plugins."""

from __future__ import annotations

import json
from typing import Any

from ..canonical import CANON, GENESIS, HASH_ALGO, canonicalize


def json_reporter(_settings: Any) -> JsonReporter:
    """Entry point factory. Pro reporters use the same (settings,) signature."""
    return JsonReporter()


class JsonReporter:
    name = "json"
    media_type = "application/json"

    def render(self, document: dict[str, Any]) -> bytes:
        return canonicalize(document) + b"\n"


def filter_entries(
    entries: list[dict[str, Any]],
    *,
    record_class: str | None = None,
    tool: str | None = None,
    principal_id: str | None = None,
    status: str | None = None,
    method: str | None = None,
    server: str | None = None,
    since: str | None = None,
    until: str | None = None,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for entry in entries:
        if record_class and entry.get("record_class") != record_class:
            continue
        if tool and entry.get("tool") != tool:
            continue
        if status and entry.get("status") != status:
            continue
        if method and entry.get("method") != method:
            continue
        if server and entry.get("server") != server:
            continue
        if principal_id and (entry.get("principal") or {}).get("id") != principal_id:
            continue
        stamp = entry.get("timestamp") or ""
        if since and stamp < since:
            continue
        if until and stamp > until:
            continue
        selected.append(entry)
    return selected


def export_document(
    entries: list[dict[str, Any]],
    *,
    full_chain: list[dict[str, Any]],
    chain_valid: bool,
    filters: dict[str, Any],
    exported_at: str,
    signer: str = "unsigned",
) -> dict[str, Any]:
    filtered = any(value not in (None, "", [], {}) for value in filters.values())
    head = full_chain[-1]["entry_hash"] if full_chain else GENESIS
    return {
        "chain_valid": chain_valid,
        "complete": chain_valid and not filtered,
        "entries": entries,
        "exported_at": exported_at,
        "export_type": "electronic",
        "filters": filters,
        "manifest": {
            "canonicalization": CANON,
            "chain_valid": chain_valid,
            "complete": chain_valid and not filtered,
            "exported_count": len(entries),
            "full_chain_count": len(full_chain),
            "full_head_hash": head,
            "hash_algo": HASH_ALGO,
            "signer": signer,
        },
        "schema": "audit-record.schema.json",
        "schema_version": "1.0.0",
    }


def dumps_document(document: dict[str, Any]) -> str:
    """Pretty JSON for humans who will search the file. Manifest hashes use the chain, not this rendering."""
    return json.dumps(document, indent=2, sort_keys=True) + "\n"
