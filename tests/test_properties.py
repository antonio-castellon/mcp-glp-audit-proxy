"""Property checks for RFC 8785 canonical JSON and the SHA-256 chain."""

from __future__ import annotations

import json

from hypothesis import given, settings
from hypothesis import strategies as st

from mcp_glp_audit_proxy.canonical import canonicalize, seal, sha256_hex
from mcp_glp_audit_proxy.chain import verify_bytes
from mcp_glp_audit_proxy.records import SYSTEM_PRINCIPAL, build_event

_leaf = st.none() | st.booleans() | st.integers(min_value=-(10**6), max_value=10**6) | st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz 01",
    max_size=12,
)
json_value = st.recursive(
    _leaf,
    lambda children: st.lists(children, max_size=3)
    | st.dictionaries(st.text(alphabet="abc", min_size=1, max_size=4), children, max_size=3),
    max_leaves=6,
)


@settings(max_examples=40, derandomize=True, deadline=None)
@given(json_value)
def test_canonical_form_is_stable(value) -> None:
    first = canonicalize(value)
    again = canonicalize(json.loads(first))
    assert again == first
    assert sha256_hex(first) == sha256_hex(again)


@settings(max_examples=20, derandomize=True, deadline=None)
@given(st.lists(st.integers(min_value=0, max_value=50), min_size=1, max_size=6))
def test_sealed_lines_verify_and_a_byte_flip_does_not(values: list[int]) -> None:
    lines: list[bytes] = []
    prior: list[dict] = []
    for index, value in enumerate(values):
        event = build_event(
            method="tools/call",
            record_class="access",
            status="ok",
            server="excel",
            principal=SYSTEM_PRINCIPAL,
            client={"id": "proxy", "name": "proxy", "version": "0.1.0", "model_id": None},
            protocol_version="2025-11-25",
            session_id=None,
            tool="excel__read_cell",
            arguments={"n": value, "i": index},
            result={"n": value},
        )
        body = dict(event)
        body["seq"] = 1 if not prior else int(prior[-1]["seq"]) + 1
        prev = "0" * 64 if not prior else str(prior[-1]["entry_hash"])
        sealed = seal(body, prev)
        line = canonicalize(sealed)
        lines.append(line + b"\n")
        prior.append(sealed)
    blob = b"".join(lines)
    assert verify_bytes(blob).ok
    # Flip a payload byte that is not the newline.
    raw = bytearray(blob)
    raw[0] = raw[0] ^ 0x01
    assert verify_bytes(bytes(raw)).ok is False
