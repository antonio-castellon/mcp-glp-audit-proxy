"""Message limits, name tricks, and credential scrubbing."""

from __future__ import annotations

import json

from mcp_glp_audit_proxy.policy import Policy
from mcp_glp_audit_proxy.proxy import MAX_MESSAGE_BYTES
from mcp_glp_audit_proxy.upstream import split_meta

from conftest import call_tool


def test_name_tricks_fail_closed() -> None:
    policy = Policy(
        allow=["excel__*"],
        deny=["excel__drop_*"],
        write_tools=["excel__write_cell"],
    )
    assert policy.decide("excel__read_cell", "operator").action == "allow"
    assert policy.decide("EXCEL__read_cell", "operator").rule == "allow:none"
    assert policy.decide("excel__read_cell ", "operator").rule == "name:whitespace"
    assert policy.decide(" excel__read_cell", "operator").rule == "name:whitespace"
    # Cyrillic i looks like ASCII i. The allow glob excel__* would match it
    # if the name were not rejected first.
    lookalike = "excel__read_\u0456cell"
    assert policy.decide(lookalike, "operator").rule == "name:charset"
    assert policy.decide("excel__drop_table", "operator").rule == "deny:excel__drop_*"
    assert policy.decide("excel__write_cell_extra", "operator").action == "allow"
    assert policy.decide("excel__write_cell_extra", "operator").action == "allow"
    exact = Policy(allow=["excel__write_cell"], deny=[], write_tools=[])
    assert exact.decide("excel__write_cell_extra", "operator").rule == "allow:none"
    assert exact.decide("excel__write_cel", "operator").rule == "allow:none"


def test_secrets_are_stripped_from_meta_and_the_log(build) -> None:
    cleaned, stripped = split_meta(
        {
            "authorization": "Bearer secret-value",
            "api_key": "k",
            "traceparent": "00-abc",
        }
    )
    assert "authorization" not in cleaned
    assert "secret-value" not in json.dumps(cleaned)
    assert "authorization" in stripped
    stack = build()
    response = call_tool(
        stack["proxies"]["operator"],
        "excel__read_cell",
        {"cell": "A1"},
        {"authorization": "Bearer secret-value", "traceparent": "00-abc"},
    )
    assert response["result"]["isError"] is False
    blob = json.dumps(stack["store"].read_entries())
    assert "secret-value" not in blob
    assert "authorization" in blob


def test_malformed_and_oversized_messages_are_not_forwarded(build) -> None:
    stack = build()
    proxy = stack["proxies"]["operator"]
    before = len(stack["fake"].calls)
    missing = proxy.handle({"jsonrpc": "2.0", "id": 1})
    assert missing["error"]["code"] == -32600
    not_object = proxy.handle(["tools/call"])  # type: ignore[arg-type]
    assert not_object["error"]["code"] == -32600
    huge = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "excel__read_cell", "arguments": {"blob": "x" * (MAX_MESSAGE_BYTES + 10)}},
    }
    refused = proxy.handle(huge)
    assert refused["error"]["message"] == "message exceeds size limit"
    assert len(stack["fake"].calls) == before
    logged = stack["store"].read_entries()[-1]
    assert logged["policy_decision"]["rule"] == "message:size"
    assert "xxx" not in json.dumps(logged["arguments"])
