"""Allow list, deny list, roles, and admin-only policy changes."""

from __future__ import annotations

import pytest

from mcp_glp_audit_proxy.config import Retention
from mcp_glp_audit_proxy.errors import ConfigurationError

from conftest import call_tool


def test_allowlist_and_denylist(build) -> None:
    stack = build(allow=["excel__read_*"], deny=["excel__read_cell"])
    proxy = stack["proxies"]["operator"]
    denied = call_tool(proxy, "excel__read_cell", {"cell": "A1"})
    assert denied["result"]["isError"] is True
    # deny wins over a matching allow pattern; a different read is allowed.
    allowed = call_tool(proxy, "excel__read_other", {"cell": "B2"}, request_id=11)
    # read_other is not a real upstream tool name the fake knows; it still gets forwarded
    # because the policy allowed it. The fake returns the generic read result.
    assert allowed["result"]["isError"] is False
    rules = [
        entry["policy_decision"]["rule"]
        for entry in stack["store"].read_entries()
        if entry.get("tool") == "excel__read_cell"
    ]
    assert any(rule.startswith("deny:") for rule in rules)


def test_empty_allow_denies_upstream(build) -> None:
    stack = build(allow=[])
    response = call_tool(stack["proxies"]["operator"], "excel__read_cell", {"cell": "A1"})
    assert response["result"]["isError"] is True
    assert stack["fake"].calls == []


def test_write_requires_reason(build) -> None:
    stack = build()
    missing = call_tool(stack["proxies"]["operator"], "excel__write_cell", {"cell": "A1", "value": 1})
    assert missing["result"]["isError"] is True
    assert stack["fake"].calls == []
    meta = {"io.github.antonio-castellon/reason": "correct the reading"}
    done = call_tool(
        stack["proxies"]["operator"],
        "excel__write_cell",
        {"cell": "A1", "value": 1},
        meta,
        request_id=11,
    )
    assert done["result"]["structuredContent"]["saved"] is True
    entry = [item for item in stack["store"].read_entries() if item.get("tool") == "excel__write_cell" and item["status"] == "ok"][-1]
    assert entry["reason"] == "correct the reading"
    assert entry["record_class"] == "gxp_data"


def test_qa_and_admin_cannot_call_upstream(build) -> None:
    stack = build()
    for role in ("qa", "admin", "approver"):
        response = call_tool(stack["proxies"][role], "excel__read_cell", {"cell": "A1"})
        assert response["result"]["isError"] is True
    assert stack["fake"].calls == []
    denied = [entry for entry in stack["store"].read_entries() if entry["status"] == "denied"]
    assert {entry["policy_decision"]["rule"] for entry in denied} >= {"role:qa", "role:admin", "role:approver"}


def test_admin_policy_change_is_audited_and_replayed(build) -> None:
    stack = build()
    admin = stack["proxies"]["admin"]
    operator = stack["proxies"]["operator"]
    blocked = call_tool(
        admin,
        "glp_update_policy",
        {"audit_enabled": False, "reason": "turn it off"},
    )
    assert blocked["result"]["isError"] is True
    updated = call_tool(
        admin,
        "glp_update_policy",
        {"deny": ["excel__read_cell"], "reason": "remove a risky read"},
        request_id=11,
    )
    assert updated["result"]["isError"] is False
    config_entries = [entry for entry in stack["store"].read_entries() if entry["method"] == "glp_update_policy"]
    ok = [entry for entry in config_entries if entry["status"] == "ok"][-1]
    assert ok["record_class"] == "config"
    assert ok["arguments"]["previous"]["deny"] == []
    assert ok["result"]["policy"]["deny"] == ["excel__read_cell"]
    # The operator process picks the change up from the log. No restart.
    refused = call_tool(operator, "excel__read_cell", {"cell": "A1"}, request_id=12)
    assert refused["result"]["isError"] is True


def test_retention_floor_and_swiss_default() -> None:
    Retention().validate()
    swiss = Retention(profile="swiss_glp", years_after_study=10, min_months=6)
    swiss.validate()
    with pytest.raises(ConfigurationError):
        Retention(min_months=5).validate()
    with pytest.raises(ConfigurationError):
        Retention(profile="swiss_glp", years_after_study=9).validate()
    Retention(profile="minimum", years_after_study=1, min_months=6).validate()
