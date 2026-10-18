"""Fail-closed logging: no upstream call without a durable audit entry."""

from __future__ import annotations

import json

from mcp_glp_audit_proxy.errors import AuditStoreError
from mcp_glp_audit_proxy.proxy import AuditProxy

from conftest import call_tool


class Unhealthy:
    def health(self) -> bool:
        return False

    def read_entries(self) -> list:
        return []

    def append_event(self, event: dict) -> dict:
        raise AuditStoreError("down")


class AppendFails:
    def health(self) -> bool:
        return True

    def read_entries(self) -> list:
        return []

    def append_event(self, event: dict) -> dict:
        raise AuditStoreError("disk full")


def test_unhealthy_store_does_not_forward(build) -> None:
    stack = build()
    proxy = stack["proxies"]["operator"]
    proxy.store = Unhealthy()
    response = call_tool(proxy, "excel__read_cell", {"cell": "A1"})
    assert response["error"]["data"]["reason"] == "fail_closed"
    assert "value:" not in json.dumps(response)
    assert [item["method"] for item in stack["fake"].calls] == []


def test_append_failure_hides_upstream_result(build) -> None:
    stack = build()
    proxy = stack["proxies"]["operator"]
    proxy.store = AppendFails()
    response = call_tool(proxy, "excel__read_cell", {"cell": "A1"})
    assert response["error"]["data"]["reason"] == "fail_closed"
    assert "value:" not in json.dumps(response)
    assert any(item["method"] == "tools/call" for item in stack["fake"].calls)


def test_denied_call_is_logged_and_not_forwarded(build) -> None:
    stack = build(deny=["excel__read_cell"])
    proxy = stack["proxies"]["operator"]
    response = call_tool(proxy, "excel__read_cell", {"cell": "A1"})
    assert response["result"]["isError"] is True
    assert [item["method"] for item in stack["fake"].calls] == []
    denied = [entry for entry in stack["store"].read_entries() if entry["status"] == "denied"]
    assert denied
    assert denied[-1]["tool"] == "excel__read_cell"
    assert denied[-1]["policy_decision"]["action"] == "deny"


def test_failed_upstream_call_is_logged(build) -> None:
    stack = build()
    proxy = stack["proxies"]["operator"]
    response = call_tool(proxy, "excel__boom", {})
    assert response["error"]["message"] == "boom"
    failed = [entry for entry in stack["store"].read_entries() if entry["status"] == "failed"]
    assert failed[-1]["tool"] == "excel__boom"
    assert failed[-1]["error"]["message"] == "boom"


def test_tool_is_error_is_logged_as_failed(build) -> None:
    stack = build()
    response = call_tool(stack["proxies"]["operator"], "excel__soft_fail", {})
    assert response["result"]["isError"] is True
    failed = [entry for entry in stack["store"].read_entries() if entry["tool"] == "excel__soft_fail"]
    assert failed[-1]["status"] == "failed"


def test_tampered_chain_does_not_forward(build) -> None:
    stack = build()
    path = stack["store"].path
    path.write_bytes(path.read_bytes().replace(b"audit/startup", b"audit/startux", 1))
    before = len(stack["fake"].calls)
    response = call_tool(stack["proxies"]["operator"], "excel__read_cell", {"cell": "A1"})
    assert response["error"]["data"]["reason"] == "fail_closed"
    assert len(stack["fake"].calls) == before


def test_store_refuses_disposal(build) -> None:
    stack = build()
    store = stack["store"]
    assert not hasattr(store, "delete")
    assert not hasattr(store, "update")
    store.legal_hold = True
    try:
        store.refuse_disposal()
    except AuditStoreError as exc:
        assert "legal hold" in str(exc)
    else:
        raise AssertionError("disposal was not refused")
