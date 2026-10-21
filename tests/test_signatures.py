"""glp_sign delegates to a licensed signature plugin and links a new chain entry."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.features import SIGNATURE_GROUP

from conftest import call_tool

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "audit-record.schema.json").read_text(encoding="utf-8"))
PHRASE = "designed to support 21 CFR Part 11 workflows"


def _names(proxy) -> list[str]:
    listed = proxy.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    return [item["name"] for item in listed["result"]["tools"]]


def _arm(proxy, **factories: object) -> None:
    proxy.features.enabled.add("signature.part11")
    table = proxy.features.plugins.setdefault(SIGNATURE_GROUP, {})
    table.update(factories)


def _factory(tool: object, feature: str = "signature.part11"):
    def factory(settings: object, options: object = None) -> object:
        del settings, options
        factory.calls += 1
        return tool

    factory.calls = 0
    factory.licence_feature = feature  # type: ignore[attr-defined]
    return factory


class _Signer:
    def __init__(self) -> None:
        self.seen: list[dict[str, str]] = []

    def sign(self, *, target: dict, meaning: str, principal: dict) -> dict:
        self.seen.append(
            {
                "hash": target["entry_hash"],
                "meaning": meaning,
                "principal": principal["id"],
            }
        )
        return {"algorithm": "test", "value": "sig"}


def test_glp_sign_is_absent_without_a_licensed_plugin(build) -> None:
    stack = build()
    approver = stack["proxies"]["approver"]
    assert "glp_sign" not in _names(approver)
    response = call_tool(
        approver,
        "glp_sign",
        {"target_entry_hash": "a" * 64, "meaning": "approved the record"},
    )
    assert response["result"]["isError"] is True
    assert response["result"]["content"][0]["text"] == "no licensed signature plugin"
    assert [item for item in stack["store"].read_entries() if item.get("method") == "glp_sign"] == []


def test_unlicensed_signature_plugin_is_not_called(build) -> None:
    stack = build()
    approver = stack["proxies"]["approver"]

    def boom(settings: object, options: object = None) -> None:
        del settings, options
        raise AssertionError("unlicensed signature factory was called")

    boom.licence_feature = "signature.part11"  # type: ignore[attr-defined]

    def community(settings: object, options: object = None) -> None:
        del settings, options
        raise AssertionError("community feature ran the signature factory")

    community.licence_feature = "storage.jsonl"  # type: ignore[attr-defined]
    table = approver.features.plugins.setdefault(SIGNATURE_GROUP, {})
    table["part11"] = boom
    table["jsonl"] = community
    assert "signature.part11" not in approver.features.enabled
    assert "glp_sign" not in _names(approver)
    response = call_tool(
        approver,
        "glp_sign",
        {"target_entry_hash": "b" * 64, "meaning": "approved the record"},
    )
    assert response["result"]["content"][0]["text"] == "no licensed signature plugin"


def test_glp_sign_appends_a_linked_entry(build) -> None:
    stack = build()
    operator = stack["proxies"]["operator"]
    approver = stack["proxies"]["approver"]
    signer = _Signer()
    factory = _factory(signer)
    _arm(operator, part11=factory)
    _arm(approver, part11=factory)
    assert "glp_sign" not in _names(operator)
    denied = call_tool(
        operator,
        "glp_sign",
        {"target_entry_hash": "c" * 64, "meaning": "approved the record"},
    )
    assert denied["result"]["isError"] is True
    assert factory.calls == 0
    assert "glp_sign" in _names(approver)

    call_tool(operator, "excel__read_cell", {"cell": "A1"})
    before = stack["store"].read_entries()
    target = before[0]
    head = before[-1]["entry_hash"]
    assert target["entry_hash"] != head
    missing = call_tool(
        approver,
        "glp_sign",
        {"target_entry_hash": "d" * 64, "meaning": "approved the record"},
    )
    assert missing["result"]["isError"] is True
    assert "no audit entry" in missing["result"]["content"][0]["text"]
    assert factory.calls == 0
    before = stack["store"].read_entries()
    head = before[-1]["entry_hash"]

    response = call_tool(
        approver,
        "glp_sign",
        {"target_entry_hash": target["entry_hash"], "meaning": "approved the record"},
    )
    assert response["result"]["isError"] is False
    text = response["result"]["content"][0]["text"]
    assert PHRASE.lower() in text.lower()
    assert factory.calls == 1
    assert signer.seen == [
        {
            "hash": target["entry_hash"],
            "meaning": "approved the record",
            "principal": "approver-1",
        }
    ]
    after = stack["store"].read_entries()
    assert after[0] == target
    signed = after[-1]
    assert signed["method"] == "glp_sign"
    assert signed["status"] == "ok"
    assert signed["approval"] is None
    assert signed["prev_hash"] == head
    assert signed["arguments"]["target_entry_hash"] == target["entry_hash"]
    assert signed["result"]["target_entry_hash"] == target["entry_hash"]
    assert signed["result"]["label"] == "signature"
    assert signed["result"]["signature"] == {"algorithm": "test", "value": "sig"}
    assert signed["entry_hash"] != target["entry_hash"]
    jsonschema.validate(signed, SCHEMA)
    assert verify_file(stack["proxies"]["operator"].settings.audit_path).ok


def test_several_plugins_require_a_name_and_a_failure_is_not_ok(build) -> None:
    stack = build()
    approver = stack["proxies"]["approver"]
    first = _Signer()
    second = _Signer()
    factory_a = _factory(first)
    factory_b = _factory(second)
    _arm(approver, alpha=factory_a, beta=factory_b)
    target = stack["store"].read_entries()[0]["entry_hash"]
    unnamed = call_tool(
        approver,
        "glp_sign",
        {"target_entry_hash": target, "meaning": "approved the record"},
    )
    assert unnamed["result"]["content"][0]["text"] == "name the signature plugin"
    assert factory_a.calls == 0
    assert factory_b.calls == 0

    class Broken:
        def sign(self, *, target: dict, meaning: str, principal: dict) -> dict:
            del target, meaning, principal
            raise RuntimeError("disk full")

    factory_b = _factory(Broken())
    approver.features.plugins[SIGNATURE_GROUP]["beta"] = factory_b
    failed = call_tool(
        approver,
        "glp_sign",
        {"target_entry_hash": target, "meaning": "approved the record", "plugin": "beta"},
    )
    assert failed["result"]["isError"] is True
    assert failed["result"]["content"][0]["text"] == "disk full"
    assert factory_a.calls == 0
    assert factory_b.calls == 1
    rows = [item for item in stack["store"].read_entries() if item.get("method") == "glp_sign"]
    assert rows[-1]["status"] == "failed"
    assert rows[-1]["arguments"]["target_entry_hash"] == target
    assert not any(item["status"] == "ok" for item in rows)


def test_readme_documents_the_signature_hook() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme.encode("ascii")
    assert PHRASE in readme
    assert "mcp_glp_audit_proxy.signatures" in readme
    assert "no licensed signature plugin" in readme
    plugins = (ROOT / "docs" / "PLUGINS.md").read_text(encoding="utf-8")
    plugins.encode("ascii")
    assert "signature.part11" in plugins
    assert "An unlicensed name is not called" in plugins or "does not call factories" in plugins
