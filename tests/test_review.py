"""Review-by-exception report and the CSV copy."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

from mcp_glp_audit_proxy.records import SYSTEM_PRINCIPAL, build_event
from mcp_glp_audit_proxy.review import CSV_HEADER, main
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore

MARKER = "FULLMODE-SECRET-BODY"


def _http(method: str, status: int, body: str | None = None) -> dict:
    return {
        "body": body,
        "body_mode": "full" if body else "hash_only",
        "body_sha256": hashlib.sha256(b"body").hexdigest(),
        "headers": {},
        "kind": "api",
        "latency_ms": 1,
        "method": method,
        "path": "/v1/item",
        "route": "/v1/item",
        "status": status,
        "stripped_credential_headers": [],
    }


def _event(method: str, **kwargs: object) -> dict:
    principal = kwargs.pop("principal", {"id": "operator-1", "name": "Ada", "role": "operator"})
    record_class = kwargs.pop("record_class", "access")
    status = kwargs.pop("status", "ok")
    return build_event(
        method=method,
        record_class=record_class,
        status=status,
        server="proxy",
        principal=principal,
        client={"id": "test", "name": "test", "version": None, "model_id": None},
        protocol_version=None,
        session_id=None,
        **kwargs,
    )


def _log(path: Path, events: list[dict]) -> None:
    store = JsonlAuditStore(path, checkpoint_every=0)
    for event in events:
        store.append_event(event)


def _sample(path: Path) -> None:
    _log(
        path,
        [
            _event(
                "audit/startup",
                record_class="config",
                arguments={
                    "audit_enabled": True,
                    "body_mode": "hash_only",
                    "clock": {"ntp_synchronized": True},
                    "config_changed": ["body_mode"],
                },
                timestamp="2026-10-25T12:00:00.000000+00:00",
            ),
            _event(
                "GET",
                status="denied",
                tool="http:GET /v1/item",
                policy_action="deny",
                policy_rule="deny:GET /v1/item",
                http=_http("GET", 403),
                timestamp="2026-10-25T12:01:00.000000+00:00",
                reason="denied by policy",
            ),
            _event(
                "GET",
                status="denied",
                tool="http:GET /v1/item",
                policy_action="deny",
                policy_rule="identity:bearer",
                arguments={"client_address": "10.1.1.1", "path": "/v1/item"},
                principal={"id": "unauthenticated", "name": None, "role": "system"},
                http=_http("GET", 401),
                timestamp="2026-10-25T12:02:00.000000+00:00",
            ),
            _event(
                "GET",
                status="denied",
                tool="http:GET /v1/item",
                policy_action="deny",
                policy_rule="identity:bearer",
                arguments={"client_address": "10.1.1.1", "path": "/v1/item"},
                principal={"id": "unauthenticated", "name": None, "role": "system"},
                http=_http("GET", 401),
                timestamp="2026-10-25T12:03:00.000000+00:00",
            ),
            _event(
                "POST",
                record_class="gxp_data",
                tool="http:POST /v1/item",
                policy_action="allow",
                policy_rule="allow",
                http=_http("POST", 200),
                reason=None,
                timestamp="2026-10-25T12:04:00.000000+00:00",
            ),
            _event(
                "glp_approve",
                tool="glp_approve",
                timestamp="2026-10-25T11:00:00.000000+00:00",
                reason="approved",
            ),
        ],
    )


def test_exceptions_are_listed_once(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _sample(audit)
    out = tmp_path / "review.json"
    assert main([str(audit), "--out", str(out), "--format", "json"]) == 0
    document = json.loads(out.read_text(encoding="ascii"))
    assert [item["seq"] for item in document["denied"]] == [2]
    assert [item["seq"] for item in document["authentication_failures"]["items"]] == [3, 4]
    assert document["authentication_failures"]["counts"] == [
        {"address": "10.1.1.1", "count": 2, "identity": "unauthenticated"}
    ]
    assert [item["seq"] for item in document["writes_without_reason"]] == [5]
    assert [item["seq"] for item in document["approvals"]] == [6]


def test_clock_going_backwards_is_one_anomaly(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _sample(audit)
    out = tmp_path / "review.json"
    assert main([str(audit), "--out", str(out)]) == 0
    document = json.loads(out.read_text(encoding="ascii"))
    assert [item["seq"] for item in document["clock_anomalies"]] == [6]


def test_startup_config_change_is_listed(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _sample(audit)
    out = tmp_path / "review.json"
    assert main([str(audit), "--out", str(out)]) == 0
    document = json.loads(out.read_text(encoding="ascii"))
    assert document["configuration_changes"][0]["seq"] == 1
    assert document["configuration_changes"][0]["config_changed"] == ["body_mode"]


def test_csv_rows_match_the_period(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _sample(audit)
    out = tmp_path / "review.csv"
    assert main([str(audit), "--out", str(out), "--format", "csv"]) == 0
    text = out.read_text(encoding="ascii")
    text.encode("ascii")
    rows = list(csv.reader(io.StringIO(text)))
    assert tuple(rows[0]) == CSV_HEADER
    data = [row for row in rows[1:] if row and row[0].isdigit()]
    assert len(data) == 6


def test_full_mode_output_has_no_body_text(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _log(
        audit,
        [
            _event(
                "POST",
                http=_http("POST", 200, MARKER),
                result={"text": MARKER},
                arguments={"payload": MARKER},
                reason="kept",
            )
        ],
    )
    for fmt, name in (("json", "review.json"), ("md", "review.md"), ("csv", "review.csv")):
        out = tmp_path / name
        assert main([str(audit), "--out", str(out), "--format", fmt]) == 0
        assert MARKER not in out.read_text(encoding="ascii")


def test_tampered_log_exits_1_and_names_the_line(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _sample(audit)
    raw = audit.read_bytes()
    audit.write_bytes(raw.replace(b"audit/startup", b"audit/startuP", 1))
    out = tmp_path / "review.json"
    assert main([str(audit), "--out", str(out)]) == 1
    document = json.loads(out.read_text(encoding="ascii"))
    assert document["header"] == "chain integrity FAILED at line 1"


def test_review_does_not_change_the_log(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    _sample(audit)
    before = {item.name: (item.stat().st_mtime_ns, item.read_bytes()) for item in tmp_path.iterdir() if item.is_file()}
    out = tmp_path / "review.json"
    assert main([str(audit), "--out", str(out)]) == 0
    for name, (mtime, content) in before.items():
        path = tmp_path / name
        assert path.stat().st_mtime_ns == mtime
        assert path.read_bytes() == content
    assert SYSTEM_PRINCIPAL["id"]
