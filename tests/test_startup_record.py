"""audit/startup records identity, role, and configuration changes."""

from __future__ import annotations

import hashlib
from pathlib import Path

from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.config import (
    ListenConfig,
    ListenIdentity,
    MappedPrincipal,
    Principal,
    Retention,
    Settings,
)
from mcp_glp_audit_proxy.policy import Policy
from mcp_glp_audit_proxy.proxy import AuditProxy
from mcp_glp_audit_proxy.records import SYSTEM_PRINCIPAL, build_event
from mcp_glp_audit_proxy.server import resolve_change_reason
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore

from conftest import Clock


def _settings(path: Path, **changes: object) -> Settings:
    settings = Settings(
        principal=Principal(id="operator-1", name="Ada Analyst", role="operator"),
        retention=Retention(),
        policy=Policy(
            allow=["*"],
            deny=[],
            write_tools=["excel__write_cell"],
            require_reason_for_writes=True,
        ),
        audit_path=path,
        fail_closed=True,
        body_mode="hash_only",
        checkpoint_every=0,
    )
    for key, value in changes.items():
        setattr(settings, key, value)
    return settings


def _proxy(settings: Settings, store: JsonlAuditStore) -> AuditProxy:
    return AuditProxy(
        settings,
        store,
        [],
        now=Clock(),
        clock_probe=lambda: {"detail": "yes", "ntp_synchronized": True, "source": "test"},
    )


def _listen(token_file: Path, *, end_user: bool = False) -> ListenConfig:
    return ListenConfig(
        bind="127.0.0.1",
        port=8443,
        cert_file="cert.pem",
        key_file="key.pem",
        identity=ListenIdentity(
            mode="bearer",
            bearer_token_file=str(token_file),
            bearer_principal=MappedPrincipal(id="gw", name="Gateway", role="operator"),
            end_user_header="X-User" if end_user else None,
            end_users=(MappedPrincipal(id="u2", name="User Two", role="operator"),) if end_user else (),
        ),
    )


def test_first_start_records_config_and_null_change(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    proxy = _proxy(_settings(path), JsonlAuditStore(path, checkpoint_every=0))
    record = proxy.startup()
    arguments = record["arguments"]
    assert arguments["config_changed"] is None
    assert arguments["body_mode"] == "hash_only"
    assert arguments["listen"] is None
    assert arguments["identities"][0]["id"] == "operator-1"
    assert arguments["identities"][0]["match"] == "stdio"
    assert len(arguments["config_sha256"]) == 64
    assert arguments["audit_enabled"] is True
    assert arguments["change_reason"] is None


def test_restart_with_the_same_config_has_an_empty_change_list(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    proxy = _proxy(_settings(path), JsonlAuditStore(path, checkpoint_every=0))
    proxy.startup()
    again = proxy.startup()
    assert again["arguments"]["config_changed"] == []
    assert again["arguments"]["config_sha256"] == proxy.store.read_entries()[0]["arguments"]["config_sha256"]


def test_body_mode_and_identity_are_listed_when_they_change(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    token = tmp_path / "bearer.txt"
    token.write_text("not-in-the-log\n", encoding="utf-8")
    settings = _settings(path, listen=_listen(token))
    proxy = _proxy(settings, JsonlAuditStore(path, checkpoint_every=0))
    first = proxy.startup()
    settings.body_mode = "full"
    settings.listen = _listen(token, end_user=True)
    second = proxy.startup()
    assert second["arguments"]["config_changed"] == ["body_mode", "identities"]
    assert second["arguments"]["config_sha256"] != first["arguments"]["config_sha256"]


def test_change_reason_is_stored_and_a_missing_reason_warns(tmp_path: Path, capsys, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    settings = _settings(path)
    proxy = _proxy(settings, JsonlAuditStore(path, checkpoint_every=0))
    proxy.startup()
    settings.body_mode = "redacted"
    warned = proxy.startup()
    assert warned["arguments"]["change_reason"] is None
    assert warned["arguments"]["config_changed"] == ["body_mode"]
    assert "no change reason" in capsys.readouterr().err
    proxy.change_reason = "ticket 12"
    settings.fail_closed = False
    stored = proxy.startup()
    assert stored["arguments"]["change_reason"] == "ticket 12"
    assert "fail_closed" in stored["arguments"]["config_changed"]
    monkeypatch.setenv("GLP_CHANGE_REASON", "from-env")
    assert resolve_change_reason(None) == "from-env"
    assert resolve_change_reason("ticket 12") == "ticket 12"
    assert resolve_change_reason("  ") is None


def test_bearer_token_and_its_hash_are_absent(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    token = "super-secret-token-value"
    token_file = tmp_path / "bearer.txt"
    token_file.write_text(token + "\n", encoding="utf-8")
    settings = _settings(path, listen=_listen(token_file))
    proxy = _proxy(settings, JsonlAuditStore(path, checkpoint_every=0))
    proxy.startup()
    raw = path.read_bytes()
    assert token.encode() not in raw
    assert hashlib.sha256(token.encode()).hexdigest().encode() not in raw
    assert f"bearer:{token_file}".encode() in raw


def test_old_startup_still_verifies_and_the_next_change_list_is_null(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = JsonlAuditStore(path, checkpoint_every=0)
    store.append_event(
        build_event(
            method="audit/startup",
            record_class="config",
            status="ok",
            server="proxy",
            principal=SYSTEM_PRINCIPAL,
            client={"id": "proxy"},
            protocol_version=None,
            session_id=None,
            arguments={"audit_enabled": True, "clock": {"ntp_synchronized": True}},
            result={"auditing": "enabled"},
        )
    )
    proxy = _proxy(_settings(path), store)
    record = proxy.startup()
    assert record["arguments"]["config_changed"] is None
    report = verify_file(path)
    assert report.ok, report.errors
