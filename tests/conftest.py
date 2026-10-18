"""Shared builders for proxy tests."""

from __future__ import annotations

import pytest

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mcp_glp_audit_proxy.config import Principal, Retention, Settings
from mcp_glp_audit_proxy.policy import Policy
from mcp_glp_audit_proxy.proxy import AuditProxy
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore
from mcp_glp_audit_proxy.upstream import JsonRpcUpstream

from fake_upstream_server import FakeUpstreamApp

NAMES = {
    "operator": "Ada Analyst",
    "approver": "Ben Reviewer",
    "qa": "Cara QA",
    "admin": "Dan Admin",
}


class Clock:
    def __init__(self) -> None:
        self.moment = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, seconds: int) -> None:
        self.moment = self.moment + timedelta(seconds=seconds)


class MemoryTransport:
    def __init__(self, app: FakeUpstreamApp) -> None:
        self.app = app
        self.sent: list[dict[str, Any]] = []
        self.response_session_id: str | None = None
        self._buffer: dict[str, Any] | None = None

    def send(self, message: dict[str, Any], *, session_id: str | None = None) -> None:
        self.sent.append({"message": message, "session_id": session_id})
        response = self.app.handle(message)
        if message.get("method") == "initialize" and self.app.session_id:
            self.response_session_id = self.app.session_id
        self._buffer = response

    def receive(self) -> dict[str, Any]:
        if self._buffer is None:
            raise RuntimeError("no response buffered")
        value = self._buffer
        self._buffer = None
        return value

    def close(self) -> None:
        return None


def assemble(
    tmp_path: Path,
    *,
    era: str = "legacy",
    protocol: str = "auto",
    allow: list[str] | None = None,
    deny: list[str] | None = None,
    write_tools: list[str] | None = None,
    require_approval: bool = False,
    require_reason: bool = True,
    checkpoint_every: int = 0,
    clock: Clock | None = None,
) -> dict[str, Any]:
    clock = clock or Clock()
    fake = FakeUpstreamApp(era)
    upstream = JsonRpcUpstream("excel", MemoryTransport(fake), protocol)
    store = JsonlAuditStore(
        tmp_path / "audit.jsonl",
        checkpoint_every=checkpoint_every,
        now=clock,
    )
    proxies: dict[str, AuditProxy] = {}
    for role in ("operator", "approver", "qa", "admin"):
        settings = Settings(
            principal=Principal(id=f"{role}-1", name=NAMES[role], role=role),
            retention=Retention(),
            policy=Policy(
                allow=list(allow) if allow is not None else ["*"],
                deny=list(deny or []),
                write_tools=list(write_tools) if write_tools is not None else ["excel__write_cell"],
                require_approval_for_writes=require_approval,
                require_reason_for_writes=require_reason,
            ),
            audit_path=tmp_path / "audit.jsonl",
            fail_closed=True,
            checkpoint_every=checkpoint_every,
            approval_ttl_seconds=3600,
            export_dir=tmp_path / "exports",
            require_ntp=False,
        )
        proxies[role] = AuditProxy(
            settings,
            store,
            [upstream],
            now=clock,
            clock_probe=lambda: {
                "detail": "yes",
                "ntp_synchronized": True,
                "source": "test",
            },
        )
    proxies["operator"].startup()
    return {"proxies": proxies, "fake": fake, "store": store, "clock": clock, "path": tmp_path}


@pytest.fixture
def build(tmp_path: Path):
    def _build(**kwargs: Any) -> dict[str, Any]:
        return assemble(tmp_path, **kwargs)

    return _build


def call_tool(
    proxy: AuditProxy,
    name: str,
    arguments: dict[str, Any] | None = None,
    meta: dict[str, Any] | None = None,
    *,
    request_id: int = 10,
) -> dict[str, Any]:
    params: dict[str, Any] = {"name": name, "arguments": arguments or {}}
    if meta:
        params["_meta"] = meta
    response = proxy.handle({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": params})
    assert response is not None
    return response
