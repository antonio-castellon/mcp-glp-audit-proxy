"""Optional HTTPS failed-authentication limit. Off unless configured."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

from mcp_glp_audit_proxy.authlimit import AuthGate
from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.channels.https_inbound import handle_http
from mcp_glp_audit_proxy.config import (
    AuthFailureLimit,
    ListenConfig,
    ListenIdentity,
    MappedPrincipal,
    Principal,
    Retention,
    RouteConfig,
    Settings,
    UpstreamConfig,
)
from mcp_glp_audit_proxy.policy import Policy
from mcp_glp_audit_proxy.proxy import AuditProxy
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore

from conftest import Clock

TOKEN = "tok-b4-do-not-store-9f3a"


class _Headers:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, key: str, default: str | None = None) -> str | None:
        for name, value in self._values.items():
            if name.lower() == key.lower():
                return value
        return default

    def items(self):
        return self._values.items()


class _Handler:
    def __init__(self, address: str, token: str | None) -> None:
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        self.headers = _Headers(headers)
        self.path = "/v1/ok"
        self.command = "GET"
        self.client_address = (address, 9)
        self.rfile = None
        self.connection = SimpleNamespace()
        self.server = SimpleNamespace(bearer_token=TOKEN)


def _stack(tmp_path: Path, limit: AuthFailureLimit | None, monkeypatch):
    path = tmp_path / "audit.jsonl"
    store = JsonlAuditStore(path, checkpoint_every=0)
    settings = Settings(
        principal=Principal(id="operator-1", name="Ada Analyst", role="operator"),
        retention=Retention(),
        policy=Policy(
            allow=["*"],
            deny=[],
            write_tools=[],
            http_allow=["GET /v1/ok"],
            require_reason_for_writes=False,
        ),
        audit_path=path,
        body_mode="hash_only",
        checkpoint_every=0,
        listen=ListenConfig(
            bind="127.0.0.1",
            port=8443,
            cert_file="cert.pem",
            key_file="key.pem",
            identity=ListenIdentity(
                mode="bearer",
                bearer_token_file=str(tmp_path / "bearer.txt"),
                bearer_principal=MappedPrincipal(id="gw", name="Gateway", role="operator"),
            ),
            auth_failure_limit=limit,
        ),
        upstreams=[
            UpstreamConfig(name="lab", transport="https", url="https://127.0.0.1:9", kind="api")
        ],
        routes=[RouteConfig(flow="api2api", methods=("GET",), path="/v1/ok", upstream="lab")],
    )
    proxy = AuditProxy(
        settings,
        store,
        [],
        now=Clock(),
        clock_probe=lambda: {"detail": "yes", "ntp_synchronized": True, "source": "test"},
    )
    proxy.startup()
    clock = {"t": 1000.0}
    proxy._auth_gate = AuthGate(limit, now=lambda: clock["t"])
    calls: list[str] = []

    class FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs

        def request(self, method, target, body):
            calls.append(method)
            return 200, "application/json", b"{}"

    monkeypatch.setattr("mcp_glp_audit_proxy.channels.https_inbound.HttpsApiClient", FakeClient)
    return proxy, settings, path, clock, calls


def _status(proxy, settings, address: str, token: str | None) -> int:
    code, _kind, _body = handle_http(proxy, settings, _Handler(address, token))
    return code


def test_limit_off_allows_repeated_failures(tmp_path: Path, monkeypatch) -> None:
    proxy, settings, path, _clock, calls = _stack(tmp_path, None, monkeypatch)
    assert [_status(proxy, settings, "10.0.0.1", "nope") for _ in range(10)] == [401] * 10
    methods = [entry["method"] for entry in proxy.store.read_entries()]
    assert "audit/auth_block" not in methods
    assert not (path.parent / (path.name + ".warning.json")).exists()
    assert calls == []


def test_fourth_request_is_blocked_and_alerts(tmp_path: Path, monkeypatch) -> None:
    limit = AuthFailureLimit(max_failures=3, window_seconds=60, block_seconds=10, key="address")
    proxy, settings, path, _clock, calls = _stack(tmp_path, limit, monkeypatch)
    statuses = [_status(proxy, settings, "10.0.0.1", "nope") for _ in range(4)]
    assert statuses == [401, 401, 401, 429]
    methods = [entry["method"] for entry in proxy.store.read_entries()]
    assert methods.count("audit/auth_block") == 1
    warning = path.with_name(path.name + ".warning.json")
    assert warning.is_file()
    text = warning.read_text(encoding="utf-8")
    assert "warning" in text
    assert "auth_block" in text
    assert calls == []
    if os.name != "nt":
        assert warning.stat().st_mode & 0o777 == 0o600


def test_block_expires_and_a_valid_request_succeeds(tmp_path: Path, monkeypatch) -> None:
    limit = AuthFailureLimit(max_failures=3, window_seconds=60, block_seconds=10, key="address")
    proxy, settings, _path, clock, calls = _stack(tmp_path, limit, monkeypatch)
    for _ in range(4):
        _status(proxy, settings, "10.0.0.1", "nope")
    assert _status(proxy, settings, "10.0.0.1", TOKEN) == 429
    assert calls == []
    clock["t"] = 1010.0
    assert _status(proxy, settings, "10.0.0.1", TOKEN) == 200
    methods = [entry["method"] for entry in proxy.store.read_entries()]
    assert "audit/auth_unblock" in methods
    assert calls == ["GET"]


def test_address_key_does_not_block_another_address(tmp_path: Path, monkeypatch) -> None:
    limit = AuthFailureLimit(max_failures=3, window_seconds=60, block_seconds=10, key="address")
    proxy, settings, _path, _clock, _calls = _stack(tmp_path, limit, monkeypatch)
    assert [_status(proxy, settings, "10.0.0.1", "nope") for _ in range(4)][-1] == 429
    assert _status(proxy, settings, "10.0.0.2", "nope") == 401


def test_chain_verifies_and_token_is_absent(tmp_path: Path, monkeypatch) -> None:
    limit = AuthFailureLimit(max_failures=3, window_seconds=60, block_seconds=10, key="address")
    proxy, settings, path, _clock, _calls = _stack(tmp_path, limit, monkeypatch)
    for _ in range(3):
        _status(proxy, settings, "10.0.0.1", "nope")
    assert _status(proxy, settings, "10.0.0.1", TOKEN) == 429
    raw = path.read_bytes()
    warning = path.with_name(path.name + ".warning.json").read_bytes()
    digest = hashlib.sha256(TOKEN.encode()).hexdigest().encode()
    assert TOKEN.encode() not in raw
    assert digest not in raw
    assert TOKEN.encode() not in warning
    report = verify_file(path)
    assert report.ok, report.errors
