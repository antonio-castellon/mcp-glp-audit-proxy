"""HTTPS gateway: six flows, policy, body storage, identity, and fail-closed.

Certificates and the bearer file are created in the test tmp directory.
Nothing here is a long-lived key.
"""

from __future__ import annotations

import hashlib
import http.client
import http.server
import json
import os
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlparse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from jsonschema import Draft202012Validator

from mcp_glp_audit_proxy.bodyutil import prepare_body, sha256_hex
from mcp_glp_audit_proxy.canonical import args_hash
from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.channels.https_inbound import build_server
from mcp_glp_audit_proxy.channels.https_outbound import HttpsApiClient
from mcp_glp_audit_proxy.channels.identity import cert_fingerprint
from mcp_glp_audit_proxy.config import Principal, load_settings
from mcp_glp_audit_proxy.core import SCHEMA_VERSION
from mcp_glp_audit_proxy.errors import AuditStoreError, ConfigurationError, TlsRequired
from mcp_glp_audit_proxy.policy import Policy
from mcp_glp_audit_proxy.records import build_event
from mcp_glp_audit_proxy.server import build_proxy
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore
from mcp_glp_audit_proxy.tlsutil import tls13_context

from conftest import call_tool

SCHEMA = json.loads(
    (Path(__file__).resolve().parents[1] / "schema" / "audit-record.schema.json").read_text(
        encoding="utf-8"
    )
)
VALIDATOR = Draft202012Validator(SCHEMA)
EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def test_core_reexports_the_historical_schema_version() -> None:
    from mcp_glp_audit_proxy.canonical import SCHEMA_VERSION as historical

    assert SCHEMA_VERSION is historical
    assert SCHEMA_VERSION == "1.2.0"


def test_body_modes_always_keep_the_raw_hash() -> None:
    raw = b'{"password":"secret","n":1}'
    digest = sha256_hex(raw)
    hashed = prepare_body(raw, mode="hash_only", redact_paths=("$.password",))
    assert hashed == {"body_sha256": digest, "body": None, "body_mode": "hash_only"}
    redacted = prepare_body(raw, mode="redacted", redact_paths=("$.password",))
    assert redacted["body_sha256"] == digest
    assert redacted["body"] == {"password": "***", "n": 1}
    full = prepare_body(raw, mode="full", redact_paths=())
    assert full["body"] == {"password": "secret", "n": 1}
    assert full["body_sha256"] == digest
    opaque = b"\xff\xfe not json"
    redacted_text = prepare_body(opaque, mode="redacted", redact_paths=("$.password",))
    assert redacted_text["body"] is None
    assert redacted_text["body_sha256"] == sha256_hex(opaque)
    full_binary = prepare_body(opaque, mode="full", redact_paths=())
    assert full_binary["body"] is None
    assert full_binary["body_sha256"] == sha256_hex(opaque)


def test_http_policy_is_separate_from_tool_policy() -> None:
    policy = Policy(
        allow=["*"],
        deny=[],
        write_tools=[],
        http_allow=["GET /v1/*", "POST /v1/studies/*"],
        http_deny=["GET /v1/secret", "POST /v1/studies/secret"],
    )
    assert policy.decide_http("GET", "/v1/secret", "operator").action == "deny"
    assert policy.decide_http("POST", "/v1/studies/secret", "operator").rule.startswith("deny:")
    assert policy.decide_http("GET", "/v1/studies/S1", "operator").action == "allow"
    assert policy.decide_http("GET", "/other", "operator").rule == "allow:none"
    assert policy.decide("excel__read_cell", "operator").action == "allow"
    empty = Policy(allow=["*"], deny=[], write_tools=[], http_allow=[], http_deny=[])
    assert empty.decide_http("GET", "/v1/studies/S1", "operator").rule == "allow:none"
    assert empty.decide("excel__read_cell", "operator").action == "allow"


def test_empty_http_allow_does_not_deny_mcp(build) -> None:
    env = build()
    proxy = env["proxies"]["operator"]
    assert proxy.settings.policy.http_allow == []
    response = call_tool(proxy, "excel__read_cell", {"cell": "A1"})
    assert "error" not in response
    assert response["result"].get("isError") is not True


def test_tls_verification_cannot_be_disabled(tmp_path: Path) -> None:
    material = _issue(tmp_path)
    context = tls13_context(str(material.ca_cert))
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert context.maximum_version is ssl.TLSVersion.TLSv1_3
    assert len(context.get_ca_certs()) == 1
    with pytest.raises(TlsRequired):
        HttpsApiClient("http://127.0.0.1/v1", ca_file=None, headers=None, timeout=1, max_body_bytes=100)
    with pytest.raises(ConfigurationError, match="mode must be"):
        _load(
            tmp_path,
            _gateway_config(material, 1, "https://127.0.0.1:9", mode="none"),
        )


def test_mixed_schema_chain_verifies(tmp_path: Path) -> None:
    store = JsonlAuditStore(tmp_path / "audit.jsonl", checkpoint_every=0)
    principal = {"id": "operator-1", "name": "Ada Analyst", "role": "operator"}
    client = {"id": "test", "name": "test", "version": None, "model_id": None}
    legacy = build_event(
        method="tools/call",
        record_class="access",
        status="ok",
        server="excel",
        principal=principal,
        client=client,
        protocol_version="2025-11-25",
        session_id=None,
        tool="excel__read_cell",
        arguments={"cell": "A1"},
        result={"ok": True},
    )
    for key in ("transport", "channel", "flow", "http"):
        legacy.pop(key)
    legacy["schema_version"] = "1.1.0"
    store.append_event(legacy)
    current = build_event(
        method="GET",
        record_class="access",
        status="ok",
        server="api",
        principal=principal,
        client=client,
        protocol_version=None,
        session_id=None,
        tool="http:GET /v1/studies/{study}",
        arguments={"path": "/v1/studies/S1"},
        transport="https",
        channel="https",
        flow="api2api",
        http={
            "body": None,
            "body_mode": "hash_only",
            "body_sha256": EMPTY_HASH,
            "headers": {},
            "kind": "api",
            "latency_ms": 0,
            "method": "GET",
            "path": "/v1/studies/S1",
            "route": "/v1/studies/{study}",
            "status": 200,
            "stripped_credential_headers": [],
        },
    )
    store.append_event(current)
    report = verify_file(tmp_path / "audit.jsonl")
    assert report.ok, report.errors
    assert [item["schema_version"] for item in report.entries] == ["1.1.0", "1.2.0"]
    for entry in report.entries:
        VALIDATOR.validate(entry)


def test_six_flows_policy_body_and_identity(tmp_path: Path) -> None:
    material = _issue(tmp_path)
    lab = _LabServer(material.server_cert, material.server_key)
    lab_thread = threading.Thread(target=lab.serve_forever, daemon=True)
    lab_thread.start()
    try:
        port = lab.server_address[1]
        origin = f"https://127.0.0.1:{port}"
        _exercise_mcp_flows(tmp_path / "mcp", material, origin)
        gateway = _start_gateway(tmp_path / "gw", material, origin)
        try:
            _exercise_https_flows(gateway, material, lab)
        finally:
            gateway.server.shutdown()
            gateway.server.server_close()
    finally:
        lab.shutdown()
        lab.server_close()


def _exercise_mcp_flows(directory: Path, material: SimpleNamespace, origin: str) -> None:
    directory.mkdir()
    config = {
        "principal": {"id": "operator-1", "name": "Ada Analyst", "role": "operator"},
        "policy": {
            "allow": ["lab__*", "api__*", "llm__*"],
            "deny": [],
            "write_tools": ["llm__chat"],
            "require_reason_for_writes": True,
            "http_allow": [],
        },
        "audit": {"path": str(directory / "audit.jsonl"), "body_mode": "hash_only", "fail_closed": True},
        "upstreams": _upstreams(material, origin),
    }
    path = directory / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    proxy = build_proxy(_load(directory, config))
    proxy.startup()
    mcp = call_tool(proxy, "lab__hello", {})
    assert mcp["result"]["content"][0]["text"] == "lab-ok"
    api = call_tool(proxy, "api__get_study", {"study": "S1"})
    assert "S1" in api["result"]["content"][0]["text"]
    denied = call_tool(proxy, "llm__chat", {"body": {"prompt": "hi"}})
    assert denied["result"]["isError"] is True
    allowed = call_tool(
        proxy,
        "llm__chat",
        {"body": {"prompt": "hi"}},
        {"io.github.antonio-castellon/reason": "draft a note"},
    )
    assert allowed["result"]["isError"] is not True
    rows = _rows(directory / "audit.jsonl")
    by_flow = {row.get("flow"): row for row in rows if row.get("tool")}
    assert by_flow["mcp2mcp"]["transport"] == "stdio"
    assert by_flow["mcp2mcp"]["channel"] == "mcp"
    assert by_flow["mcp2mcp"]["http"] is None
    assert by_flow["mcp2api"]["http"]["kind"] == "api"
    assert by_flow["mcp2api"]["http"]["body_sha256"] == EMPTY_HASH
    assert by_flow["mcp2api"]["http"]["body"] is None
    assert by_flow["mcp2api"]["http"]["method"] == "GET"
    assert "authorization" in by_flow["mcp2api"]["http"]["stripped_credential_headers"]
    assert by_flow["mcp2llm"]["flow"] == "mcp2llm"
    assert by_flow["mcp2llm"]["http"]["kind"] == "llm"
    assert by_flow["mcp2llm"]["http"]["body_sha256"]
    text = (directory / "audit.jsonl").read_text(encoding="utf-8")
    assert "upstream-secret-do-not-log" not in text
    report = verify_file(directory / "audit.jsonl")
    assert report.ok, report.errors
    for entry in report.entries:
        VALIDATOR.validate(entry)


def _exercise_https_flows(gateway: SimpleNamespace, material: SimpleNamespace, lab: _LabServer) -> None:
    proxy = gateway.proxy
    before = len(lab.hits)
    status, body, _headers = _request(
        gateway,
        "GET",
        "/v1/studies/S1?token=query-secret",
        material=material,
        headers={"X-Api-Key": "header-secret"},
    )
    assert status == 200
    assert b"S1" in body
    hit = lab.hits[-1]
    assert hit[0] == "GET"
    assert hit[1].startswith("/studies/S1?")
    assert "query-secret" in hit[1]
    record = _latest(gateway.log, flow="api2api")
    assert record["transport"] == "https"
    assert record["channel"] == "https"
    assert record["method"] == "GET"
    assert record["principal"]["id"] == "operator-9"
    assert record["http"]["path"] == "/v1/studies/S1"
    assert "query-secret" not in json.dumps(record)
    assert record["http"]["body_sha256"] == EMPTY_HASH
    assert record["http"]["body"] is None
    assert record["http"]["body_mode"] == "hash_only"
    assert "x-api-key" in record["http"]["stripped_credential_headers"]
    assert "header-secret" not in gateway.log.read_text(encoding="utf-8")

    hidden, _, _ = _request(gateway, "GET", "/v1/studies/hidden", material=material)
    assert hidden == 403
    denied = _latest(gateway.log, status="denied")
    assert denied["policy_decision"]["rule"].startswith("deny:")
    assert len(lab.hits) == before + 1

    missing, _, _ = _request(gateway, "GET", "/health", material=material)
    assert missing == 403
    assert _latest(gateway.log, tool="http:GET /health")["policy_decision"]["rule"] == "allow:none"

    nope, _, _ = _request(gateway, "GET", "/missing", material=material)
    assert nope == 404

    qa, _, _ = _request(gateway, "GET", "/v1/studies/S1", material=material, which="qa")
    assert qa == 403
    assert _latest(gateway.log, status="denied")["policy_decision"]["rule"] == "role:qa"

    bare, _, _ = _request(gateway, "POST", "/v1/studies/S1", material=material, body=b"{}")
    assert bare == 403
    assert "X-Audit-Reason" in _latest(gateway.log, status="denied")["error"]["message"]

    proxy.settings.body_mode = "redacted"
    proxy.settings.redact_paths = ("$.password",)
    posted = b'{"password":"secret","n":1}'
    status, body, _headers = _request(
        gateway,
        "POST",
        "/v1/studies/S1",
        material=material,
        body=posted,
        headers={"X-Audit-Reason": "record a result"},
    )
    assert status == 200
    assert b"saved" in body
    redacted = _latest(gateway.log, flow="api2api", method="POST")
    assert redacted["http"]["body_mode"] == "redacted"
    assert redacted["http"]["body"] == {"password": "***", "n": 1}
    assert redacted["http"]["body_sha256"] == sha256_hex(posted)
    assert "secret" not in json.dumps(redacted["http"]["body"])

    proxy.settings.body_mode = "full"
    status, _body, _headers = _request(
        gateway,
        "POST",
        "/v1/studies/S1",
        material=material,
        body=posted,
        headers={"X-Audit-Reason": "record a result"},
    )
    assert status == 200
    full = _latest(gateway.log, flow="api2api", method="POST")
    assert full["http"]["body"] == {"password": "secret", "n": 1}
    assert full["http"]["body_sha256"] == sha256_hex(posted)
    assert full["result"]["response_body"] == '{"saved":true}'

    proxy.settings.body_mode = "hash_only"
    status, body, _headers = _request(
        gateway,
        "POST",
        "/tools/hello",
        material=material,
        body=b'{"note":"hi"}',
        headers={"X-Audit-Reason": "call the tool"},
    )
    assert status == 200, body
    assert b"lab-ok" in body
    bridged = _latest(gateway.log, flow="api2mcp")
    assert bridged["method"] == "POST"
    assert bridged["http"]["route"] == "/tools/hello"
    assert bridged["http"]["kind"] == "mcp"
    assert bridged["tool"] == "lab__hello"
    assert sum(1 for row in _rows(gateway.log) if row.get("flow") == "api2mcp") == 1

    status, body, _headers = _request(
        gateway,
        "POST",
        "/v1/chat",
        material=material,
        body=b'{"prompt":"hi"}',
        headers={"X-Audit-Reason": "ask the model"},
    )
    assert status == 200, body
    assert b"hello" in body
    llm = _latest(gateway.log, flow="api2llm")
    assert llm["http"]["kind"] == "llm"
    assert llm["http"]["body_sha256"] == sha256_hex(b'{"prompt":"hi"}')

    proxy.settings.max_body_bytes = 16
    too_big, _, _ = _request(
        gateway,
        "POST",
        "/v1/studies/S1",
        material=material,
        body=b'{"password":"this body is far too long"}',
        headers={"X-Audit-Reason": "too big"},
    )
    assert too_big == 413
    limited = _latest(gateway.log, status="denied")
    assert limited["http"]["body_sha256"] is None
    assert limited["policy_decision"]["rule"] == "body:size"
    proxy.settings.max_body_bytes = 1_048_576

    _request_without_length(gateway, material)
    empty = _latest(gateway.log, flow="api2api", method="POST")
    assert empty["http"]["body_sha256"] == EMPTY_HASH

    proxy.settings.policy.require_approval_for_writes = True
    proxy.settings.body_mode = "hash_only"
    approval_body = b'{"n":2}'
    status, body, _headers = _request(
        gateway,
        "POST",
        "/v1/studies/S2",
        material=material,
        body=approval_body,
        headers={"X-Audit-Reason": "needs a second person"},
    )
    assert status == 403
    pending = json.loads(body)
    expect = args_hash(
        "http:POST /v1/studies/{study}",
        {"body_sha256": sha256_hex(approval_body), "path": "/v1/studies/S2"},
    )
    assert pending["args_hash"] == expect
    assert "approval_id" in pending
    proxy.settings.principal = Principal(id="approver-1", name="Ben Reviewer", role="approver")
    approved = proxy._approve(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}},
        {"approval_id": pending["approval_id"], "meaning": "approved"},
    )
    assert approved["result"]["isError"] is not True
    status, body, _headers = _request(
        gateway,
        "POST",
        "/v1/studies/S2",
        material=material,
        body=approval_body,
        headers={
            "X-Audit-Reason": "needs a second person",
            "X-Audit-Approval": pending["approval_id"],
        },
    )
    assert status == 200, body
    consumed = _latest(gateway.log, flow="api2api", method="POST")
    assert consumed["approval"]["status"] == "consumed"
    assert consumed["approval"]["args_hash"] == expect
    proxy.settings.policy.require_approval_for_writes = False

    marker = b"UPSTREAM-BODY-MARKER"
    original = proxy.store.append_event

    def fail_append(event: dict[str, Any]) -> dict[str, Any]:
        if event.get("flow") == "api2api":
            raise AuditStoreError("disk full")
        return original(event)

    proxy.store.append_event = fail_append  # type: ignore[method-assign]
    hits = len(lab.hits)
    status, body, _headers = _request(gateway, "GET", "/marker", material=material)
    assert status == 503
    assert marker not in body
    assert len(lab.hits) == hits + 1
    proxy.store.append_event = original  # type: ignore[method-assign]
    proxy._dead = False

    proxy.store.health = lambda: False  # type: ignore[method-assign]
    hits = len(lab.hits)
    status, body, _headers = _request(gateway, "GET", "/v1/studies/S1", material=material)
    assert status == 503
    assert len(lab.hits) == hits
    proxy._dead = False

    report = verify_file(gateway.log)
    assert report.ok, report.errors
    for entry in report.entries:
        if entry.get("schema_version") == "1.2.0":
            VALIDATOR.validate(entry)


def test_bearer_and_mtls_modes(tmp_path: Path) -> None:
    material = _issue(tmp_path)
    lab = _LabServer(material.server_cert, material.server_key)
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"https://127.0.0.1:{lab.server_address[1]}"
        loose = tmp_path / "loose.token"
        loose.write_text("bearer-secret-do-not-log\n", encoding="utf-8")
        loose.chmod(0o644)
        with pytest.raises(ConfigurationError, match="0600"):
            _start_gateway(tmp_path / "loose", material, origin, mode="bearer", token_file=loose)

        bearer = _start_gateway(tmp_path / "bearer", material, origin, mode="bearer")
        try:
            status, _body, _headers = _request(bearer, "GET", "/v1/studies/S1")
            assert status == 401
            missing = _latest(bearer.log, status="denied")
            assert missing["principal"]["id"] == "unauthenticated"
            assert missing["principal"]["role"] == "system"
            status, body, _headers = _request(
                bearer,
                "GET",
                "/v1/studies/S1",
                headers={"Authorization": "Bearer bearer-secret-do-not-log"},
            )
            assert status == 200, body
            assert _latest(bearer.log, flow="api2api")["principal"]["id"] == "gateway-1"
            status, _body, _headers = _request(
                bearer,
                "GET",
                "/v1/studies/S1",
                headers={"Authorization": "Bearer wrong-token"},
            )
            assert status == 401
            text = bearer.log.read_text(encoding="utf-8")
            assert "bearer-secret-do-not-log" not in text
            assert "wrong-token" not in text
        finally:
            bearer.server.shutdown()
            bearer.server.server_close()

        both = _start_gateway(tmp_path / "both", material, origin, mode="mtls_and_bearer")
        try:
            status, _body, _headers = _request(both, "GET", "/v1/studies/S1", material=material)
            assert status == 401
            status, _body, _headers = _request(
                both,
                "GET",
                "/v1/studies/S1",
                material=material,
                headers={"Authorization": "Bearer bearer-secret-do-not-log"},
            )
            assert status == 401
            assert _latest(both.log, status="denied")["policy_decision"]["rule"] == "identity:end-user"
            user, body, _headers = _request(
                both,
                "GET",
                "/v1/studies/S1",
                material=material,
                headers={
                    "Authorization": "Bearer bearer-secret-do-not-log",
                    "X-Audit-End-User": "operator-9",
                },
            )
            assert user == 200, body
            assert _latest(both.log, flow="api2api")["principal"]["id"] == "operator-9"
            rejected, _, _ = _request(
                both,
                "GET",
                "/v1/studies/S1",
                material=material,
                headers={
                    "Authorization": "Bearer bearer-secret-do-not-log",
                    "X-Audit-End-User": "somebody-else",
                },
            )
            assert rejected == 401
        finally:
            both.server.shutdown()
            both.server.server_close()

        mtls = _start_gateway(tmp_path / "mtls", material, origin, mode="mtls")
        try:
            _assert_plaintext_and_tls12_fail(mtls)
            before = len(_rows(mtls.log))
            _assert_plaintext_and_tls12_fail(mtls)
            assert len(_rows(mtls.log)) == before
        finally:
            mtls.server.shutdown()
            mtls.server.server_close()
    finally:
        lab.shutdown()
        lab.server_close()


def _assert_plaintext_and_tls12_fail(gateway: SimpleNamespace) -> None:
    port = gateway.port
    raw = socket.create_connection(("127.0.0.1", port), timeout=2)
    try:
        raw.sendall(b"GET /v1/studies/S1 HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        chunk = raw.recv(64)
    except OSError:
        chunk = b""
    finally:
        raw.close()
    assert not chunk.startswith(b"HTTP/")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with pytest.raises(ssl.SSLError):
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            context.wrap_socket(sock, server_hostname="127.0.0.1")
        finally:
            sock.close()


class _LabServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, cert_file: Path, key_file: Path) -> None:
        self.hits: list[tuple[str, str, bytes]] = []
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.load_cert_chain(str(cert_file), str(key_file))
        super().__init__(("127.0.0.1", 0), _LabHandler)

    def get_request(self) -> tuple[Any, Any]:
        sock, address = super().get_request()
        try:
            return self.ssl_context.wrap_socket(sock, server_side=True), address
        except ssl.SSLError:
            sock.close()
            raise


class _LabHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args

    def do_GET(self) -> None:  # noqa: N802
        self._serve()

    def do_POST(self) -> None:  # noqa: N802
        self._serve()

    def do_PUT(self) -> None:  # noqa: N802
        self._serve()

    def do_PATCH(self) -> None:  # noqa: N802
        self._serve()

    def do_DELETE(self) -> None:  # noqa: N802
        self._serve()

    def _serve(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(length) if length else b""
        server: _LabServer = self.server  # type: ignore[assignment]
        server.hits.append((self.command, self.path, body))
        path = urlparse(self.path).path
        if path == "/mcp":
            self._rpc(body)
            return
        if path == "/marker":
            self._send(200, b"UPSTREAM-BODY-MARKER")
            return
        if path.startswith("/studies/"):
            if self.command == "GET":
                study = path.rsplit("/", 1)[-1]
                self._send(200, json.dumps({"id": study}).encode("utf-8"))
                return
            self._send(200, b'{"saved":true}')
            return
        if path == "/v1/chat/completions":
            self._send(200, b'{"id":"c","choices":[{"message":{"content":"hello"}}]}')
            return
        self._send(404, b"{}")

    def _rpc(self, body: bytes) -> None:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(200, b"{}")
            return
        if not isinstance(payload, dict) or "id" not in payload:
            self._send(200, b"{}")
            return
        method = payload.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "serverInfo": {"name": "lab", "version": "0"},
            }
        elif method == "tools/call":
            result = {"content": [{"type": "text", "text": "lab-ok"}]}
        else:
            result = {}
        encoded = json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode("utf-8")
        self._send(200, encoded)

    def _send(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _start_gateway(
    directory: Path,
    material: SimpleNamespace,
    origin: str,
    *,
    mode: str = "mtls",
    token_file: Path | None = None,
) -> SimpleNamespace:
    directory.mkdir(parents=True, exist_ok=True)
    config = _gateway_config(material, 0, origin, mode=mode, token_file=token_file)
    config["audit"]["path"] = str(directory / "audit.jsonl")
    path = directory / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    proxy = build_proxy(_load(directory, config))
    proxy.startup()
    server = build_server(proxy, proxy.settings)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return SimpleNamespace(
        proxy=proxy,
        server=server,
        port=server.server_address[1],
        log=directory / "audit.jsonl",
        thread=thread,
        ca=material.ca_cert,
    )


def _gateway_config(
    material: SimpleNamespace,
    port: int,
    origin: str,
    *,
    mode: str,
    token_file: Path | None = None,
) -> dict[str, Any]:
    identity: dict[str, Any] = {"mode": mode}
    if mode in {"mtls", "mtls_and_bearer"}:
        identity["client_ca_file"] = str(material.ca_cert)
        identity["principals"] = [
            {
                "fingerprint": material.operator_fingerprint,
                "id": "operator-9",
                "name": "Ada Analyst",
                "role": "operator",
            },
            {
                "fingerprint": material.qa_fingerprint,
                "id": "qa-9",
                "name": "Cara QA",
                "role": "qa",
            },
        ]
    if mode in {"bearer", "mtls_and_bearer"}:
        identity["bearer_token_file"] = str(token_file or material.bearer)
        identity["bearer_principal"] = {"id": "gateway-1", "name": "Lab Gateway", "role": "operator"}
    if mode == "mtls_and_bearer":
        identity["end_user_header"] = "X-Audit-End-User"
        identity["end_users"] = [
            {"id": "operator-9", "name": "Ada Analyst", "role": "operator"},
        ]
    return {
        "principal": {"id": "operator-1", "name": "Ada Analyst", "role": "operator"},
        "policy": {
            "allow": ["lab__*", "api__*", "llm__*"],
            "deny": [],
            "write_tools": [],
            "require_reason_for_writes": True,
            "require_approval_for_writes": False,
            "http_allow": [
                "GET /v1/studies/*",
                "POST /v1/studies/*",
                "POST /v1/chat",
                "POST /tools/hello",
                "GET /marker",
            ],
            "http_deny": ["GET /v1/studies/hidden", "POST /v1/studies/secret"],
        },
        "audit": {"path": "audit.jsonl", "body_mode": "hash_only", "fail_closed": True},
        "listen": {
            "bind": "127.0.0.1",
            "port": port,
            "cert_file": str(material.server_cert),
            "key_file": str(material.server_key),
            "identity": identity,
        },
        "routes": [
            {
                "flow": "api2api",
                "methods": ["GET", "POST"],
                "path": "/v1/studies/{study}",
                "upstream": "api",
                "upstream_path": "/studies/{study}",
            },
            {
                "flow": "api2api",
                "methods": ["GET"],
                "path": "/marker",
                "upstream": "api",
                "upstream_path": "/marker",
            },
            {
                "flow": "api2api",
                "methods": ["GET"],
                "path": "/health",
                "upstream": "api",
                "upstream_path": "/health",
            },
            {
                "flow": "api2mcp",
                "methods": ["POST"],
                "path": "/tools/hello",
                "upstream": "lab",
                "tool": "hello",
            },
            {
                "flow": "api2llm",
                "methods": ["POST"],
                "path": "/v1/chat",
                "upstream": "llm",
                "upstream_path": "/v1/chat/completions",
            },
        ],
        "upstreams": _upstreams(material, origin),
    }


def _upstreams(material: SimpleNamespace, origin: str) -> list[dict[str, Any]]:
    return [
        {
            "name": "lab",
            "transport": "https",
            "kind": "mcp",
            "protocol": "legacy",
            "url": origin + "/mcp",
            "ca_file": str(material.ca_cert),
        },
        {
            "name": "api",
            "transport": "https",
            "kind": "api",
            "url": origin,
            "ca_file": str(material.ca_cert),
            "headers": {"Authorization": "Bearer upstream-secret-do-not-log"},
            "endpoints": [{"tool": "get_study", "method": "GET", "path": "/studies/{study}"}],
        },
        {
            "name": "llm",
            "transport": "https",
            "kind": "llm",
            "url": origin,
            "ca_file": str(material.ca_cert),
            "endpoints": [{"tool": "chat", "method": "POST", "path": "/v1/chat/completions"}],
        },
    ]


def _load(directory: Path, config: dict[str, Any]) -> Any:
    path = directory / "config.json"
    if not path.exists():
        directory.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(config), encoding="utf-8")
    saved = {key: os.environ.pop(key) for key in list(os.environ) if key.startswith("GLP_")}
    try:
        return load_settings(path)
    finally:
        os.environ.update(saved)


def _request(
    gateway: SimpleNamespace,
    method: str,
    path: str,
    *,
    material: SimpleNamespace | None = None,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    which: str = "operator",
) -> tuple[int, bytes, dict[str, str]]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=str(gateway.ca))
    context.check_hostname = True
    if material is not None and gateway.proxy.settings.listen.identity.mode in {"mtls", "mtls_and_bearer"}:
        cert = material.operator_cert if which == "operator" else material.qa_cert
        key = material.operator_key if which == "operator" else material.qa_key
        context.load_cert_chain(str(cert), str(key))
    connection = http.client.HTTPSConnection("127.0.0.1", gateway.port, context=context, timeout=5)
    try:
        outbound = dict(headers or {})
        if body is not None:
            outbound.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=body, headers=outbound)
        response = connection.getresponse()
        payload = response.read()
        return response.status, payload, {key: value for key, value in response.getheaders()}
    finally:
        connection.close()


def _request_without_length(gateway: SimpleNamespace, material: SimpleNamespace) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=str(material.ca_cert))
    context.check_hostname = True
    context.load_cert_chain(str(material.operator_cert), str(material.operator_key))
    sock = socket.create_connection(("127.0.0.1", gateway.port), timeout=5)
    tls = context.wrap_socket(sock, server_hostname="127.0.0.1")
    try:
        tls.sendall(
            b"POST /v1/studies/S1 HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"X-Audit-Reason: empty body\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b'{"ignored":true}'
        )
        chunks = []
        while True:
            piece = tls.recv(4096)
            if not piece:
                break
            chunks.append(piece)
    finally:
        tls.close()
    raw = b"".join(chunks)
    assert raw.startswith(b"HTTP/1.1 200"), raw


def _rows(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _latest(path: Path, **match: object) -> dict[str, Any]:
    found = None
    for row in _rows(path):
        if all(row.get(key) == value for key, value in match.items()):
            found = row
    assert found is not None, match
    return found


def _issue(directory: Path) -> SimpleNamespace:
    directory.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = _certificate(common_name="lab-ca", ca=True)
    server_key, server_cert = _certificate(
        common_name="127.0.0.1",
        issuer_key=ca_key,
        issuer=ca_cert,
        san=True,
        server=True,
    )
    operator_key, operator_cert = _certificate(
        common_name="operator-9",
        issuer_key=ca_key,
        issuer=ca_cert,
        client=True,
    )
    qa_key, qa_cert = _certificate(
        common_name="qa-9",
        issuer_key=ca_key,
        issuer=ca_cert,
        client=True,
    )
    paths = SimpleNamespace(
        ca_cert=directory / "ca.pem",
        server_cert=directory / "server.pem",
        server_key=directory / "server.key",
        operator_cert=directory / "operator.pem",
        operator_key=directory / "operator.key",
        qa_cert=directory / "qa.pem",
        qa_key=directory / "qa.key",
        bearer=directory / "bearer.token",
    )
    _write_cert(paths.ca_cert, ca_cert)
    _write_cert(paths.server_cert, server_cert)
    _write_key(paths.server_key, server_key)
    _write_cert(paths.operator_cert, operator_cert)
    _write_key(paths.operator_key, operator_key)
    _write_cert(paths.qa_cert, qa_cert)
    _write_key(paths.qa_key, qa_key)
    paths.bearer.write_text("bearer-secret-do-not-log\n", encoding="utf-8")
    paths.bearer.chmod(0o600)
    paths.operator_fingerprint = cert_fingerprint(operator_cert.public_bytes(serialization.Encoding.DER))
    paths.qa_fingerprint = cert_fingerprint(qa_cert.public_bytes(serialization.Encoding.DER))
    return paths


def _certificate(
    *,
    common_name: str,
    ca: bool = False,
    issuer_key: Any = None,
    issuer: x509.Certificate | None = None,
    san: bool = False,
    server: bool = False,
    client: bool = False,
) -> tuple[Any, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject if issuer is not None else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    else:
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
    eku = []
    if server:
        eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if client:
        eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    signed = builder.sign(issuer_key or key, hashes.SHA256())
    return key, signed


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path: Path, key: Any) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
