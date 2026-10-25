"""HTTPS inbound reverse proxy. TLS 1.3 only. There is no plaintext listener.

The client keeps its request and changes the base URL to this listener.
One audit record is written per request. If that write fails, the upstream
body is not returned.
"""

from __future__ import annotations

import json
import logging
import ssl
import threading
import time
import uuid
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import quote, urlparse

from ..approvals import load_approvals
from ..bodyutil import filter_headers, prepare_body
from ..canonical import args_hash
from ..config import ListenConfig, RouteConfig, Settings
from ..errors import AuditStoreError, ConfigurationError, TlsRequired, UpstreamError
from ..proxy import _approval_problem
from ..records import build_event, format_timestamp
from .https_outbound import HttpsApiClient
from .identity import cert_fingerprint, read_bearer, same_secret

_LOG = logging.getLogger("mcp_glp_audit_proxy.technical")
_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)
_LOCAL_APPROVE = "/_glp/approve"


class GatewayServer(ThreadingHTTPServer):
    """TLS socket wrapped before ``serve_forever``. Daemon threads so tests can stop it."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, proxy: Any, settings: Settings) -> None:
        listen = settings.listen
        if listen is None:
            raise ConfigurationError("HTTPS listener is not configured")
        self.proxy = proxy
        self.settings = settings
        self.lock = threading.Lock()
        self.ssl_context = server_context(listen)
        self.bearer_token: str | None = None
        super().__init__((listen.bind, listen.port), _Handler)

    def get_request(self) -> tuple[Any, Any]:
        sock, address = super().get_request()
        try:
            return self.ssl_context.wrap_socket(sock, server_side=True), address
        except ssl.SSLError:
            sock.close()
            raise


def build_server(proxy: Any, settings: Settings) -> GatewayServer:
    """Check identity files, then bind a TLS 1.3 socket. Does not call ``startup``."""
    listen = settings.listen
    if listen is None:
        raise ConfigurationError("HTTPS listener is not configured")
    token = _bearer_token(listen)
    server = GatewayServer(proxy, settings)
    server.bearer_token = token
    return server


def serve_https(proxy: Any, settings: Settings) -> None:
    logging.basicConfig(stream=__import__("sys").stderr, level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    try:
        proxy.startup()
        server = build_server(proxy, settings)
    except (ConfigurationError, AuditStoreError, OSError, ssl.SSLError) as exc:
        print(f"mcp-glp-audit-proxy: refusing to start: {exc}", file=__import__("sys").stderr)
        raise SystemExit(1) from exc
    try:
        server.serve_forever()
    finally:
        proxy.close()
        server.server_close()


def server_context(listen: ListenConfig) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(listen.cert_file, listen.key_file)
    mode = listen.identity.mode
    if mode in {"mtls", "mtls_and_bearer"}:
        if not listen.identity.client_ca_file:
            raise ConfigurationError("mTLS requires client_ca_file")
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=listen.identity.client_ca_file)
    else:
        # The listener still presents a certificate and speaks only TLS 1.3.
        # Client certificates are not requested. Bearer authentication is required.
        context.verify_mode = ssl.CERT_NONE  # nosec B501  # noqa: S501
    if context.minimum_version != ssl.TLSVersion.TLSv1_3:
        raise TlsRequired("the HTTPS listener requires TLS 1.3")
    return context


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        del fmt, args
        return None

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def _dispatch(self) -> None:
        server: GatewayServer = self.server  # type: ignore[assignment]
        with server.lock:
            try:
                status, content_type, body = handle_http(server.proxy, server.settings, self)
            except Exception:
                _LOG.error("https request failed")
                server.proxy._dead = True
                status = 503
                content_type = "application/json"
                body = _json_bytes({"error": "audit log unavailable; request was not completed"})
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


def handle_http(proxy: Any, settings: Settings, handler: BaseHTTPRequestHandler) -> tuple[int, str, bytes]:
    """One request. Returns the bytes the client may see."""
    if proxy._dead and settings.fail_closed:
        return _unavailable()
    try:
        proxy._refresh()
    except AuditStoreError:
        proxy._dead = True
        return _unavailable()
    parsed = urlparse(handler.path)
    path = parsed.path or "/"
    method = handler.command
    inbound_headers = handler_headers_safe(handler)
    raw, problem = _read_body(handler, settings.max_body_bytes)
    if problem == "body:size":
        handler.close_connection = True
    if problem:
        return _deny_http(
            proxy,
            settings,
            method=method,
            path=path,
            route=path,
            flow=None,
            raw=b"",
            status_code=413 if problem == "body:size" else 400,
            rule=problem,
            message="request body exceeds size limit" if problem == "body:size" else "request body was not accepted",
            principal=_system_principal(),
            kind=None,
            headers=inbound_headers,
        )
    if raw is None:
        proxy._dead = True
        return _unavailable()
    identity = settings.listen.identity if settings.listen else None
    if identity is None:
        proxy._dead = True
        return _unavailable()
    principal, rule = _authenticate(identity, handler)
    if principal is None:
        return _deny_http(
            proxy,
            settings,
            method=method,
            path=path,
            route=path,
            flow=None,
            raw=raw,
            status_code=401,
            rule=rule,
            message="authentication failed",
            principal=_system_principal(),
            kind=None,
            headers=inbound_headers,
        )
    if path == _LOCAL_APPROVE:
        return _approve(proxy, settings, principal, raw, inbound_headers)
    route, params = _match(settings.routes, method, path)
    if route is None:
        return _deny_http(
            proxy,
            settings,
            method=method,
            path=path,
            route=path,
            flow=None,
            raw=raw,
            status_code=404,
            rule="route:none",
            message="no route for this request",
            principal=principal,
            kind=None,
            headers=inbound_headers,
        )
    decision = settings.policy.decide_http(method, path, principal["role"])
    if decision.action == "deny":
        return _deny_http(
            proxy,
            settings,
            method=method,
            path=path,
            route=route.path,
            flow=route.flow,
            raw=raw,
            status_code=403,
            rule=decision.rule,
            message=f"denied by policy ({decision.rule})",
            principal=principal,
            kind=_kind_for(route.flow),
            headers=inbound_headers,
        )
    reason = handler.headers.get("X-Audit-Reason")
    is_write = settings.policy.is_http_write(method)
    if is_write and settings.policy.require_reason_for_writes and not reason:
        return _deny_http(
            proxy,
            settings,
            method=method,
            path=path,
            route=route.path,
            flow=route.flow,
            raw=raw,
            status_code=403,
            rule="write:reason-missing",
            message="X-Audit-Reason is required for this method",
            principal=principal,
            kind=_kind_for(route.flow),
            headers=inbound_headers,
        )
    prepared = prepare_body(raw, mode=settings.body_mode, redact_paths=settings.redact_paths)
    tool = f"http:{method} {route.path}"
    approval_arguments = {"body_sha256": prepared["body_sha256"], "path": path}
    digest = args_hash(tool, approval_arguments)
    approval_id = handler.headers.get("X-Audit-Approval")
    if is_write and settings.policy.require_approval_for_writes:
        gate = _approval_gate(
            proxy,
            settings,
            principal,
            method=method,
            path=path,
            route=route,
            raw=raw,
            reason=reason,
            digest=digest,
            tool=tool,
            approval_id=approval_id,
            headers=inbound_headers,
        )
        if gate is not None:
            return gate
    if route.flow == "api2mcp":
        return _forward_mcp(
            proxy,
            settings,
            principal,
            route,
            params,
            raw,
            path,
            method,
            reason,
            approval_id,
            prepared,
            inbound_headers,
        )
    return _forward_https(
        proxy,
        settings,
        principal,
        route,
        params,
        raw,
        path,
        method,
        reason,
        parsed.query,
        prepared,
        tool,
        approval_arguments,
        approval_id,
        is_write,
        inbound_headers,
    )


def _forward_https(
    proxy: Any,
    settings: Settings,
    principal: dict[str, Any],
    route: RouteConfig,
    params: dict[str, str],
    raw: bytes,
    path: str,
    method: str,
    reason: str | None,
    query: str,
    prepared: dict[str, Any],
    tool: str,
    approval_arguments: dict[str, Any],
    approval_id: str | None,
    is_write: bool,
    headers: dict[str, str],
) -> tuple[int, str, bytes]:
    upstream = _upstream_config(settings, route.upstream)
    if upstream is None:
        return _deny_http(
            proxy,
            settings,
            method=method,
            path=path,
            route=route.path,
            flow=route.flow,
            raw=raw,
            status_code=502,
            rule="upstream:unknown",
            message="upstream is not configured",
            principal=principal,
            kind=_kind_for(route.flow),
            headers=headers,
        )
    target = _fill(route.upstream_path or route.path, params)
    if query:
        target = target + "?" + query
    client = HttpsApiClient(
        str(upstream.url),
        ca_file=upstream.ca_file,
        headers=upstream.headers,
        timeout=upstream.timeout if upstream.timeout is not None else 30.0,
        max_body_bytes=settings.max_body_bytes,
    )
    started = time.perf_counter()
    try:
        status, content_type, body = client.request(method, target, raw or None)
    except (UpstreamError, TlsRequired):
        wrote = _audit_forward_failure(proxy, settings, principal, route, path, method, raw, reason, headers)
        if not wrote:
            return _unavailable()
        return 502, "application/json", _json_bytes({"error": "upstream failed"})
    http_view = _view(
        method,
        route.path,
        path,
        headers,
        prepared,
        status,
        started,
        _kind_for(route.flow),
    )
    stored = {"status": status, "response_sha256": prepare_body(body, mode="hash_only", redact_paths=())["body_sha256"]}
    if settings.body_mode == "full":
        stored["response_body"] = body.decode("utf-8", errors="replace")
    approval = None
    if is_write and approval_id:
        approval = _consumed(proxy, principal, tool, approval_arguments, approval_id)
    try:
        _append(
            proxy,
            principal=principal,
            method=method,
            record_class="gxp_data" if is_write else "access",
            status="ok" if status < 400 else "failed",
            server=route.upstream,
            tool=tool,
            arguments={"path": path, "body_sha256": prepared["body_sha256"]},
            result=stored,
            error={"message": "upstream status"} if status >= 400 else None,
            policy_action="allow",
            policy_rule="allow",
            reason=reason,
            approval=approval if status < 400 else None,
            flow=route.flow,
            http=http_view,
        )
    except AuditStoreError:
        proxy._dead = True
        return _unavailable()
    safe_type = content_type if content_type and "\n" not in content_type and "\r" not in content_type else "application/octet-stream"
    return status, safe_type, body


def _forward_mcp(
    proxy: Any,
    settings: Settings,
    principal: dict[str, Any],
    route: RouteConfig,
    params: dict[str, str],
    raw: bytes,
    path: str,
    method: str,
    reason: str | None,
    approval_id: str | None,
    prepared: dict[str, Any],
    headers: dict[str, str],
) -> tuple[int, str, bytes]:
    tool_name = route.tool or ""
    for key, value in params.items():
        tool_name = tool_name.replace("{" + key + "}", value)
    if not tool_name:
        return _deny_http(
            proxy,
            settings,
            method=method,
            path=path,
            route=route.path,
            flow=route.flow,
            raw=raw,
            status_code=500,
            rule="route:tool",
            message="route has no MCP tool",
            principal=principal,
            kind="mcp",
            headers=headers,
        )
    exposed = tool_name if "__" in tool_name else f"{route.upstream}__{tool_name}"
    arguments: dict[str, Any] = {}
    if raw:
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
        if isinstance(parsed, dict):
            arguments.update(parsed)
    arguments.update(params)
    meta: dict[str, Any] = {}
    if reason:
        meta["io.github.antonio-castellon/reason"] = reason
    preauthorized = bool(
        settings.policy.require_approval_for_writes and settings.policy.is_http_write(method)
    )
    if approval_id and not preauthorized:
        meta["io.github.antonio-castellon/approvalId"] = approval_id
    message = {
        "jsonrpc": "2.0",
        "id": "https",
        "method": "tools/call",
        "params": {"name": exposed, "arguments": arguments, "_meta": meta},
    }
    started = time.perf_counter()
    http_view = _view(method, route.path, path, headers, prepared, None, started, "mcp")
    http_view["_started"] = started
    from ..config import Principal

    previous = proxy.settings.principal
    previous_fields = (
        proxy._record_transport,
        proxy._record_channel,
        proxy._record_flow,
        proxy._record_http,
    )
    proxy.settings.principal = Principal(
        id=str(principal["id"]),
        name=str(principal.get("name") or ""),
        role=str(principal["role"]),
    )
    proxy._record_transport = "https"
    proxy._record_channel = "https"
    proxy._record_flow = "api2mcp"
    proxy._record_http = http_view
    proxy._http_preauthorized = preauthorized
    if approval_id and preauthorized:
        proxy._inbound_approval = _consumed(
            proxy,
            principal,
            f"http:{method} {route.path}",
            {"body_sha256": prepared["body_sha256"], "path": path},
            approval_id,
        )
    try:
        response = proxy._upstream_call(message, exposed, arguments)
    finally:
        proxy.settings.principal = previous
        (
            proxy._record_transport,
            proxy._record_channel,
            proxy._record_flow,
            proxy._record_http,
        ) = previous_fields
        proxy._http_preauthorized = False
        proxy._inbound_approval = None
    return _mcp_http(response)


def _mcp_http(response: dict[str, Any]) -> tuple[int, str, bytes]:
    if "error" in response:
        return 502, "application/json", _json_bytes({"error": "upstream failed"})
    result = response.get("result")
    if not isinstance(result, dict):
        return 502, "application/json", _json_bytes({"error": "upstream failed"})
    if result.get("isError"):
        text = ""
        content = result.get("content")
        if isinstance(content, list) and content and isinstance(content[0], dict):
            text = str(content[0].get("text") or "")
        status = 403
        if "approval_id=" in text:
            status = 403
        return status, "application/json", _json_bytes({"error": text or "denied"})
    structured = result.get("structuredContent")
    if structured is not None:
        return 200, "application/json", _json_bytes(structured)
    content = result.get("content")
    text = ""
    if isinstance(content, list) and content and isinstance(content[0], dict):
        text = str(content[0].get("text") or "")
    return 200, "application/json", _json_bytes({"text": text})


def _approve(
    proxy: Any,
    settings: Settings,
    principal: dict[str, Any],
    raw: bytes,
    headers: dict[str, str] | None = None,
) -> tuple[int, str, bytes]:
    if principal["role"] != "approver":
        return _deny_http(
            proxy,
            settings,
            method="POST",
            path=_LOCAL_APPROVE,
            route=_LOCAL_APPROVE,
            flow=None,
            raw=raw,
            status_code=403,
            rule=f"role:{principal['role']}",
            message="only an approver may record an approval",
            principal=principal,
            kind=None,
            headers=headers,
        )
    try:
        payload = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if not isinstance(payload, dict):
        return _deny_http(
            proxy,
            settings,
            method="POST",
            path=_LOCAL_APPROVE,
            route=_LOCAL_APPROVE,
            flow=None,
            raw=raw,
            status_code=400,
            rule="approve:body",
            message="approval body must be a JSON object",
            principal=principal,
            kind=None,
            headers=headers,
        )
    from ..config import Principal

    message = {
        "jsonrpc": "2.0",
        "id": "https",
        "method": "tools/call",
        "params": {"name": "glp_approve", "arguments": payload},
    }
    previous = proxy.settings.principal
    previous_fields = (
        proxy._record_transport,
        proxy._record_channel,
        proxy._record_flow,
        proxy._record_http,
    )
    proxy.settings.principal = Principal(
        id=str(principal["id"]),
        name=str(principal.get("name") or ""),
        role="approver",
    )
    proxy._record_transport = "https"
    proxy._record_channel = "https"
    proxy._record_flow = None
    proxy._record_http = None
    try:
        response = proxy._approve(message, payload if isinstance(payload, dict) else {})
    finally:
        proxy.settings.principal = previous
        (
            proxy._record_transport,
            proxy._record_channel,
            proxy._record_flow,
            proxy._record_http,
        ) = previous_fields
    result = response.get("result") if isinstance(response, dict) else None
    if isinstance(result, dict) and result.get("isError"):
        return 403, "application/json", _json_bytes(result)
    return 200, "application/json", _json_bytes(result or {"ok": True})


def _approval_gate(
    proxy: Any,
    settings: Settings,
    principal: dict[str, Any],
    *,
    method: str,
    path: str,
    route: RouteConfig,
    raw: bytes,
    reason: str | None,
    digest: str,
    tool: str,
    approval_id: str | None,
    headers: dict[str, str],
) -> tuple[int, str, bytes] | None:
    if not approval_id:
        approval_record_id = str(uuid.uuid4())
        expires = proxy._now() + timedelta(seconds=settings.approval_ttl_seconds)
        approval = {
            "approval_id": approval_record_id,
            "approver_id": None,
            "approver_name": None,
            "args_hash": digest,
            "decided_at": None,
            "expires_at": format_timestamp(expires),
            "label": "approval",
            "meaning": None,
            "status": "pending",
            "tool": tool,
        }
        try:
            _append(
                proxy,
                principal=principal,
                method=method,
                record_class="gxp_data",
                status="pending_approval",
                server=route.upstream,
                tool=tool,
                arguments={"path": path, "body_sha256": prepare_body(raw, mode="hash_only", redact_paths=())["body_sha256"]},
                result={"approval_id": approval_record_id},
                error=None,
                policy_action="require_approval",
                policy_rule="write:approval",
                reason=reason,
                approval=approval,
                flow=route.flow,
                http=_view(
                    method,
                    route.path,
                    path,
                    headers,
                    prepare_body(raw, mode=settings.body_mode, redact_paths=settings.redact_paths),
                    None,
                    time.perf_counter(),
                    _kind_for(route.flow),
                ),
            )
        except AuditStoreError:
            proxy._dead = True
            return _unavailable()
        return (
            403,
            "application/json",
            _json_bytes(
                {
                    "error": "approval required",
                    "approval_id": approval_record_id,
                    "args_hash": digest,
                }
            ),
        )
    record = load_approvals(proxy.store.read_entries()).get(str(approval_id))
    problem = _approval_problem(
        record,
        tool=tool,
        digest=digest,
        requester=str(principal["id"]),
        now=proxy._now(),
    )
    if problem:
        return _deny_http(
            proxy,
            settings,
            method=method,
            path=path,
            route=route.path,
            flow=route.flow,
            raw=raw,
            status_code=403,
            rule=f"approval:{problem}",
            message=f"approval refused ({problem})",
            principal=principal,
            kind=_kind_for(route.flow),
            headers=headers,
        )
    return None


def _consumed(
    proxy: Any,
    principal: dict[str, Any],
    tool: str,
    arguments: dict[str, Any],
    approval_id: str,
) -> dict[str, Any] | None:
    record = load_approvals(proxy.store.read_entries()).get(approval_id)
    if record is None:
        return None
    problem = _approval_problem(
        record,
        tool=tool,
        digest=args_hash(tool, arguments),
        requester=str(principal["id"]),
        now=proxy._now(),
    )
    if problem:
        return None
    return {
        "approval_id": record.approval_id,
        "approver_id": record.approver_id,
        "approver_name": record.approver_name,
        "args_hash": record.args_hash,
        "decided_at": record.decided_at,
        "expires_at": record.expires_at,
        "label": "approval",
        "meaning": record.meaning,
        "status": "consumed",
        "tool": tool,
    }


def _audit_forward_failure(
    proxy: Any,
    settings: Settings,
    principal: dict[str, Any],
    route: RouteConfig,
    path: str,
    method: str,
    raw: bytes,
    reason: str | None,
    headers: dict[str, str],
) -> bool:
    prepared = prepare_body(raw, mode=settings.body_mode, redact_paths=settings.redact_paths)
    try:
        _append(
            proxy,
            principal=principal,
            method=method,
            record_class="gxp_data" if settings.policy.is_http_write(method) else "access",
            status="failed",
            server=route.upstream,
            tool=f"http:{method} {route.path}",
            arguments={"path": path},
            result=None,
            error={"message": "upstream failed"},
            policy_action="allow",
            policy_rule="allow",
            reason=reason,
            approval=None,
            flow=route.flow,
            http=_view(method, route.path, path, headers, prepared, None, time.perf_counter(), _kind_for(route.flow)),
        )
    except AuditStoreError:
        proxy._dead = True
        return False
    return True


def _deny_http(
    proxy: Any,
    settings: Settings,
    *,
    method: str,
    path: str,
    route: str,
    flow: str | None,
    raw: bytes,
    status_code: int,
    rule: str,
    message: str,
    principal: dict[str, Any],
    kind: str | None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str, bytes]:
    prepared = prepare_body(raw, mode=settings.body_mode, redact_paths=settings.redact_paths)
    if rule in {"body:size", "body:short", "body:length"}:
        prepared = {"body_sha256": None, "body": None, "body_mode": settings.body_mode}
    try:
        _append(
            proxy,
            principal=principal,
            method=method,
            record_class="access",
            status="denied",
            server="proxy",
            tool=f"http:{method} {route}",
            arguments={"path": path},
            result=None,
            error={"message": message},
            policy_action="deny",
            policy_rule=rule,
            reason=None,
            approval=None,
            flow=flow,
            http=_view(method, route, path, headers or {}, prepared, status_code, time.perf_counter(), kind),
        )
    except AuditStoreError:
        proxy._dead = True
        return _unavailable()
    return status_code, "application/json", _json_bytes({"error": message})


def _append(proxy: Any, **kwargs: Any) -> dict[str, Any]:
    http = kwargs.pop("http")
    flow = kwargs.pop("flow")
    principal = kwargs.pop("principal")
    event = build_event(
        principal=principal,
        client={"id": "https", "name": "https", "version": None, "model_id": None},
        protocol_version=None,
        session_id=None,
        transport="https",
        channel="https",
        flow=flow,
        http=http,
        timestamp=format_timestamp(proxy._now()),
        **kwargs,
    )
    return proxy.store.append_event(event)


def _view(
    method: str,
    route: str,
    path: str,
    headers: dict[str, str],
    prepared: dict[str, Any],
    status: int | None,
    started: float,
    kind: str | None,
) -> dict[str, Any]:
    kept, stripped = filter_headers(headers)
    return {
        "body": prepared["body"],
        "body_mode": prepared["body_mode"],
        "body_sha256": prepared["body_sha256"],
        "headers": kept,
        "kind": kind,
        "latency_ms": max(0, int((time.perf_counter() - started) * 1000)),
        "method": method,
        "path": path,
        "route": route,
        "status": status,
        "stripped_credential_headers": stripped,
    }


def handler_headers_safe(handler: BaseHTTPRequestHandler | None) -> dict[str, str]:
    if handler is None:
        return {}
    kept: dict[str, str] = {}
    for key, value in handler.headers.items():
        if key.lower() in _HOP:
            continue
        if key.lower() in {"x-audit-reason", "x-audit-approval", "x-audit-end-user"}:
            continue
        kept[key] = value
    return kept


def _authenticate(identity: Any, handler: BaseHTTPRequestHandler) -> tuple[dict[str, Any] | None, str]:
    mode = identity.mode
    peer = _peer_der(handler)
    principal: dict[str, Any] | None = None
    if mode in {"mtls", "mtls_and_bearer"}:
        if not peer:
            return None, "identity:certificate"
        fingerprint = cert_fingerprint(peer)
        matched = None
        for item in identity.principals:
            if item.fingerprint and same_secret(fingerprint, item.fingerprint):
                matched = item
                break
        if matched is None:
            return None, "identity:certificate"
        principal = matched.as_dict()
    if mode in {"bearer", "mtls_and_bearer"}:
        expected = getattr(handler.server, "bearer_token", None)
        if not isinstance(expected, str):
            return None, "identity:bearer"
        presented = _bearer_header(handler)
        if not presented or not same_secret(presented, expected):
            return None, "identity:bearer"
        if principal is None and identity.bearer_principal is not None:
            principal = identity.bearer_principal.as_dict()
    if principal is None:
        return None, "identity:rejected"
    header_name = identity.end_user_header
    if header_name:
        raw = handler.headers.get(header_name)
        if not raw:
            return None, "identity:end-user"
        end_user = next((item for item in identity.end_users if item.id == raw), None)
        if end_user is None:
            return None, "identity:end-user"
        principal = end_user.as_dict()
    return principal, ""


def _bearer_header(handler: BaseHTTPRequestHandler) -> str:
    raw = handler.headers.get("Authorization") or ""
    scheme, sep, token = raw.partition(" ")
    if not sep or scheme.lower() != "bearer":
        return ""
    return token.strip()


def _peer_der(handler: BaseHTTPRequestHandler) -> bytes | None:
    sock = handler.connection
    getter = getattr(sock, "getpeercert", None)
    if getter is None:
        return None
    der = getter(binary_form=True)
    return der if isinstance(der, bytes) else None


def _read_body(handler: BaseHTTPRequestHandler, limit: int) -> tuple[bytes | None, str | None]:
    declared = handler.headers.get("Content-Length")
    if declared is None:
        return b"", None
    try:
        length = int(declared)
    except ValueError:
        return None, "body:length"
    if length < 0:
        return None, "body:length"
    if length > limit:
        return None, "body:size"
    data = handler.rfile.read(length)
    if len(data) != length:
        return None, "body:short"
    return data, None


def _match(routes: list[RouteConfig], method: str, path: str) -> tuple[RouteConfig | None, dict[str, str]]:
    for route in routes:
        if method not in route.methods:
            continue
        params = _match_template(route.path, path)
        if params is not None:
            return route, params
    return None, {}


def _match_template(template: str, path: str) -> dict[str, str] | None:
    from urllib.parse import unquote

    left = [part for part in template.split("/") if part]
    right = [part for part in path.split("/") if part]
    if len(left) != len(right):
        return None
    params: dict[str, str] = {}
    for item, got in zip(left, right, strict=True):
        if item.startswith("{") and item.endswith("}") and len(item) > 2:
            params[item[1:-1]] = unquote(got)
        elif item != unquote(got):
            return None
    return params


def _fill(template: str, params: dict[str, str]) -> str:
    filled = template
    for key, value in params.items():
        filled = filled.replace("{" + key + "}", quote(value, safe=""))
    return filled


def _upstream_config(settings: Settings, name: str) -> Any:
    for item in settings.upstreams or []:
        if item.name == name:
            return item
    return None


def _kind_for(flow: str) -> str:
    if flow.endswith("llm"):
        return "llm"
    if flow.endswith("mcp"):
        return "mcp"
    return "api"


def _system_principal() -> dict[str, Any]:
    return {"id": "unauthenticated", "name": None, "role": "system"}


def _bearer_token(listen: ListenConfig) -> str | None:
    identity = listen.identity
    if identity.mode not in {"bearer", "mtls_and_bearer"}:
        return None
    if not identity.bearer_token_file:
        raise ConfigurationError("bearer identity requires bearer_token_file")
    from pathlib import Path

    return read_bearer(Path(identity.bearer_token_file))


def _unavailable() -> tuple[int, str, bytes]:
    return 503, "application/json", _json_bytes({"error": "audit log unavailable; request was not completed"})


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")
