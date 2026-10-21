"""Mediating MCP proxy. Every forwarded or refused call is audited first.

The proxy is not a byte pipe. It accepts a fixed set of methods (complete
mediation), writes the audit entry, and only then returns the upstream
result. If the audit store cannot be written, the result is not returned.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

from . import __version__
from .approvals import load_approvals, parse_timestamp
from .canonical import args_hash
from .anchor import verify_anchored
from .config import Settings
from .errors import AuditStoreError, ChainIntegrityError, ConfigurationError
from .features import FeatureSet
from .framing import MAX_MESSAGE_BYTES
from .records import build_event, format_timestamp
from .reporters.json_export import JsonReporter, dumps_document, export_document, filter_entries
from .reporters.text_export import TextReporter, format_entry
from .upstream import MODERN_VERSION, SECRET_META, split_meta
from .wiring import REPORTERS_GROUP, feature_for

LEGACY_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
MODERN_VERSIONS = (MODERN_VERSION,)
MODEL_KEYS = ("gen_ai.request.model", "model", "io.modelcontextprotocol/model")

LOCAL_TOOLS: dict[str, dict[str, Any]] = {
    "glp_verify_chain": {
        "description": "Verify the append-only hash chain and list integrity errors.",
        "roles": frozenset({"qa", "admin", "approver"}),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "glp_search_audit": {
        "description": "Search the audit trail. Returns matching entries. QA, approver and admin only.",
        "roles": frozenset({"qa", "admin", "approver"}),
        "inputSchema": {
            "type": "object",
            "properties": {
                "record_class": {"type": "string"},
                "tool": {"type": "string"},
                "principal_id": {"type": "string"},
                "status": {"type": "string"},
                "method": {"type": "string"},
                "server": {"type": "string"},
                "since": {"type": "string"},
                "until": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    "glp_export_audit": {
        "description": (
            "Write an electronic export with a hash manifest. "
            "format selects a configured reporter (default json). PDF is Pro."
        ),
        "roles": frozenset({"qa", "admin", "approver"}),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "record_class": {"type": "string"},
                "tool": {"type": "string"},
                "principal_id": {"type": "string"},
                "status": {"type": "string"},
                "method": {"type": "string"},
                "server": {"type": "string"},
                "since": {"type": "string"},
                "until": {"type": "string"},
                "format": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    "glp_approve": {
        "description": (
            "Record an approval or rejection for a pending write. "
            "This is an approval, not an electronic signature."
        ),
        "roles": frozenset({"approver"}),
        "inputSchema": {
            "type": "object",
            "properties": {
                "approval_id": {"type": "string"},
                "meaning": {"type": "string", "enum": ["approved", "reviewed", "rejected"]},
            },
            "required": ["approval_id", "meaning"],
            "additionalProperties": False,
        },
    },
    "glp_update_policy": {
        "description": "Replace the tool policy. Admin only. The change is itself audited. Auditing cannot be disabled.",
        "roles": frozenset({"admin"}),
        "inputSchema": {
            "type": "object",
            "properties": {
                "allow": {"type": "array", "items": {"type": "string"}},
                "deny": {"type": "array", "items": {"type": "string"}},
                "write_tools": {"type": "array", "items": {"type": "string"}},
                "require_approval_for_writes": {"type": "boolean"},
                "require_reason_for_writes": {"type": "boolean"},
                "reason": {"type": "string"},
                "audit_enabled": {"type": "boolean"},
            },
            "required": ["reason"],
            "additionalProperties": False,
        },
    },
}


class Session:
    def __init__(self) -> None:
        self.era = "unknown"
        self.protocol_version: str | None = None
        self.session_id: str | None = None
        self.client_info: dict[str, Any] | None = None


class AuditProxy:
    def __init__(
        self,
        settings: Settings,
        store: Any,
        upstreams: list[Any] | None = None,
        features: FeatureSet | None = None,
        now: Any | None = None,
        clock_probe: Any | None = None,
        reporters: dict[str, Any] | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.upstreams = {item.name: item for item in (upstreams or [])}
        self.features = features or FeatureSet.community()
        self.reporters = (
            dict(reporters)
            if reporters is not None
            else {"json": JsonReporter(), "text": TextReporter()}
        )
        self.session = Session()
        self._now = now or _default_now
        self._clock_probe = clock_probe
        self._dead = False
        self._transport_session_id: str | None = None

    def startup(self) -> dict[str, Any]:
        from .clockutil import probe_clock

        probe = self._clock_probe or probe_clock
        status = probe()
        if self.settings.require_ntp and status.get("ntp_synchronized") is not True:
            raise ConfigurationError(
                "require_ntp is set and the clock is not reported synchronized (RFC 5905)"
            )
        self._refresh()
        return self._audit(
            method="audit/startup",
            record_class="config",
            status="ok",
            server="proxy",
            tool=None,
            arguments={
                "audit_enabled": True,
                "clock": status,
                "fail_closed": self.settings.fail_closed,
                "plugins": {
                    "auth": self.settings.auth,
                    "reporters": list(self.reporters),
                    "signer": getattr(getattr(self.store, "signer", None), "name", self.settings.signer),
                    "storage": self.settings.storage,
                },
                "policy": self.settings.policy.as_dict(),
                "retention": self.settings.retention.as_dict(),
            },
            result={"auditing": "enabled", "version": __version__},
            error=None,
            policy_action="allow",
            policy_rule="startup",
            reason="audit trail enabled at startup",
            approval=None,
            protocol_version=None,
            session_id=None,
            message=None,
        )

    def handle(
        self,
        message: dict[str, Any],
        transport_session_id: str | None = None,
    ) -> dict[str, Any] | None:
        self._transport_session_id = transport_session_id
        if not isinstance(message, dict) or not isinstance(message.get("method"), str):
            return _error(message if isinstance(message, dict) else {"id": None}, -32600, "invalid request")
        too_big = _encoded_size(message)
        if too_big > MAX_MESSAGE_BYTES:
            return self._oversized(message, too_big)
        method = message["method"]
        if self._dead and self.settings.fail_closed and not _is_verify_call(message):
            if _is_notification(message):
                return None
            return _fail_closed(message, "audit log unavailable")
        try:
            if method == "initialize":
                return self._initialize(message)
            if method == "notifications/initialized":
                return self._initialized(message)
            if method == "server/discover":
                return self._discover(message)
            if method == "ping":
                return self._ping(message)
            if method == "logging/setLevel":
                return self._set_level(message)
            if method == "tools/list":
                return self._tools_list(message)
            if method == "tools/call":
                return self._tools_call(message)
            if method == "resources/list":
                return self._resources_list(message)
            if method == "resources/read":
                return self._resources_read(message)
            if method == "prompts/list":
                return self._prompts_list(message)
            if method == "prompts/get":
                return self._prompts_get(message)
            self._audit_simple(
                message,
                method=method,
                record_class="technical",
                status="denied",
                server="proxy",
                tool=None,
                arguments=_params(message),
                result=None,
                error={"code": -32601, "message": "method not found"},
                policy_action="deny",
                policy_rule="method:unknown",
                reason=None,
            )
        except ChainIntegrityError as exc:
            if _is_verify_call(message):
                return self._verify_tool(message)
            self._dead = True
            if _is_notification(message):
                return None
            return _fail_closed(message, str(exc))
        except AuditStoreError as exc:
            self._dead = True
            if _is_notification(message):
                return None
            return _fail_closed(message, str(exc))
        else:
            if method in {
                "initialize",
                "notifications/initialized",
                "server/discover",
                "ping",
                "logging/setLevel",
                "tools/list",
                "tools/call",
                "resources/list",
                "resources/read",
                "prompts/list",
                "prompts/get",
            }:
                return None  # handlers return directly
            if _is_notification(message):
                return None
            return _error(message, -32601, f"method not found: {method}")
        if _is_notification(message):
            return None
        return _error(message, -32601, f"method not found: {method}")

    def reject_oversized_line(self, nbytes: int) -> dict[str, Any]:
        """Stdio saw a line past the size limit. The body is not parsed or stored."""
        stub = {"jsonrpc": "2.0", "id": None, "method": "rejected/oversized"}
        return self._oversized(stub, nbytes)

    def _oversized(self, message: dict[str, Any], nbytes: int) -> dict[str, Any]:
        """Refuse a message that would bloat the trail. Do not store its body."""
        try:
            self._audit_simple(
                message,
                method=str(message.get("method") or "rejected/oversized"),
                record_class="technical",
                status="denied",
                server="proxy",
                tool=None,
                arguments={"bytes": nbytes, "limit": MAX_MESSAGE_BYTES},
                result=None,
                error={"code": -32600, "message": "message exceeds size limit"},
                policy_action="deny",
                policy_rule="message:size",
                reason=None,
            )
        except AuditStoreError as exc:
            self._dead = True
            return _fail_closed(message, str(exc))
        return _error(
            message,
            -32600,
            "message exceeds size limit",
            {"bytes": nbytes, "limit": MAX_MESSAGE_BYTES},
        )

    def close(self) -> None:
        for upstream in self.upstreams.values():
            close = getattr(upstream, "close", None)
            if close:
                close()

    # --- protocol ---------------------------------------------------------

    def _initialize(self, message: dict[str, Any]) -> dict[str, Any]:
        self._refresh()
        params = _params(message)
        version = params.get("protocolVersion")
        if version not in LEGACY_VERSIONS:
            self._audit_simple(
                message,
                method="initialize",
                record_class="technical",
                status="failed",
                server="proxy",
                tool=None,
                arguments={"protocolVersion": version},
                result=None,
                error={"code": -32022, "message": "unsupported protocol version"},
                policy_action="deny",
                policy_rule="protocol",
                reason=None,
                protocol_version=version if isinstance(version, str) else None,
                session_id=None,
            )
            return _error(
                message,
                -32022,
                "unsupported protocol version",
                {"supported": list(LEGACY_VERSIONS) + list(MODERN_VERSIONS)},
            )
        info = params.get("clientInfo") if isinstance(params.get("clientInfo"), dict) else {}
        response = _result(
            message,
            {
                "protocolVersion": version,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {},
                    "prompts": {},
                },
                "serverInfo": {"name": "mcp-glp-audit-proxy", "version": __version__},
                "instructions": _instructions(),
            },
        )
        self._audit_simple(
            message,
            method="initialize",
            record_class="technical",
            status="ok",
            server="proxy",
            tool=None,
            arguments={"clientInfo": info, "protocolVersion": version},
            result={"protocolVersion": version, "server": "mcp-glp-audit-proxy"},
            error=None,
            policy_action="allow",
            policy_rule="initialize",
            reason=None,
            protocol_version=version,
            session_id=self._legacy_session_id(message),
        )
        self.session.era = "legacy"
        self.session.protocol_version = version
        self.session.client_info = info
        self.session.session_id = self._legacy_session_id(message)
        return response

    def _initialized(self, message: dict[str, Any]) -> None:
        self._refresh()
        self._audit_simple(
            message,
            method="notifications/initialized",
            record_class="technical",
            status="ok",
            server="proxy",
            tool=None,
            arguments={},
            result=None,
            error=None,
            policy_action="allow",
            policy_rule="initialized",
            reason=None,
        )
        return None

    def _discover(self, message: dict[str, Any]) -> dict[str, Any]:
        self._refresh()
        meta = _meta(message)
        requested = meta.get("io.modelcontextprotocol/protocolVersion") or MODERN_VERSION
        if requested not in MODERN_VERSIONS:
            self._audit_simple(
                message,
                method="server/discover",
                record_class="technical",
                status="failed",
                server="proxy",
                tool=None,
                arguments={"protocolVersion": requested},
                result=None,
                error={"code": -32022, "message": "unsupported protocol version"},
                policy_action="deny",
                policy_rule="protocol",
                reason=None,
                protocol_version=None,
                session_id=None,
            )
            return _error(
                message,
                -32022,
                "unsupported protocol version",
                {"supported": list(MODERN_VERSIONS)},
            )
        info = meta.get("io.modelcontextprotocol/clientInfo")
        response = _result(
            message,
            {
                "resultType": "complete",
                "supportedVersions": list(MODERN_VERSIONS),
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {
                        "name": "mcp-glp-audit-proxy",
                        "version": __version__,
                    }
                },
                "instructions": _instructions(),
                "ttlMs": 3_600_000,
                "cacheScope": "private",
            },
        )
        self._audit_simple(
            message,
            method="server/discover",
            record_class="technical",
            status="ok",
            server="proxy",
            tool=None,
            arguments={"clientInfo": info if isinstance(info, dict) else None},
            result={"supportedVersions": list(MODERN_VERSIONS)},
            error=None,
            policy_action="allow",
            policy_rule="discover",
            reason=None,
            protocol_version=MODERN_VERSION,
            session_id=None,
        )
        self.session.era = "modern"
        self.session.protocol_version = MODERN_VERSION
        self.session.session_id = None
        if isinstance(info, dict):
            self.session.client_info = info
        return response

    def _ping(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if self._host_version(message) == MODERN_VERSION or self.session.era == "modern":
            return self._unknown(message, "ping")
        self._refresh()
        self._audit_simple(
            message,
            method="ping",
            record_class="technical",
            status="ok",
            server="proxy",
            tool=None,
            arguments={},
            result={},
            error=None,
            policy_action="allow",
            policy_rule="ping",
            reason=None,
        )
        return _result(message, {})

    def _set_level(self, message: dict[str, Any]) -> dict[str, Any] | None:
        # logging/setLevel was removed in 2026-07-28. On legacy it is accepted
        # and audited, and it does not change the audit trail.
        if self._host_version(message) == MODERN_VERSION or self.session.era == "modern":
            return self._unknown(message, "logging/setLevel")
        self._refresh()
        self._audit_simple(
            message,
            method="logging/setLevel",
            record_class="technical",
            status="ok",
            server="proxy",
            tool=None,
            arguments=_params(message),
            result={},
            error=None,
            policy_action="allow",
            policy_rule="logging/setLevel",
            reason="technical log level only; the audit trail is unchanged",
        )
        return _result(message, {})

    def _unknown(self, message: dict[str, Any], method: str) -> dict[str, Any] | None:
        self._audit_simple(
            message,
            method=method,
            record_class="technical",
            status="denied",
            server="proxy",
            tool=None,
            arguments=_params(message),
            result=None,
            error={"code": -32601, "message": "method not found"},
            policy_action="deny",
            policy_rule="method:removed",
            reason=None,
        )
        if _is_notification(message):
            return None
        return _error(message, -32601, f"method not found: {method}")

    # --- listings and reads ----------------------------------------------

    def _tools_list(self, message: dict[str, Any]) -> dict[str, Any]:
        self._refresh()
        tools: list[dict[str, Any]] = []
        if self.settings.principal.role == "operator":
            try:
                for upstream in self.upstreams.values():
                    upstream.ensure()
                    for tool in upstream.list_tools():
                        exposed = f"{upstream.name}__{tool.get('name')}"
                        decision = self.settings.policy.decide(exposed, "operator")
                        if decision.action == "deny":
                            continue
                        tools.append(_expose_tool(tool, exposed))
            except Exception as exc:
                self._audit_simple(
                    message,
                    method="tools/list",
                    record_class="access",
                    status="failed",
                    server="proxy",
                    tool=None,
                    arguments={},
                    result=None,
                    error={"message": str(exc)},
                    policy_action="allow",
                    policy_rule="tools/list",
                    reason=None,
                )
                return _error(message, -32000, f"upstream failed: {exc}")
        tools.extend(self._local_tool_defs())
        payload = {"tools": tools}
        self._audit_simple(
            message,
            method="tools/list",
            record_class="access",
            status="ok",
            server="proxy",
            tool=None,
            arguments={},
            result={"tools": [item["name"] for item in tools]},
            error=None,
            policy_action="allow",
            policy_rule="tools/list",
            reason=None,
            upstream_protocol_version=self._any_upstream_version(),
            upstream_session_id=self._any_upstream_session(),
        )
        return _result(message, payload)

    def _resources_list(self, message: dict[str, Any]) -> dict[str, Any]:
        return self._list_named(
            message,
            method="resources/list",
            key="resources",
            fetch=lambda upstream: upstream.list_resources(),
            expose=lambda upstream, item: {
                **item,
                "uri": f"{upstream.name}:{item.get('uri')}",
            },
        )

    def _prompts_list(self, message: dict[str, Any]) -> dict[str, Any]:
        return self._list_named(
            message,
            method="prompts/list",
            key="prompts",
            fetch=lambda upstream: upstream.list_prompts(),
            expose=lambda upstream, item: {**item, "name": f"{upstream.name}__{item.get('name')}"},
        )

    def _list_named(
        self,
        message: dict[str, Any],
        *,
        method: str,
        key: str,
        fetch: Any,
        expose: Any,
    ) -> dict[str, Any]:
        self._refresh()
        if self.settings.principal.role != "operator":
            self._audit_simple(
                message,
                method=method,
                record_class="access",
                status="denied",
                server="proxy",
                tool=None,
                arguments={},
                result=None,
                error={"message": "role cannot list upstream data"},
                policy_action="deny",
                policy_rule=f"role:{self.settings.principal.role}",
                reason=None,
            )
            return _error(message, -32001, "role cannot list upstream data")
        collected: list[dict[str, Any]] = []
        for upstream in self.upstreams.values():
            upstream.ensure()
            for item in fetch(upstream):
                collected.append(expose(upstream, item))
        self._audit_simple(
            message,
            method=method,
            record_class="access",
            status="ok",
            server="proxy",
            tool=None,
            arguments={},
            result={key: collected},
            error=None,
            policy_action="allow",
            policy_rule=method,
            reason=None,
        )
        return _result(message, {key: collected})

    def _resources_read(self, message: dict[str, Any]) -> dict[str, Any]:
        self._refresh()
        uri = str(_params(message).get("uri") or "")
        server_name, raw_uri = _split_prefixed(uri)
        if self.settings.principal.role != "operator":
            return self._deny(
                message,
                method="resources/read",
                record_class="access",
                server=server_name or "proxy",
                tool=None,
                arguments={"uri": uri},
                rule=f"role:{self.settings.principal.role}",
                text="role cannot read upstream resources",
            )
        upstream = self.upstreams.get(server_name)
        if upstream is None:
            return self._deny(
                message,
                method="resources/read",
                record_class="access",
                server=server_name or "proxy",
                tool=None,
                arguments={"uri": uri},
                rule="upstream:unknown",
                text=f"unknown upstream in uri {uri}",
            )
        upstream.ensure()
        response = upstream.read_resource(raw_uri, _meta(message))
        return self._finish_upstream(
            message,
            response,
            method="resources/read",
            record_class="access",
            server=upstream.name,
            tool=None,
            arguments={"uri": uri},
            upstream=upstream,
            reason=_reason(message),
        )

    def _prompts_get(self, message: dict[str, Any]) -> dict[str, Any]:
        self._refresh()
        params = _params(message)
        exposed = str(params.get("name") or "")
        server_name, prompt_name = _split_tool(exposed)
        arguments = dict(params.get("arguments") or {}) if isinstance(params.get("arguments"), dict) else {}
        if self.settings.principal.role != "operator":
            return self._deny(
                message,
                method="prompts/get",
                record_class="access",
                server=server_name or "proxy",
                tool=exposed,
                arguments=arguments,
                rule=f"role:{self.settings.principal.role}",
                text="role cannot get upstream prompts",
            )
        upstream = self.upstreams.get(server_name)
        if upstream is None:
            return self._deny(
                message,
                method="prompts/get",
                record_class="access",
                server="proxy",
                tool=exposed,
                arguments=arguments,
                rule="upstream:unknown",
                text=f"unknown prompt {exposed}",
            )
        upstream.ensure()
        response = upstream.get_prompt(prompt_name, arguments, _meta(message))
        return self._finish_upstream(
            message,
            response,
            method="prompts/get",
            record_class="access",
            server=upstream.name,
            tool=exposed,
            arguments=arguments,
            upstream=upstream,
            reason=_reason(message),
        )

    # --- tools/call -------------------------------------------------------

    def _tools_call(self, message: dict[str, Any]) -> dict[str, Any]:
        if _is_verify_call(message):
            return self._verify_tool(message)
        self._refresh()
        params = _params(message)
        name = str(params.get("name") or "")
        arguments = dict(params.get("arguments") or {}) if isinstance(params.get("arguments"), dict) else {}
        arguments.pop("_glp_reason", None)
        if name in LOCAL_TOOLS:
            return self._local_call(message, name, arguments)
        return self._upstream_call(message, name, arguments)

    def _upstream_call(
        self,
        message: dict[str, Any],
        name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        server_name, tool_name = _split_tool(name)
        reason = _reason(message)
        decision = self.settings.policy.decide(name, self.settings.principal.role)
        if decision.action == "deny":
            return self._deny(
                message,
                method="tools/call",
                record_class="gxp_data" if self.settings.policy.is_write(name) else "access",
                server=server_name or "proxy",
                tool=name,
                arguments=arguments,
                rule=decision.rule,
                text=f"denied by policy ({decision.rule})",
                reason=reason,
            )
        is_write = self.settings.policy.is_write(name)
        if is_write and self.settings.policy.require_reason_for_writes and not reason:
            return self._deny(
                message,
                method="tools/call",
                record_class="gxp_data",
                server=server_name or "proxy",
                tool=name,
                arguments=arguments,
                rule="write:reason-missing",
                text="a reason is required for write tools",
                reason=None,
            )
        if is_write and self.settings.policy.require_approval_for_writes:
            gate = self._approval_gate(message, name, arguments, reason)
            if gate is not None:
                return gate
        upstream = self.upstreams.get(server_name)
        if upstream is None:
            return self._deny(
                message,
                method="tools/call",
                record_class="gxp_data" if is_write else "access",
                server="proxy",
                tool=name,
                arguments=arguments,
                rule="upstream:unknown",
                text=f"unknown tool {name}",
                reason=reason,
            )
        try:
            upstream.ensure()
            response = upstream.call_tool(tool_name, arguments, _meta(message))
        except Exception as exc:  # upstream transport or negotiation
            self._audit_simple(
                message,
                method="tools/call",
                record_class="gxp_data" if is_write else "access",
                status="failed",
                server=upstream.name,
                tool=name,
                arguments=arguments,
                result=None,
                error={"message": str(exc)},
                policy_action="allow",
                policy_rule=decision.rule,
                reason=reason,
                approval=None,
                upstream_protocol_version=getattr(upstream, "protocol_version", None),
                upstream_session_id=getattr(upstream, "session_id", None),
            )
            return _error(message, -32000, f"upstream failed: {exc}")
        approval = self._consumed_approval(message, name, arguments)
        return self._finish_upstream(
            message,
            response,
            method="tools/call",
            record_class="gxp_data" if is_write else "access",
            server=upstream.name,
            tool=name,
            arguments=arguments,
            upstream=upstream,
            reason=reason,
            approval=approval,
            policy_rule=decision.rule,
        )

    def _approval_gate(
        self,
        message: dict[str, Any],
        name: str,
        arguments: dict[str, Any],
        reason: str | None,
    ) -> dict[str, Any] | None:
        digest = args_hash(name, arguments)
        approval_id = _meta(message).get("io.github.antonio-castellon/approvalId")
        if not approval_id:
            return self._pending(message, name, arguments, digest, reason)
        from .approvals import load_approvals as _load

        record = _load(self.store.read_entries()).get(str(approval_id))
        problem = _approval_problem(
            record,
            tool=name,
            digest=digest,
            requester=self.settings.principal.id,
            now=self._now(),
        )
        if problem:
            return self._deny(
                message,
                method="tools/call",
                record_class="gxp_data",
                server=_split_tool(name)[0] or "proxy",
                tool=name,
                arguments=arguments,
                rule=f"approval:{problem}",
                text=f"approval refused ({problem})",
                reason=reason,
                approval={
                    "approval_id": str(approval_id),
                    "approver_id": None,
                    "approver_name": None,
                    "args_hash": digest,
                    "decided_at": None,
                    "expires_at": None,
                    "label": "approval",
                    "meaning": None,
                    "status": "rejected",
                    "tool": name,
                },
            )
        return None

    def _pending(
        self,
        message: dict[str, Any],
        name: str,
        arguments: dict[str, Any],
        digest: str,
        reason: str | None,
    ) -> dict[str, Any]:
        approval_id = str(uuid.uuid4())
        expires = self._now() + timedelta(seconds=self.settings.approval_ttl_seconds)
        approval = {
            "approval_id": approval_id,
            "approver_id": None,
            "approver_name": None,
            "args_hash": digest,
            "decided_at": None,
            "expires_at": format_timestamp(expires),
            "label": "approval",
            "meaning": None,
            "status": "pending",
            "tool": name,
        }
        text = (
            "Approval required before this write. "
            f"approval_id={approval_id} args_hash={digest}. "
            "An approver must call glp_approve. This call was not forwarded. "
            "The record is an approval, not an electronic signature."
        )
        client_result = {"content": [{"type": "text", "text": text}], "isError": True}
        self._audit_simple(
            message,
            method="tools/call",
            record_class="gxp_data",
            status="pending_approval",
            server=_split_tool(name)[0] or "proxy",
            tool=name,
            arguments=arguments,
            result={"approval_id": approval_id},
            error=None,
            policy_action="require_approval",
            policy_rule="write:approval",
            reason=reason,
            approval=approval,
        )
        return _result(message, client_result)

    def _consumed_approval(
        self,
        message: dict[str, Any],
        name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any] | None:
        approval_id = _meta(message).get("io.github.antonio-castellon/approvalId")
        if not approval_id or not self.settings.policy.is_write(name):
            return None
        if not self.settings.policy.require_approval_for_writes:
            return None
        records = load_approvals(self.store.read_entries())
        record = records.get(str(approval_id))
        if record is None:
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
            "tool": name,
        }

    def _local_call(
        self,
        message: dict[str, Any],
        name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        allowed = LOCAL_TOOLS[name]["roles"]
        role = self.settings.principal.role
        if role not in allowed:
            return self._deny(
                message,
                method="tools/call",
                record_class="access" if name != "glp_update_policy" else "config",
                server="proxy",
                tool=name,
                arguments=arguments,
                rule=f"role:{role}",
                text=f"role {role} cannot call {name}",
            )
        if name == "glp_search_audit":
            return self._search(message, arguments)
        if name == "glp_export_audit":
            return self._export(message, arguments)
        if name == "glp_approve":
            return self._approve(message, arguments)
        if name == "glp_update_policy":
            return self._update_policy(message, arguments)
        return self._deny(
            message,
            method="tools/call",
            record_class="access",
            server="proxy",
            tool=name,
            arguments=arguments,
            rule="tool:unknown",
            text=f"unknown local tool {name}",
        )

    def _verify_tool(self, message: dict[str, Any]) -> dict[str, Any]:
        role = self.settings.principal.role
        if role not in LOCAL_TOOLS["glp_verify_chain"]["roles"]:
            try:
                self._refresh()
            except (ChainIntegrityError, AuditStoreError):
                pass
            return self._deny(
                message,
                method="tools/call",
                record_class="access",
                server="proxy",
                tool="glp_verify_chain",
                arguments={},
                rule=f"role:{role}",
                text=f"role {role} cannot verify the audit trail",
            )
        report = verify_anchored(self.settings.audit_path)
        client_result = {
            "content": [
                {
                    "type": "text",
                    "text": _verify_text(report),
                }
            ],
            "isError": not report.ok,
            "structuredContent": {
                "ok": report.ok,
                "errors": report.errors,
                "anchor_lag": report.anchor_lag,
                "head_hash": report.head_hash,
                "entries": report.count,
            },
        }
        try:
            self._audit_simple(
                message,
                method="tools/call",
                record_class="access",
                status="ok" if report.ok else "failed",
                server="proxy",
                tool="glp_verify_chain",
                arguments={},
                result={"ok": report.ok, "errors": report.errors, "head_hash": report.head_hash},
                error=None if report.ok else {"message": "chain invalid"},
                policy_action="allow",
                policy_rule="verify",
                reason="audit trail review",
            )
        except AuditStoreError:
            client_result["structuredContent"]["audit_of_verify"] = "not_written"
        return _result(message, client_result)

    def _search(self, message: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
        entries = filter_entries(self.store.read_entries(), **_filters(arguments))
        summary = {"count": len(entries), "filters": _filters(arguments)}
        self._audit_simple(
            message,
            method="tools/call",
            record_class="access",
            status="ok",
            server="proxy",
            tool="glp_search_audit",
            arguments=_filters(arguments),
            result=summary,
            error=None,
            policy_action="allow",
            policy_rule="search",
            reason="audit trail review",
        )
        return _result(
            message,
            {
                "content": [{"type": "text", "text": f"{len(entries)} entries"}],
                "structuredContent": {"entries": entries, "count": len(entries)},
                "isError": False,
            },
        )

    def _export(self, message: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
        format_name = arguments.get("format") or "json"
        if not isinstance(format_name, str) or format_name not in self.reporters:
            return self._deny(
                message,
                method="tools/call",
                record_class="access",
                server="proxy",
                tool="glp_export_audit",
                arguments=arguments,
                rule="reporter:unknown",
                text=f"reporter {format_name!r} is not configured",
            )
        feature = feature_for(REPORTERS_GROUP, format_name)
        if feature is not None and not self.features.allows(feature):
            return self._deny(
                message,
                method="tools/call",
                record_class="access",
                server="proxy",
                tool="glp_export_audit",
                arguments=arguments,
                rule=f"feature:{feature}",
                text=f"{format_name} export is not enabled",
            )
        reporter = self.reporters[format_name]
        report = verify_anchored(self.settings.audit_path)
        if not report.ok:
            # Do not append onto a broken chain and do not write a partial copy.
            return _fail_closed(message, "refusing to export a chain that does not verify")
        full = report.entries
        filters = _filters(arguments)
        selected = filter_entries(full, **filters)
        signer_name = getattr(getattr(self.store, "signer", None), "name", None) or "unsigned"
        document = export_document(
            selected,
            full_chain=full,
            chain_valid=True,
            filters=filters,
            exported_at=format_timestamp(self._now()),
            signer=str(signer_name),
        )
        rendered = reporter.render(document)
        if not isinstance(rendered, (bytes, bytearray)):
            raise ConfigurationError(f"reporter {format_name!r} did not return bytes")
        target = arguments.get("path")
        written = None
        if target:
            written = self._export_path(str(target))
            written.parent.mkdir(parents=True, exist_ok=True)
            # The Community json reporter stays pretty-printed so a reviewer can search it.
            # Other reporters write the bytes from render().
            if format_name == "json":
                written.write_text(dumps_document(document), encoding="utf-8")
            else:
                written.write_bytes(bytes(rendered))
        try:
            self._audit_simple(
                message,
                method="tools/call",
                record_class="access",
                status="ok",
                server="proxy",
                tool="glp_export_audit",
                arguments={
                    "filters": filters,
                    "format": format_name,
                    "path": str(written) if written else None,
                },
                result={
                    "complete": document["complete"],
                    "count": len(selected),
                    "head_hash": document["manifest"]["full_head_hash"],
                },
                error=None,
                policy_action="allow",
                policy_rule="export",
                reason="audit export / archive retrieval",
            )
        except AuditStoreError:
            if written and written.exists():
                written.unlink()
            raise
        text = format_entry(selected[-1]) if selected else "export empty"
        return _result(
            message,
            {
                "content": [{"type": "text", "text": text}],
                "structuredContent": document,
                "isError": False,
            },
        )

    def _approve(self, message: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
        approval_id = str(arguments.get("approval_id") or "")
        meaning = str(arguments.get("meaning") or "")
        if meaning not in {"approved", "reviewed", "rejected"}:
            return self._deny(
                message,
                method="tools/call",
                record_class="gxp_data",
                server="proxy",
                tool="glp_approve",
                arguments=arguments,
                rule="approval:meaning",
                text="meaning must be approved, reviewed or rejected",
            )
        records = load_approvals(self.store.read_entries())
        record = records.get(approval_id)
        if record is None or record.status != "pending":
            return self._deny(
                message,
                method="tools/call",
                record_class="gxp_data",
                server="proxy",
                tool="glp_approve",
                arguments=arguments,
                rule="approval:unknown",
                text="no pending approval with that id",
            )
        if record.requested_by == self.settings.principal.id:
            return self._deny(
                message,
                method="tools/call",
                record_class="gxp_data",
                server="proxy",
                tool="glp_approve",
                arguments=arguments,
                rule="approval:self",
                text="the requester cannot approve their own write",
            )
        status = "approved" if meaning in {"approved", "reviewed"} else "rejected"
        # 'reviewed' is recorded but does not authorise the write. The gate
        # accepts only meaning 'approved'.
        approval = {
            "approval_id": approval_id,
            "approver_id": self.settings.principal.id,
            "approver_name": self.settings.principal.name,
            "args_hash": record.args_hash,
            "decided_at": format_timestamp(self._now()),
            "expires_at": record.expires_at,
            "label": "approval",
            "meaning": meaning,
            "status": "approved" if meaning != "rejected" else "rejected",
            "tool": record.tool,
        }
        self._audit_simple(
            message,
            method="glp_approve",
            record_class="gxp_data",
            status=status if meaning != "reviewed" else "approved",
            server="proxy",
            tool="glp_approve",
            arguments={"approval_id": approval_id, "meaning": meaning},
            result={"tool": record.tool, "label": "approval"},
            error=None,
            policy_action="allow",
            policy_rule="approval",
            reason=meaning,
            approval=approval,
        )
        note = (
            "Recorded an approval. This is not an electronic signature."
            if meaning == "approved"
            else "Recorded. This meaning does not authorise the write."
            if meaning == "reviewed"
            else "Recorded a rejection."
        )
        return _result(
            message,
            {"content": [{"type": "text", "text": note}], "isError": meaning == "rejected"},
        )

    def _update_policy(self, message: dict[str, Any], arguments: dict[str, Any]) -> dict[str, Any]:
        from .policy import Policy

        reason = arguments.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            return self._deny(
                message,
                method="tools/call",
                record_class="config",
                server="proxy",
                tool="glp_update_policy",
                arguments=arguments,
                rule="config:reason-missing",
                text="a reason is required to change audit policy",
            )
        if arguments.get("audit_enabled") is False:
            return self._deny(
                message,
                method="tools/call",
                record_class="config",
                server="proxy",
                tool="glp_update_policy",
                arguments=arguments,
                rule="config:audit-disable",
                text="auditing cannot be disabled",
                reason=reason,
            )
        proposed = {
            key: arguments[key]
            for key in (
                "allow",
                "deny",
                "write_tools",
                "require_approval_for_writes",
                "require_reason_for_writes",
            )
            if key in arguments
        }
        current = self.settings.policy.as_dict()
        merged = dict(current)
        merged.update(proposed)
        try:
            new_policy = Policy.from_mapping(merged)
        except ValueError as exc:
            return self._deny(
                message,
                method="tools/call",
                record_class="config",
                server="proxy",
                tool="glp_update_policy",
                arguments={"previous": current, "proposed": proposed},
                rule="config:invalid",
                text=str(exc),
                reason=reason,
            )
        self._audit_simple(
            message,
            method="glp_update_policy",
            record_class="config",
            status="ok",
            server="proxy",
            tool="glp_update_policy",
            arguments={"previous": current, "proposed": new_policy.as_dict()},
            result={"policy": new_policy.as_dict()},
            error=None,
            policy_action="allow",
            policy_rule="config",
            reason=reason.strip(),
        )
        self.settings.policy = new_policy
        return _result(
            message,
            {
                "content": [{"type": "text", "text": "policy updated"}],
                "structuredContent": {"policy": new_policy.as_dict()},
                "isError": False,
            },
        )

    # --- shared audit paths ----------------------------------------------

    def _finish_upstream(
        self,
        message: dict[str, Any],
        response: dict[str, Any],
        *,
        method: str,
        record_class: str,
        server: str,
        tool: str | None,
        arguments: dict[str, Any],
        upstream: Any,
        reason: str | None,
        approval: dict[str, Any] | None = None,
        policy_rule: str = "allow",
    ) -> dict[str, Any]:
        if "error" in response:
            error = response["error"] if isinstance(response["error"], dict) else {"message": str(response["error"])}
            # A failed call does not consume the approval; the approver's decision can be retried.
            self._audit_simple(
                message,
                method=method,
                record_class=record_class,
                status="failed",
                server=server,
                tool=tool,
                arguments=arguments,
                result=None,
                error=error,
                policy_action="allow",
                policy_rule=policy_rule,
                reason=reason,
                approval=None,
                upstream_protocol_version=getattr(upstream, "protocol_version", None),
                upstream_session_id=getattr(upstream, "session_id", None),
            )
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": error,
            }
        payload = response.get("result")
        status = "failed" if isinstance(payload, dict) and payload.get("isError") else "ok"
        if status != "ok":
            approval = None
        self._audit_simple(
            message,
            method=method,
            record_class=record_class,
            status=status,
            server=server,
            tool=tool,
            arguments=arguments,
            result=payload,
            error={"message": "tool error"} if status == "failed" else None,
            policy_action="allow",
            policy_rule=policy_rule,
            reason=reason,
            approval=approval,
            upstream_protocol_version=getattr(upstream, "protocol_version", None),
            upstream_session_id=getattr(upstream, "session_id", None),
        )
        return _result(message, payload)

    def _deny(
        self,
        message: dict[str, Any],
        *,
        method: str,
        record_class: str,
        server: str,
        tool: str | None,
        arguments: dict[str, Any],
        rule: str,
        text: str,
        reason: str | None = None,
        approval: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._audit_simple(
            message,
            method=method,
            record_class=record_class,
            status="denied",
            server=server,
            tool=tool,
            arguments=arguments,
            result=None,
            error={"message": text},
            policy_action="deny",
            policy_rule=rule,
            reason=reason,
            approval=approval,
        )
        if method == "tools/call":
            return _result(
                message,
                {"content": [{"type": "text", "text": text}], "isError": True},
            )
        return _error(message, -32001, text)

    def _audit_simple(self, message: dict[str, Any] | None, **kwargs: Any) -> dict[str, Any]:
        protocol_version = kwargs.pop("protocol_version", None)
        session_id = kwargs.pop("session_id", None)
        if message is not None and "protocol_version" not in kwargs:
            pass
        if protocol_version is None and message is not None:
            protocol_version = self._host_version(message)
        if session_id is None and message is not None and protocol_version != MODERN_VERSION:
            session_id = self._legacy_session_id(message)
        if protocol_version == MODERN_VERSION:
            session_id = None
        return self._audit(
            message=message,
            protocol_version=protocol_version,
            session_id=session_id,
            **kwargs,
        )

    def _audit(
        self,
        *,
        message: dict[str, Any] | None,
        method: str,
        record_class: str,
        status: str,
        server: str,
        tool: str | None,
        arguments: dict[str, Any] | None,
        result: Any,
        error: dict[str, Any] | None,
        policy_action: str,
        policy_rule: str,
        reason: str | None,
        approval: dict[str, Any] | None = None,
        protocol_version: str | None,
        session_id: str | None,
        upstream_protocol_version: str | None = None,
        upstream_session_id: str | None = None,
    ) -> dict[str, Any]:
        meta = _meta(message) if message else {}
        _cleaned, stripped = split_meta(meta)
        event = build_event(
            method=method,
            record_class=record_class,
            status=status,
            server=server,
            principal=self.settings.principal.as_dict(),
            client=self._client_block(message),
            protocol_version=protocol_version,
            session_id=session_id,
            tool=tool,
            arguments=arguments,
            result=result,
            error=error,
            policy_action=policy_action,
            policy_rule=policy_rule,
            reason=reason,
            approval=approval,
            upstream_protocol_version=upstream_protocol_version,
            upstream_session_id=None if upstream_protocol_version == MODERN_VERSION else upstream_session_id,
            stripped_credential_fields=stripped,
            traceparent=meta.get("traceparent") if isinstance(meta.get("traceparent"), str) else None,
            timestamp=format_timestamp(self._now()),
        )
        # Technical logs stay on stderr via the logging module. The GxP record
        # is only the store append below.
        import logging

        logging.getLogger("mcp_glp_audit_proxy.technical").info(
            "audit append method=%s status=%s class=%s",
            method,
            status,
            record_class,
        )
        return self.store.append_event(event)

    def _refresh(self) -> list[dict[str, Any]]:
        if not self.store.health():
            raise AuditStoreError("audit store unavailable")
        entries = self.store.read_entries()
        self._restore_policy(entries)
        return entries

    def _restore_policy(self, entries: list[dict[str, Any]]) -> None:
        from .policy import Policy

        for entry in entries:
            if entry.get("method") == "glp_update_policy" and entry.get("status") == "ok":
                policy = (entry.get("result") or {}).get("policy")
                if isinstance(policy, dict):
                    self.settings.policy = Policy.from_mapping(policy)

    def _client_block(self, message: dict[str, Any] | None) -> dict[str, Any]:
        meta = _meta(message) if message else {}
        info = meta.get("io.modelcontextprotocol/clientInfo")
        if not isinstance(info, dict):
            info = self.session.client_info or {}
        model_id = None
        for key in MODEL_KEYS:
            if meta.get(key):
                model_id = str(meta[key])
                break
        name = info.get("name") if isinstance(info, dict) else None
        return {
            "id": str(name or "unknown"),
            "model_id": model_id,
            "name": name,
            "version": info.get("version") if isinstance(info, dict) else None,
        }

    def _host_version(self, message: dict[str, Any]) -> str | None:
        meta = _meta(message)
        version = meta.get("io.modelcontextprotocol/protocolVersion")
        if isinstance(version, str):
            return version
        if message.get("method") == "initialize":
            raw = _params(message).get("protocolVersion")
            return raw if isinstance(raw, str) else None
        return self.session.protocol_version

    def _legacy_session_id(self, message: dict[str, Any]) -> str | None:
        if self._host_version(message) == MODERN_VERSION or self.session.era == "modern":
            return None
        meta = _meta(message)
        candidate = meta.get("mcp.session.id") or self._transport_session_id or self.session.session_id
        if isinstance(candidate, str) and candidate:
            return candidate
        return None

    def _local_tool_defs(self) -> list[dict[str, Any]]:
        role = self.settings.principal.role
        listed = []
        for name, spec in LOCAL_TOOLS.items():
            if role in spec["roles"]:
                listed.append(
                    {
                        "name": name,
                        "description": spec["description"],
                        "inputSchema": spec["inputSchema"],
                    }
                )
        return listed

    def _any_upstream_version(self) -> str | None:
        for upstream in self.upstreams.values():
            if getattr(upstream, "protocol_version", None):
                return upstream.protocol_version
        return None

    def _any_upstream_session(self) -> str | None:
        for upstream in self.upstreams.values():
            if getattr(upstream, "protocol_version", None) == MODERN_VERSION:
                return None
            if getattr(upstream, "session_id", None):
                return upstream.session_id
        return None

    def _export_path(self, raw: str) -> Path:
        root = (self.settings.export_dir or self.settings.audit_path.parent / "exports").resolve()
        path = Path(raw)
        if not path.is_absolute():
            path = root / path
        path = path.resolve()
        if path != root and root not in path.parents:
            raise AuditStoreError("export path escapes the export directory")
        return path


def _default_now() -> Any:
    from .records import utc_now

    return utc_now()


def _instructions() -> str:
    return (
        "MCP audit proxy. Tool calls are forwarded to configured upstream servers "
        "and written to a local append-only hash chain before the response is returned. "
        "Write tools may require a reason and a human approval. "
        "An approval is not an electronic signature."
    )


def _params(message: dict[str, Any]) -> dict[str, Any]:
    params = message.get("params")
    return params if isinstance(params, dict) else {}


def _meta(message: dict[str, Any] | None) -> dict[str, Any]:
    if not message:
        return {}
    meta = _params(message).get("_meta")
    return meta if isinstance(meta, dict) else {}


def _reason(message: dict[str, Any]) -> str | None:
    meta = _meta(message)
    value = meta.get("io.github.antonio-castellon/reason")
    if isinstance(value, str) and value.strip():
        return value.strip()
    arguments = _params(message).get("arguments")
    if isinstance(arguments, dict):
        fallback = arguments.get("_glp_reason")
        if isinstance(fallback, str) and fallback.strip():
            return fallback.strip()
    return None


def _is_notification(message: dict[str, Any]) -> bool:
    return "id" not in message


def _is_verify_call(message: dict[str, Any]) -> bool:
    if message.get("method") != "tools/call":
        return False
    return _params(message).get("name") == "glp_verify_chain"


def _split_tool(name: str) -> tuple[str, str]:
    server, separator, tool = name.partition("__")
    if not separator:
        return "", name
    return server, tool


def _split_prefixed(value: str) -> tuple[str, str]:
    server, separator, rest = value.partition(":")
    if not separator:
        return "", value
    return server, rest


def _expose_tool(tool: dict[str, Any], exposed: str) -> dict[str, Any]:
    schema = tool.get("inputSchema") or {"type": "object", "additionalProperties": True}
    return {
        "name": exposed,
        "description": tool.get("description") or "",
        "inputSchema": schema,
    }


def _filters(arguments: dict[str, Any]) -> dict[str, Any]:
    keys = ("record_class", "tool", "principal_id", "status", "method", "server", "since", "until")
    return {key: arguments.get(key) for key in keys}


def _approval_problem(record: Any, *, tool: str, digest: str, requester: str, now: Any) -> str | None:
    if record is None:
        return "unknown"
    if record.status == "consumed":
        return "consumed"
    if record.status == "rejected":
        return "rejected"
    if record.status != "approved":
        return record.status or "pending"
    if record.meaning != "approved":
        return "meaning"
    if record.approver_role != "approver":
        return "role"
    if record.approver_id == requester or record.requested_by == record.approver_id:
        return "self"
    if record.tool != tool or record.args_hash != digest:
        return "mismatch"
    if record.expires_at:
        try:
            if now > parse_timestamp(record.expires_at):
                return "expired"
        except ValueError:
            return "expired"
    return None


def _verify_text(report: Any) -> str:
    if report.ok:
        lag = f" anchor_lag={report.anchor_lag}" if report.anchor_lag else ""
        return f"chain ok entries={report.count} head={report.head_hash}{lag}"
    return "chain invalid: " + "; ".join(report.errors)


def _result(message: dict[str, Any], payload: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message.get("id"), "result": payload}


def _error(
    message: dict[str, Any],
    code: int,
    text: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": text}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": message.get("id"), "error": error}


def _encoded_size(message: dict[str, Any]) -> int:
    try:
        raw = json.dumps(message, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return MAX_MESSAGE_BYTES + 1
    return len(raw.encode("utf-8"))


def _fail_closed(message: dict[str, Any], detail: str) -> dict[str, Any]:
    return _error(
        message,
        -32000,
        "audit log unavailable; request was not completed",
        {"detail": detail, "reason": "fail_closed"},
    )


# Silence unused import if a future edit drops a direct reference.
_ = SECRET_META
