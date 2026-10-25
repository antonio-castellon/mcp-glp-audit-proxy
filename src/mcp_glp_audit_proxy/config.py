"""JSON config plus environment overrides. Stdio identity comes from the environment."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .policy import Policy

ROLES = frozenset({"operator", "approver", "qa", "admin"})
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,40}$")
_PLUGIN = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
_CLIENT_ID = re.compile(r"^[!-~]{1,200}$")
_DEFAULT_REPORTERS = ("json", "text")
_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


@dataclass
class Principal:
    id: str
    name: str
    role: str

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "role": self.role}


@dataclass
class Retention:
    profile: str = "swiss_glp"
    min_months: int = 6
    years_after_study: int = 10
    legal_hold: bool = False
    study_completion: str | None = None

    def validate(self) -> None:
        if self.min_months < 6:
            raise ConfigurationError(
                "retention floor is 6 months (default floor; EU AI Act Art. 19 and Art. 26(6) where applicable)"
            )
        if self.profile == "swiss_glp" and self.years_after_study < 10:
            raise ConfigurationError(
                "Swiss GLP profile requires at least 10 years after study completion "
                "(GLPV Annex 2 sec. 10 para. 1)"
            )
        if self.profile not in {"swiss_glp", "minimum"}:
            raise ConfigurationError(f"unknown retention profile {self.profile!r}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "legal_hold": self.legal_hold,
            "min_months": self.min_months,
            "profile": self.profile,
            "study_completion": self.study_completion,
            "years_after_study": self.years_after_study,
        }


@dataclass
class EndpointConfig:
    tool: str
    method: str
    path: str


@dataclass
class RouteConfig:
    flow: str
    methods: tuple[str, ...]
    path: str
    upstream: str
    upstream_path: str | None = None
    tool: str | None = None


@dataclass
class MappedPrincipal:
    id: str
    name: str
    role: str
    fingerprint: str | None = None

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "role": self.role}


@dataclass
class ListenIdentity:
    mode: str
    client_ca_file: str | None = None
    principals: tuple[MappedPrincipal, ...] = ()
    bearer_token_file: str | None = None
    bearer_principal: MappedPrincipal | None = None
    end_user_header: str | None = None
    end_users: tuple[MappedPrincipal, ...] = ()


@dataclass
class ListenConfig:
    bind: str
    port: int
    cert_file: str
    key_file: str
    identity: ListenIdentity


@dataclass
class UpstreamConfig:
    name: str
    transport: str
    protocol: str = "auto"
    command: str | None = None
    args: list[str] | None = None
    env: dict[str, str] | None = None
    url: str | None = None
    headers: dict[str, str] | None = None
    cwd: str | None = None
    timeout: float | None = None
    kind: str = "mcp"
    ca_file: str | None = None
    endpoints: list[EndpointConfig] = field(default_factory=list)


@dataclass
class Settings:
    principal: Principal
    retention: Retention
    policy: Policy
    audit_path: Path
    fail_closed: bool = True
    checkpoint_every: int = 100
    approval_ttl_seconds: int = 3600
    licence_path: Path | None = None
    client_id: str | None = None
    require_ntp: bool = False
    export_dir: Path | None = None
    upstreams: list[UpstreamConfig] | None = None
    storage: str = "jsonl"
    signer: str = "unsigned"
    reporters: tuple[str, ...] = _DEFAULT_REPORTERS
    auth: str = "env"
    plugin_options: dict[str, Any] = field(default_factory=dict)
    body_mode: str = "hash_only"
    redact_paths: tuple[str, ...] = ()
    max_body_bytes: int = 1_048_576
    alert_command: tuple[str, ...] = ()
    integrity_check_seconds: int = 0
    listen: ListenConfig | None = None
    routes: list[RouteConfig] = field(default_factory=list)

    def validate(self) -> None:
        if self.principal.role not in ROLES:
            raise ConfigurationError(
                f"role must be one of {sorted(ROLES)}; got {self.principal.role!r}"
            )
        if not self.principal.id or not self.principal.name:
            raise ConfigurationError("principal id and name are required")
        self.retention.validate()
        if self.fail_closed is not True and self.fail_closed is not False:
            raise ConfigurationError("fail_closed must be a boolean")
        if self.body_mode not in {"hash_only", "redacted", "full"}:
            raise ConfigurationError("audit.body_mode must be hash_only, redacted, or full")
        for path in self.redact_paths:
            if not path.startswith("$"):
                raise ConfigurationError(f"redact path must start with $: {path}")
        if not isinstance(self.max_body_bytes, int) or not 1 <= self.max_body_bytes <= 8_388_608:
            raise ConfigurationError("audit.max_body_bytes must be from 1 to 8388608")
        if isinstance(self.integrity_check_seconds, bool) or not isinstance(self.integrity_check_seconds, int):
            raise ConfigurationError("audit.integrity_check_seconds must be an integer")
        if self.integrity_check_seconds < 0:
            raise ConfigurationError("audit.integrity_check_seconds must be >= 0")
        if not isinstance(self.alert_command, tuple) or not all(isinstance(part, str) and part for part in self.alert_command):
            raise ConfigurationError("audit.alert_command must be a list of strings")
        names = set()
        for upstream in self.upstreams or []:
            if not _NAME.match(upstream.name) or "__" in upstream.name:
                raise ConfigurationError(
                    f"upstream name {upstream.name!r} must be a short token without '__'"
                )
            names.add(upstream.name)
            if upstream.transport not in {"stdio", "https"}:
                raise ConfigurationError(
                    f"upstream {upstream.name}: transport must be stdio or https"
                )
            if upstream.kind not in {"mcp", "api", "llm"}:
                raise ConfigurationError(
                    f"upstream {upstream.name}: kind must be mcp, api, or llm"
                )
            if upstream.kind in {"api", "llm"} and upstream.transport != "https":
                raise ConfigurationError(
                    f"upstream {upstream.name}: kind {upstream.kind} requires transport https"
                )
            if upstream.protocol not in {"auto", "legacy", "modern"}:
                raise ConfigurationError(
                    f"upstream {upstream.name}: protocol must be auto, legacy or modern"
                )
            for endpoint in upstream.endpoints:
                if not _NAME.match(endpoint.tool):
                    raise ConfigurationError(
                        f"upstream {upstream.name}: endpoint tool {endpoint.tool!r} is not a short token"
                    )
                if endpoint.method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
                    raise ConfigurationError(
                        f"upstream {upstream.name}: endpoint method must be an HTTP method"
                    )
                _check_route_path(endpoint.path, f"upstream {upstream.name} endpoint")
        _validate_listen(self.listen)
        seen: set[tuple[str, str]] = set()
        for route in self.routes:
            if route.flow not in {"api2api", "api2mcp", "api2llm"}:
                raise ConfigurationError(
                    f"route flow must be api2api, api2mcp, or api2llm; got {route.flow!r}"
                )
            if route.upstream not in names:
                raise ConfigurationError(f"route upstream {route.upstream!r} is not configured")
            upstream = next(item for item in self.upstreams or [] if item.name == route.upstream)
            expected = {"api2api": "api", "api2llm": "llm", "api2mcp": "mcp"}[route.flow]
            if upstream.kind != expected:
                raise ConfigurationError(
                    f"route flow {route.flow} requires upstream kind {expected}"
                )
            if route.flow == "api2mcp" and not route.tool:
                raise ConfigurationError("api2mcp route requires tool")
            _check_route_path(route.path, "route path")
            if route.upstream_path:
                _check_route_path(route.upstream_path, "route upstream_path")
            for method in route.methods:
                if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
                    raise ConfigurationError(f"route method {method!r} is not an HTTP method")
                key = (method, route.path)
                if key in seen:
                    raise ConfigurationError(f"duplicate route {method} {route.path}")
                seen.add(key)
        _check_plugin_name(self.storage, "plugins.storage")
        _check_plugin_name(self.signer, "plugins.signer")
        if not isinstance(self.reporters, tuple) or not self.reporters:
            raise ConfigurationError("plugins.reporters must be a non-empty list of plugin names")
        if len(set(self.reporters)) != len(self.reporters):
            raise ConfigurationError("plugins.reporters must not repeat a name")
        for name in self.reporters:
            _check_plugin_name(name, "plugins.reporters")
        _check_plugin_name(self.auth, "plugins.auth")


def load_settings(path: str | Path) -> Settings:
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigurationError(f"config file not found: {config_path}")
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"config is not JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError("config must be a JSON object")

    principal_raw = dict(raw.get("principal") or {})
    if os.environ.get("GLP_PRINCIPAL_ID"):
        principal_raw["id"] = os.environ["GLP_PRINCIPAL_ID"]
    if os.environ.get("GLP_PRINCIPAL_NAME"):
        principal_raw["name"] = os.environ["GLP_PRINCIPAL_NAME"]
    if os.environ.get("GLP_PRINCIPAL_ROLE"):
        principal_raw["role"] = os.environ["GLP_PRINCIPAL_ROLE"]
    principal = Principal(
        id=str(principal_raw.get("id") or ""),
        name=str(principal_raw.get("name") or ""),
        role=str(principal_raw.get("role") or ""),
    )

    retention_raw = dict(raw.get("retention") or {})
    retention = Retention(
        profile=str(retention_raw.get("profile") or "swiss_glp"),
        min_months=int(retention_raw.get("min_months") or 6),
        years_after_study=int(retention_raw.get("years_after_study") or 10),
        legal_hold=bool(retention_raw.get("legal_hold") or False),
        study_completion=retention_raw.get("study_completion"),
    )

    policy = Policy.from_mapping(dict(raw.get("policy") or {}))

    audit_raw = dict(raw.get("audit") or {})
    audit_path = Path(
        os.environ.get("GLP_AUDIT_PATH") or audit_raw.get("path") or "./data/audit.jsonl"
    )
    if not audit_path.is_absolute():
        audit_path = (config_path.parent / audit_path).resolve()

    fail_closed = bool(audit_raw.get("fail_closed", True))
    if os.environ.get("GLP_FAIL_CLOSED"):
        fail_closed = _parse_bool(os.environ["GLP_FAIL_CLOSED"], "GLP_FAIL_CLOSED")

    licence_value = os.environ.get("GLP_LICENCE_PATH") or raw.get("licence_path")
    licence_path = Path(licence_value) if licence_value else None
    if licence_path and not licence_path.is_absolute():
        licence_path = (config_path.parent / licence_path).resolve()
    client_id = _client_id(raw.get("client_id"))

    require_ntp = bool(raw.get("require_ntp") or False)
    if os.environ.get("GLP_REQUIRE_NTP"):
        require_ntp = _parse_bool(os.environ["GLP_REQUIRE_NTP"], "GLP_REQUIRE_NTP")

    export_value = raw.get("export_dir")
    export_dir = Path(export_value) if export_value else (audit_path.parent / "exports")
    if not export_dir.is_absolute():
        export_dir = (config_path.parent / export_dir).resolve()

    base = config_path.parent
    upstreams = [_upstream(item, base) for item in raw.get("upstreams") or []]
    storage, signer, reporters, auth, plugin_options = _plugins(raw)
    body_mode = str(audit_raw.get("body_mode") or "hash_only")
    redact_raw = audit_raw.get("redact_paths") or []
    if not isinstance(redact_raw, list) or not all(isinstance(item, str) for item in redact_raw):
        raise ConfigurationError("audit.redact_paths must be a list of strings")
    max_body = audit_raw.get("max_body_bytes", 1_048_576)
    if isinstance(max_body, bool) or not isinstance(max_body, int):
        raise ConfigurationError("audit.max_body_bytes must be an integer")
    alert_command = _alert_command(audit_raw.get("alert_command"))
    integrity_every = audit_raw.get("integrity_check_seconds", 0)
    if isinstance(integrity_every, bool) or not isinstance(integrity_every, int):
        raise ConfigurationError("audit.integrity_check_seconds must be an integer")
    settings = Settings(
        principal=principal,
        retention=retention,
        policy=policy,
        audit_path=audit_path,
        fail_closed=fail_closed,
        checkpoint_every=int(audit_raw.get("checkpoint_every") or 100),
        approval_ttl_seconds=int(raw.get("approval_ttl_seconds") or 3600),
        licence_path=licence_path,
        client_id=client_id,
        require_ntp=require_ntp,
        export_dir=export_dir,
        upstreams=upstreams,
        storage=storage,
        signer=signer,
        reporters=reporters,
        auth=auth,
        plugin_options=plugin_options,
        body_mode=body_mode,
        redact_paths=tuple(redact_raw),
        max_body_bytes=max_body,
        alert_command=alert_command,
        integrity_check_seconds=integrity_every,
        listen=_listen(raw.get("listen"), base) if raw.get("listen") is not None else None,
        routes=_routes(raw.get("routes") or []),
    )
    settings.validate()
    return settings


def _plugins(
    raw: dict[str, Any],
) -> tuple[str, str, tuple[str, ...], str, dict[str, Any]]:
    block = raw.get("plugins", None)
    if block is None:
        return "jsonl", "unsigned", _DEFAULT_REPORTERS, "env", {}
    if not isinstance(block, dict):
        raise ConfigurationError("plugins must be an object")
    unknown = set(block) - {"storage", "signer", "reporters", "auth"}
    if unknown:
        raise ConfigurationError(f"unknown plugins fields: {sorted(unknown)}")
    storage, storage_options = _named_plugin(block.get("storage", "jsonl"), "plugins.storage")
    signer, signer_options = _named_plugin(block.get("signer", "unsigned"), "plugins.signer")
    reporters, reporter_options = _reporter_plugins(
        block.get("reporters", list(_DEFAULT_REPORTERS))
    )
    auth, auth_options = _named_plugin(block.get("auth", "env"), "plugins.auth")
    options = {
        "storage": storage_options,
        "signer": signer_options,
        "reporters": reporter_options,
        "auth": auth_options,
    }
    return storage, signer, reporters, auth, options


def _named_plugin(value: object, label: str) -> tuple[str, dict[str, Any]]:
    """A plugin is a name, or {"name", "options"} (plugins.<group>.options)."""
    if isinstance(value, str):
        _check_plugin_name(value, label)
        return value, {}
    if isinstance(value, dict):
        unknown = set(value) - {"name", "options"}
        if unknown:
            raise ConfigurationError(f"unknown {label} fields: {sorted(unknown)}")
        _check_plugin_name(value.get("name"), label)
        return str(value["name"]), _options_object(value.get("options", {}), f"{label}.options")
    raise ConfigurationError(f"{label} must be a plugin name or an object with name and options")


def _reporter_plugins(value: object) -> tuple[tuple[str, ...], dict[str, Any]]:
    if isinstance(value, list):
        names = _reporter_names(value)
        return names, {}
    if isinstance(value, dict):
        unknown = set(value) - {"names", "options"}
        if unknown:
            raise ConfigurationError(f"unknown plugins.reporters fields: {sorted(unknown)}")
        names = _reporter_names(value.get("names"))
        options = _options_object(value.get("options", {}), "plugins.reporters.options")
        parsed: dict[str, Any] = {}
        for key, item in options.items():
            _check_plugin_name(key, "plugins.reporters.options")
            if key not in names:
                raise ConfigurationError(
                    f"plugins.reporters.options names {key!r} that is not selected"
                )
            if not isinstance(item, dict):
                raise ConfigurationError(
                    f"plugins.reporters.options[{key!r}] must be an object"
                )
            parsed[str(key)] = dict(item)
        return names, parsed
    raise ConfigurationError(
        "plugins.reporters must be a non-empty list or an object with names and options"
    )


def _reporter_names(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigurationError("plugins.reporters must be a non-empty list of plugin names")
    for name in value:
        _check_plugin_name(name, "plugins.reporters")
    if len(set(value)) != len(value):
        raise ConfigurationError("plugins.reporters must not repeat a name")
    return tuple(str(name) for name in value)


def _options_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{label} must be an object")
    return dict(value)


def _check_plugin_name(name: object, label: str) -> None:
    if not isinstance(name, str) or not _PLUGIN.fullmatch(name):
        raise ConfigurationError(f"{label} must be a plugin name")


def _upstream(item: object, base: Path | None = None) -> UpstreamConfig:
    if not isinstance(item, dict):
        raise ConfigurationError("upstream entries must be objects")
    env = item.get("env") or {}
    headers = item.get("headers") or {}
    if not isinstance(env, dict) or not isinstance(headers, dict):
        raise ConfigurationError("upstream env and headers must be objects")
    timeout = _timeout(item.get("timeout"))
    return UpstreamConfig(
        name=str(item.get("name") or ""),
        transport=str(item.get("transport") or "stdio"),
        protocol=str(item.get("protocol") or "auto"),
        command=item.get("command"),
        args=[str(arg) for arg in item.get("args") or []],
        env={str(key): str(value) for key, value in env.items()},
        url=item.get("url"),
        headers={str(key): str(value) for key, value in headers.items()},
        cwd=item.get("cwd"),
        timeout=timeout,
        kind=str(item.get("kind") or "mcp"),
        ca_file=_abs(base, item.get("ca_file")),
        endpoints=_endpoints(item.get("endpoints") or []),
    )


def _timeout(value: object) -> float | None:
    if value is None:
        return None
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("upstream timeout must be a positive number") from exc
    if timeout <= 0:
        raise ConfigurationError("upstream timeout must be a positive number")
    return timeout


def _client_id(value: Any) -> str | None:
    """Config client_id. Absent and null are the same. A licence that is bound needs one."""
    if value is None:
        return None
    if not isinstance(value, str) or not _CLIENT_ID.fullmatch(value):
        raise ConfigurationError("client_id must be a printable token")
    return value


def _abs(base: Path | None, value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ConfigurationError("file path must be a string")
    path = Path(value)
    if base is not None and not path.is_absolute():
        path = (base / path).resolve()
    return str(path)


def _endpoints(value: object) -> list[EndpointConfig]:
    if not isinstance(value, list):
        raise ConfigurationError("upstream endpoints must be a list")
    found: list[EndpointConfig] = []
    for item in value:
        if not isinstance(item, dict):
            raise ConfigurationError("upstream endpoint must be an object")
        unknown = set(item) - {"tool", "method", "path"}
        if unknown:
            raise ConfigurationError(f"unknown endpoint fields: {sorted(unknown)}")
        found.append(
            EndpointConfig(
                tool=str(item.get("tool") or ""),
                method=str(item.get("method") or "").upper(),
                path=str(item.get("path") or ""),
            )
        )
    return found


def _routes(value: object) -> list[RouteConfig]:
    if not isinstance(value, list):
        raise ConfigurationError("routes must be a list")
    found: list[RouteConfig] = []
    for item in value:
        if not isinstance(item, dict):
            raise ConfigurationError("route must be an object")
        unknown = set(item) - {"flow", "methods", "path", "upstream", "upstream_path", "tool"}
        if unknown:
            raise ConfigurationError(f"unknown route fields: {sorted(unknown)}")
        methods = item.get("methods")
        if not isinstance(methods, list) or not methods or not all(isinstance(m, str) for m in methods):
            raise ConfigurationError("route methods must be a non-empty list of strings")
        found.append(
            RouteConfig(
                flow=str(item.get("flow") or ""),
                methods=tuple(method.upper() for method in methods),
                path=str(item.get("path") or ""),
                upstream=str(item.get("upstream") or ""),
                upstream_path=item.get("upstream_path"),
                tool=item.get("tool"),
            )
        )
    return found


def _listen(value: object, base: Path) -> ListenConfig:
    if not isinstance(value, dict):
        raise ConfigurationError("listen must be an object")
    unknown = set(value) - {"bind", "port", "cert_file", "key_file", "identity"}
    if unknown:
        raise ConfigurationError(f"unknown listen fields: {sorted(unknown)}")
    port = value.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ConfigurationError("listen.port must be an integer from 0 to 65535")
    bind = value.get("bind")
    if not isinstance(bind, str) or not bind:
        raise ConfigurationError("listen.bind is required")
    cert = _abs(base, value.get("cert_file"))
    key = _abs(base, value.get("key_file"))
    if not cert or not key:
        raise ConfigurationError("listen.cert_file and listen.key_file are required")
    return ListenConfig(
        bind=bind,
        port=port,
        cert_file=cert,
        key_file=key,
        identity=_identity(value.get("identity"), base),
    )


def _identity(value: object, base: Path) -> ListenIdentity:
    if not isinstance(value, dict):
        raise ConfigurationError("listen.identity is required")
    unknown = set(value) - {
        "mode",
        "client_ca_file",
        "principals",
        "bearer_token_file",
        "bearer_principal",
        "end_user_header",
        "end_users",
    }
    if unknown:
        raise ConfigurationError(f"unknown listen.identity fields: {sorted(unknown)}")
    mode = value.get("mode")
    if mode not in {"mtls", "bearer", "mtls_and_bearer"}:
        raise ConfigurationError("listen.identity.mode must be mtls, bearer, or mtls_and_bearer")
    principals = tuple(_mapped(item, fingerprint=True) for item in value.get("principals") or [])
    end_users = tuple(_mapped(item, fingerprint=False) for item in value.get("end_users") or [])
    bearer_principal = None
    if value.get("bearer_principal") is not None:
        bearer_principal = _mapped(value.get("bearer_principal"), fingerprint=False)
    header = value.get("end_user_header")
    if header is not None and (not isinstance(header, str) or not header.strip()):
        raise ConfigurationError("end_user_header must be a header name")
    return ListenIdentity(
        mode=str(mode),
        client_ca_file=_abs(base, value.get("client_ca_file")),
        principals=principals,
        bearer_token_file=_abs(base, value.get("bearer_token_file")),
        bearer_principal=bearer_principal,
        end_user_header=header,
        end_users=end_users,
    )


def _mapped(value: object, *, fingerprint: bool) -> MappedPrincipal:
    if not isinstance(value, dict):
        raise ConfigurationError("principal map entries must be objects")
    allowed = {"id", "name", "role"}
    if fingerprint:
        allowed = allowed | {"fingerprint"}
    unknown = set(value) - allowed
    if unknown:
        raise ConfigurationError(f"unknown principal fields: {sorted(unknown)}")
    role = str(value.get("role") or "")
    if role not in ROLES:
        raise ConfigurationError(f"role must be one of {sorted(ROLES)}")
    ident = str(value.get("id") or "")
    name = str(value.get("name") or "")
    if not ident or not name:
        raise ConfigurationError("principal id and name are required")
    digest = None
    if fingerprint:
        raw = str(value.get("fingerprint") or "").lower().removeprefix("sha256:")
        raw = raw.replace(":", "")
        if not re.fullmatch(r"[0-9a-f]{64}", raw):
            raise ConfigurationError("client certificate fingerprint must be 64 hex characters")
        digest = raw
    return MappedPrincipal(id=ident, name=name, role=role, fingerprint=digest)


def _validate_listen(listen: ListenConfig | None) -> None:
    if listen is None:
        return
    identity = listen.identity
    if identity.mode in {"mtls", "mtls_and_bearer"}:
        if not identity.client_ca_file:
            raise ConfigurationError("mTLS requires listen.identity.client_ca_file")
        if not identity.principals:
            raise ConfigurationError("mTLS requires at least one fingerprint principal")
    if identity.mode in {"bearer", "mtls_and_bearer"}:
        if not identity.bearer_token_file or identity.bearer_principal is None:
            raise ConfigurationError("bearer identity requires bearer_token_file and bearer_principal")
    if identity.end_user_header and not identity.end_users:
        raise ConfigurationError("end_user_header requires end_users")


def _check_route_path(path: str, label: str) -> None:
    if not path.startswith("/") or path.startswith("//") or " " in path or ".." in path:
        raise ConfigurationError(f"{label} must be a single absolute path")


def _alert_command(raw: Any) -> tuple[str, ...]:
    if raw in (None, []):
        return ()
    if not isinstance(raw, list) or not all(isinstance(item, str) and item for item in raw):
        raise ConfigurationError("audit.alert_command must be a list of strings")
    return tuple(raw)


def _parse_bool(value: str, label: str) -> bool:
    lowered = value.strip().lower()
    if lowered in _TRUTHY:
        return True
    if lowered in _FALSY:
        return False
    raise ConfigurationError(f"{label} must be true or false")
