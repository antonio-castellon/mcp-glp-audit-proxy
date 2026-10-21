"""JSON config plus environment overrides. Stdio identity comes from the environment."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .policy import Policy

ROLES = frozenset({"operator", "approver", "qa", "admin"})
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,40}$")
_PLUGIN = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
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
                "retention floor is 6 months (EU AI Act Art. 19 and Art. 26(6))"
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
    require_ntp: bool = False
    export_dir: Path | None = None
    upstreams: list[UpstreamConfig] | None = None
    storage: str = "jsonl"
    signer: str = "unsigned"
    reporters: tuple[str, ...] = _DEFAULT_REPORTERS

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
        for upstream in self.upstreams or []:
            if not _NAME.match(upstream.name) or "__" in upstream.name:
                raise ConfigurationError(
                    f"upstream name {upstream.name!r} must be a short token without '__'"
                )
            if upstream.transport not in {"stdio", "https"}:
                raise ConfigurationError(
                    f"upstream {upstream.name}: transport must be stdio or https"
                )
            if upstream.protocol not in {"auto", "legacy", "modern"}:
                raise ConfigurationError(
                    f"upstream {upstream.name}: protocol must be auto, legacy or modern"
                )
        _check_plugin_name(self.storage, "plugins.storage")
        _check_plugin_name(self.signer, "plugins.signer")
        if not isinstance(self.reporters, tuple) or not self.reporters:
            raise ConfigurationError("plugins.reporters must be a non-empty list of plugin names")
        if len(set(self.reporters)) != len(self.reporters):
            raise ConfigurationError("plugins.reporters must not repeat a name")
        for name in self.reporters:
            _check_plugin_name(name, "plugins.reporters")


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

    require_ntp = bool(raw.get("require_ntp") or False)
    if os.environ.get("GLP_REQUIRE_NTP"):
        require_ntp = _parse_bool(os.environ["GLP_REQUIRE_NTP"], "GLP_REQUIRE_NTP")

    export_value = raw.get("export_dir")
    export_dir = Path(export_value) if export_value else (audit_path.parent / "exports")
    if not export_dir.is_absolute():
        export_dir = (config_path.parent / export_dir).resolve()

    upstreams = [_upstream(item) for item in raw.get("upstreams") or []]
    storage, signer, reporters = _plugins(raw)
    settings = Settings(
        principal=principal,
        retention=retention,
        policy=policy,
        audit_path=audit_path,
        fail_closed=fail_closed,
        checkpoint_every=int(audit_raw.get("checkpoint_every") or 100),
        approval_ttl_seconds=int(raw.get("approval_ttl_seconds") or 3600),
        licence_path=licence_path,
        require_ntp=require_ntp,
        export_dir=export_dir,
        upstreams=upstreams,
        storage=storage,
        signer=signer,
        reporters=reporters,
    )
    settings.validate()
    return settings


def _plugins(raw: dict[str, Any]) -> tuple[str, str, tuple[str, ...]]:
    block = raw.get("plugins", None)
    if block is None:
        return "jsonl", "unsigned", _DEFAULT_REPORTERS
    if not isinstance(block, dict):
        raise ConfigurationError("plugins must be an object")
    unknown = set(block) - {"storage", "signer", "reporters"}
    if unknown:
        raise ConfigurationError(f"unknown plugins fields: {sorted(unknown)}")
    storage = block.get("storage", "jsonl")
    signer = block.get("signer", "unsigned")
    reporters = block.get("reporters", list(_DEFAULT_REPORTERS))
    _check_plugin_name(storage, "plugins.storage")
    _check_plugin_name(signer, "plugins.signer")
    if not isinstance(reporters, list) or not reporters:
        raise ConfigurationError("plugins.reporters must be a non-empty list of plugin names")
    for name in reporters:
        _check_plugin_name(name, "plugins.reporters")
    if len(set(reporters)) != len(reporters):
        raise ConfigurationError("plugins.reporters must not repeat a name")
    return str(storage), str(signer), tuple(str(name) for name in reporters)


def _check_plugin_name(name: object, label: str) -> None:
    if not isinstance(name, str) or not _PLUGIN.fullmatch(name):
        raise ConfigurationError(f"{label} must be a plugin name")


def _upstream(item: object) -> UpstreamConfig:
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


def _parse_bool(value: str, label: str) -> bool:
    lowered = value.strip().lower()
    if lowered in _TRUTHY:
        return True
    if lowered in _FALSY:
        return False
    raise ConfigurationError(f"{label} must be true or false")
