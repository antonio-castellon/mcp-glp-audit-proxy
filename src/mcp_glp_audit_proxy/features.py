"""Offline feature flags.

Community features are always on. Pro features turn on only when a local
licence file names them AND an installed entry point provides them.

This module does not open sockets. There is no phone-home.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import LicenceError
from .licence import (
    LicenceBody,
    assert_not_expired,
    fingerprint_matches,
    licence_fingerprint,
    lm1_body,
    lm2_body,
    verify_lm1,
    verify_lm2,
)
from .plugins import load_group

COMMUNITY_FEATURES = frozenset(
    {
        "storage.jsonl",
        "signer.unsigned",
        "report.json",
        "report.text",
        "verify",
        "policy.allowlist",
        "approval.local",
        "rbac.local",
        "auth.env",
    }
)

WIZARD_GROUP = "mcp_glp_audit_proxy.wizard"

PLUGIN_GROUPS = (
    "mcp_glp_audit_proxy.storage",
    "mcp_glp_audit_proxy.signers",
    "mcp_glp_audit_proxy.reporters",
    "mcp_glp_audit_proxy.auth",
    WIZARD_GROUP,
)


def declared_feature(factory: Any) -> str | None:
    """Return the licence feature a plugin factory declares, if it declares one."""
    value = getattr(factory, "licence_feature", None)
    if isinstance(value, str) and value:
        return value
    return None


def discover_features(plugins: dict[str, dict[str, Any]]) -> set[str]:
    """Features declared by installed entry points. There is no built-in Pro list."""
    found: set[str] = set()
    for table in plugins.values():
        for factory in table.values():
            feature = declared_feature(factory)
            if feature is not None:
                found.add(feature)
    return found


def licensed_plugin_names(plugins: dict[str, dict[str, Any]]) -> list[str]:
    """Entry-point names that declare a feature outside the Community set.

    Community factories are not part of the fingerprint. Adding one of these
    names changes the fingerprint, so the previous licence no longer matches.
    """
    names: list[str] = []
    for table in plugins.values():
        for name, factory in table.items():
            feature = declared_feature(factory)
            if feature is not None and feature not in COMMUNITY_FEATURES:
                names.append(name)
    return sorted(set(names))


def licensed_plugin_features(plugins: dict[str, dict[str, Any]]) -> list[str]:
    """Features declared by the entry points that go into the fingerprint."""
    found: list[str] = []
    for table in plugins.values():
        for factory in table.values():
            feature = declared_feature(factory)
            if feature is not None and feature not in COMMUNITY_FEATURES:
                found.append(feature)
    return found


@dataclass
class FeatureSet:
    enabled: set[str] = field(default_factory=lambda: set(COMMUNITY_FEATURES))
    unavailable: list[str] = field(default_factory=list)
    plugins: dict[str, dict[str, object]] = field(default_factory=dict)

    def allows(self, feature: str) -> bool:
        return feature in self.enabled

    @classmethod
    def community(cls) -> FeatureSet:
        return cls.load(None)

    @classmethod
    def load(
        cls,
        path: Path | None,
        *,
        public_key: bytes | None = None,
        rsa_public_key: bytes | None = None,
        client_id: str | None = None,
        now: datetime | None = None,
    ) -> FeatureSet:
        body: LicenceBody | None = None
        if path is not None:
            # No licence file skips this entirely. Community features stay on.
            body = _read_licence(
                Path(path).read_text(encoding="utf-8"),
                public_key=public_key,
                rsa_public_key=rsa_public_key,
            )

        plugins = {group: load_group(group) for group in PLUGIN_GROUPS}
        if body is not None and body.fingerprint is not None:
            if not isinstance(client_id, str) or not client_id:
                raise LicenceError("licence client_id is required")
            expected = licence_fingerprint(client_id, licensed_plugin_names(plugins))
            if not fingerprint_matches(body.fingerprint, expected):
                raise LicenceError("licence fingerprint does not match")
        if body is not None:
            assert_not_expired(body.expires_at, now=now)
        if body is not None and body.grant_installed:
            requested = licensed_plugin_features(plugins)
        else:
            requested = [] if body is None else body.features
        discovered = discover_features(plugins)
        enabled = set(COMMUNITY_FEATURES)
        unavailable: list[str] = []
        for feature in requested:
            if feature in COMMUNITY_FEATURES:
                continue
            if feature in discovered:
                enabled.add(feature)
                continue
            # Named by the licence, but no installed plugin declares it.
            unavailable.append(feature)
        return cls(enabled=enabled, unavailable=unavailable, plugins=plugins)


def _read_licence(
    text: str,
    *,
    public_key: bytes | None,
    rsa_public_key: bytes | None,
) -> LicenceBody:
    header = text.split("\n", 1)[0]
    if header == "LM2":
        return lm2_body(verify_lm2(text, public_key=public_key))
    if header == "LM1":
        return lm1_body(verify_lm1(text, public_pem=rsa_public_key))
    if text.startswith("LM"):
        raise LicenceError("licence LM format is not LM1 or LM2")
    raise LicenceError("licence must be LM1 or LM2 text")
