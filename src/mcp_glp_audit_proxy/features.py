"""Offline feature flags.

Community features are always on. Pro features turn on only when a local
licence file names them AND an installed entry point provides them.

This module does not open sockets. There is no phone-home.
"""

from __future__ import annotations

import json
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
    parse_expiry,
    verify_ed25519_licence,
    verify_lm1,
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

LICENCE_FORMAT = "mcp-glp-audit-proxy-licence"

PLUGIN_GROUPS = (
    "mcp_glp_audit_proxy.storage",
    "mcp_glp_audit_proxy.signers",
    "mcp_glp_audit_proxy.reporters",
    "mcp_glp_audit_proxy.auth",
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


def _json_needs_signature(raw: dict[str, Any]) -> bool:
    features = raw.get("features") or []
    extra = any(
        isinstance(item, str) and item not in COMMUNITY_FEATURES for item in features
    )
    return extra or raw.get("signature", None) is not None or "fingerprint" in raw


def validate_licence(
    raw: dict[str, Any],
    *,
    public_key: bytes | None = None,
) -> LicenceBody:
    """Verify an Ed25519 JSON licence and return its body.

    Community features do not need a signature. Any other feature, a
    ``fingerprint``, and any file that carries a signature, is checked with
    Ed25519 against the trust anchor. The clock comparison is separate so the
    fingerprint can be checked against the plugins installed in this process.
    """
    features = raw.get("features", [])
    if not isinstance(features, list) or not all(isinstance(item, str) for item in features):
        raise ValueError("licence features must be a list of strings")
    expires_at = None
    if "expires" in raw and raw.get("expires") is not None:
        expires_at = parse_expiry(raw.get("expires"), label="expires")
    if not _json_needs_signature(raw):
        return LicenceBody(features=list(features), fingerprint=None, expires_at=expires_at)
    if raw.get("signature", None) is None:
        raise LicenceError("licence signature is required")
    verify_ed25519_licence(raw, public_key=public_key)
    fingerprint = raw.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        raise LicenceError("licence fingerprint is required")
    return LicenceBody(features=list(features), fingerprint=fingerprint, expires_at=expires_at)


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
    if text.startswith("LM1"):
        return lm1_body(verify_lm1(text, public_pem=rsa_public_key))
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("licence must be a JSON object") from exc
    if not isinstance(raw, dict):
        raise ValueError("licence must be a JSON object")
    if raw.get("format") != LICENCE_FORMAT:
        raise ValueError("licence format is not mcp-glp-audit-proxy-licence")
    return validate_licence(raw, public_key=public_key)
