"""Offline feature flags.

Community features are always on. Pro features turn on only when a local
licence file names them AND an installed entry point provides them.

This module does not open sockets. There is no phone-home.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import LicenceError
from .licence import verify_ed25519_licence
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


def validate_licence(
    raw: dict[str, Any],
    *,
    public_key: bytes | None = None,
    now: datetime | None = None,
) -> None:
    """Reject a licence that is not a valid signed grant of its extra features.

    Community features do not need a signature. Any other feature, and any
    file that carries a signature, is checked with Ed25519 against the trust
    anchor. ``expires``, when present, is then compared with the local clock.
    There is no network call and no grace period fetched from a vendor.
    """
    features = raw.get("features") or []
    extra = [
        item
        for item in features
        if isinstance(item, str) and item not in COMMUNITY_FEATURES
    ]
    if raw.get("signature", None) is not None or extra:
        if raw.get("signature", None) is None:
            raise LicenceError("licence signature is required")
        verify_ed25519_licence(raw, public_key=public_key)
    _reject_expired(raw, now=now)


def _reject_expired(raw: dict[str, Any], *, now: datetime | None) -> None:
    if "expires" not in raw or raw.get("expires") is None:
        return
    value = raw.get("expires")
    if not isinstance(value, str) or not value.strip():
        raise LicenceError("licence expires must be an RFC3339 timestamp")
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LicenceError("licence expires must be an RFC3339 timestamp") from exc
    if moment.tzinfo is None:
        raise LicenceError("licence expires must include a time zone")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    if current >= moment:
        raise LicenceError("licence expired")


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
        now: datetime | None = None,
    ) -> FeatureSet:
        requested: list[str] = []
        if path is not None:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("licence must be a JSON object")
            if raw.get("format") != LICENCE_FORMAT:
                raise ValueError("licence format is not mcp-glp-audit-proxy-licence")
            features = raw.get("features", [])
            if not isinstance(features, list) or not all(isinstance(item, str) for item in features):
                raise ValueError("licence features must be a list of strings")
            # No licence file skips this entirely. Community features stay on.
            validate_licence(raw, public_key=public_key, now=now)
            requested = list(features)

        plugins = {group: load_group(group) for group in PLUGIN_GROUPS}
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
