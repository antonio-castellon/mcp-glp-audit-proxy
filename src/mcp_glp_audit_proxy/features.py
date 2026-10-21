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

# Implemented only by the licensed Pro edition. Names are the contract.
PRO_FEATURES = frozenset(
    {
        "storage.postgres",
        "storage.mssql",
        "storage.s3_object_lock",
        "signer.ed25519",
        "signer.ecdsa",
        "timestamp.rfc3161",
        "signature.part11",
        "report.pdf",
        "report.csv",
        "validation.iqoq",
        "auth.sso",
        "auth.oauth",
    }
)

# feature -> (entry point group, entry point name)
PRO_PLUGINS: dict[str, tuple[str, str]] = {
    "storage.postgres": ("mcp_glp_audit_proxy.storage", "postgres"),
    "storage.mssql": ("mcp_glp_audit_proxy.storage", "mssql"),
    "storage.s3_object_lock": ("mcp_glp_audit_proxy.storage", "s3"),
    "signer.ed25519": ("mcp_glp_audit_proxy.signers", "ed25519"),
    "signer.ecdsa": ("mcp_glp_audit_proxy.signers", "ecdsa_p256"),
    "timestamp.rfc3161": ("mcp_glp_audit_proxy.signers", "rfc3161"),
    "signature.part11": ("mcp_glp_audit_proxy.signers", "part11"),
    "report.pdf": ("mcp_glp_audit_proxy.reporters", "pdf"),
    "report.csv": ("mcp_glp_audit_proxy.reporters", "csv"),
    "validation.iqoq": ("mcp_glp_audit_proxy.reporters", "iqoq"),
    "auth.sso": ("mcp_glp_audit_proxy.auth", "sso"),
    "auth.oauth": ("mcp_glp_audit_proxy.auth", "oauth"),
}

LICENCE_FORMAT = "mcp-glp-audit-proxy-licence"
LICENCE_GROUP = "mcp_glp_audit_proxy.licence"


class CommunityLicenceVerifier:
    """Signature check used when no licence verifier entry point is installed.

    A licence with no signature is accepted. Expiry is checked separately by
    ``validate_licence`` before this method runs. A signature cannot be checked
    here: this package has no vendor key and does not open a socket.
    """

    name = "community"

    def verify(self, raw: dict[str, Any]) -> None:
        signature = raw.get("signature", None)
        if signature is None:
            return
        if not isinstance(signature, dict):
            raise LicenceError("licence signature must be an object")
        raise LicenceError(
            "licence signature cannot be verified; no licence verifier is installed"
        )


def resolve_licence_verifier() -> Any:
    """Return the installed licence verifier, or the Community one.

    The entry-point group is ``mcp_glp_audit_proxy.licence``. Each value is a
    zero-argument factory. One factory is used. When several are installed,
    the name ``default`` is required. This repository registers none.
    """
    group = load_group(LICENCE_GROUP)
    if not group:
        return CommunityLicenceVerifier()
    if "default" in group:
        factory = group["default"]
    elif len(group) == 1:
        factory = next(iter(group.values()))
    else:
        raise LicenceError(
            "multiple licence verifiers are installed; register the name 'default'"
        )
    if not callable(factory):
        raise LicenceError("licence verifier is not callable")
    try:
        verifier = factory()
    except LicenceError:
        raise
    except Exception as exc:
        raise LicenceError(f"licence verifier failed to load: {exc}") from exc
    if not callable(getattr(verifier, "verify", None)):
        raise LicenceError("licence verifier does not implement verify")
    return verifier


def validate_licence(
    raw: dict[str, Any],
    *,
    verifier: Any | None = None,
    now: datetime | None = None,
) -> None:
    """Reject an expired licence, then delegate the signature.

    ``expires``, when present, is compared with the local clock. There is no
    network call and no grace period fetched from a vendor. A ``signature`` is
    accepted only when ``verifier`` (or the installed entry point) accepts it.
    """
    _reject_expired(raw, now=now)
    checker = verifier if verifier is not None else resolve_licence_verifier()
    try:
        result = checker.verify(raw)
    except LicenceError:
        raise
    except Exception as exc:
        raise LicenceError(f"licence rejected: {exc}") from exc
    if result is False:
        raise LicenceError("licence signature is invalid")


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
        verifier: Any | None = None,
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
            validate_licence(raw, verifier=verifier, now=now)
            requested = list(features)

        groups = (
            "mcp_glp_audit_proxy.storage",
            "mcp_glp_audit_proxy.signers",
            "mcp_glp_audit_proxy.reporters",
            "mcp_glp_audit_proxy.auth",
        )
        plugins = {group: load_group(group) for group in groups}
        enabled = set(COMMUNITY_FEATURES)
        unavailable: list[str] = []
        for feature in requested:
            if feature in COMMUNITY_FEATURES:
                continue
            if feature not in PRO_FEATURES:
                unavailable.append(feature)
                continue
            group, name = PRO_PLUGINS[feature]
            if name in plugins.get(group, {}):
                enabled.add(feature)
            else:
                # Requested, but this install has no plugin. Do not pretend.
                unavailable.append(feature)
        return cls(enabled=enabled, unavailable=unavailable, plugins=plugins)
