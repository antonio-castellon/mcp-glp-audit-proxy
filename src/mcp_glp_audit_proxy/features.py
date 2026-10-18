"""Offline feature flags.

Community features are always on. Pro features turn on only when a local
licence file names them AND an installed entry point provides them.

This module does not open sockets. There is no phone-home.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

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
    def load(cls, path: Path | None) -> FeatureSet:
        requested: list[str] = []
        if path is not None:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            if raw.get("format") != LICENCE_FORMAT:
                raise ValueError("licence format is not mcp-glp-audit-proxy-licence")
            features = raw.get("features", [])
            if not isinstance(features, list) or not all(isinstance(item, str) for item in features):
                raise ValueError("licence features must be a list of strings")
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
