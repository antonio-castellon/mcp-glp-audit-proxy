"""Errors. Failures of the audit store are fatal to the call being audited."""

from __future__ import annotations

from typing import Any


class AuditStoreError(Exception):
    """The audit trail could not be written or read safely."""


class ChainIntegrityError(AuditStoreError):
    """The hash chain is broken. The proxy must not keep serving data calls."""

    def __init__(self, message: str, report: Any | None = None) -> None:
        super().__init__(message)
        self.report = report


class ConfigurationError(Exception):
    """The local config is missing or refuses a safety rule."""


class LicenceError(ValueError):
    """A licence file is invalid or expired. No features from it are enabled."""


class FeatureDisabled(Exception):
    """A feature flag or plugin the caller asked for is not available."""


class TlsRequired(Exception):
    """A remote transport was not https, so TLS 1.3 cannot be enforced."""


class UpstreamError(Exception):
    """An upstream MCP server failed or spoke a protocol we could not negotiate."""
