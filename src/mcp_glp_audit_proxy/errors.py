"""Errors. Failures of the audit store are fatal to the call being audited."""

from __future__ import annotations


class AuditStoreError(Exception):
    """The audit trail could not be written or read safely."""


class ChainIntegrityError(AuditStoreError):
    """The hash chain is broken. The proxy must not keep serving data calls."""


class ConfigurationError(Exception):
    """The local config is missing or refuses a safety rule."""


class FeatureDisabled(Exception):
    """A feature flag or plugin the caller asked for is not available."""


class TlsRequired(Exception):
    """A remote transport was not https, so TLS 1.3 cannot be enforced."""


class UpstreamError(Exception):
    """An upstream MCP server failed or spoke a protocol we could not negotiate."""
