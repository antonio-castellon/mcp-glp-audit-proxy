"""Licence-gated signature plugins.

Community discovers the group and does not implement a signature. A factory
is called only when its licence feature is enabled and is outside the
Community set. Nothing here opens a socket.
"""

from __future__ import annotations

from typing import Any

from .errors import ConfigurationError
from .features import COMMUNITY_FEATURES, SIGNATURE_GROUP, FeatureSet, declared_feature


def licensed_signature_names(features: FeatureSet) -> list[str]:
    """Entry-point names that may sign. Does not call any factory."""
    table = features.plugins.get(SIGNATURE_GROUP) or {}
    names: list[str] = []
    for name in sorted(table):
        feature = declared_feature(table[name])
        if feature is None or feature in COMMUNITY_FEATURES or feature not in features.enabled:
            continue
        names.append(name)
    return names


def load_signature(features: FeatureSet, settings: Any, name: str) -> Any:
    """Call one licensed factory. An unlicensed name is not called."""
    table = features.plugins.get(SIGNATURE_GROUP) or {}
    if name not in licensed_signature_names(features):
        raise ConfigurationError(f"signature plugin {name!r} is not licensed")
    factory = table[name]
    if not callable(factory):
        raise ConfigurationError(f"signature plugin {name!r} is not callable")
    try:
        tool = factory(settings, options={})
    except ConfigurationError:
        raise
    except Exception as exc:
        raise ConfigurationError(f"signature plugin {name!r} failed to load: {exc}") from exc
    if not callable(getattr(tool, "sign", None)):
        raise ConfigurationError(f"signature plugin {name!r} does not sign")
    return tool
