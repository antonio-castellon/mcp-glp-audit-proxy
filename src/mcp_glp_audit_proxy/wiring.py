"""Choose installed plugins from config. Pro implementations stay out of this repo.

Entry points are factories. This module checks the name, the licence and the
returned object. It does not construct a Pro backend itself.
"""

from __future__ import annotations

from typing import Any

from .config import Principal
from .errors import ConfigurationError
from .features import PRO_PLUGINS, FeatureSet

STORAGE_GROUP = "mcp_glp_audit_proxy.storage"
SIGNERS_GROUP = "mcp_glp_audit_proxy.signers"
REPORTERS_GROUP = "mcp_glp_audit_proxy.reporters"
AUTH_GROUP = "mcp_glp_audit_proxy.auth"

# Community entry point name -> feature flag. Pro names come from PRO_PLUGINS.
COMMUNITY_PLUGIN_FEATURES: dict[str, dict[str, str]] = {
    STORAGE_GROUP: {"jsonl": "storage.jsonl"},
    SIGNERS_GROUP: {"unsigned": "signer.unsigned"},
    REPORTERS_GROUP: {"json": "report.json", "text": "report.text"},
    AUTH_GROUP: {"env": "auth.env"},
}


def feature_for(group: str, name: str) -> str | None:
    found = COMMUNITY_PLUGIN_FEATURES.get(group, {}).get(name)
    if found:
        return found
    for feature, (grp, entry) in PRO_PLUGINS.items():
        if grp == group and entry == name:
            return feature
    return None


def load_named(features: FeatureSet, group: str, name: str) -> Any:
    """Return the factory for one plugin, or refuse to start.

    Unknown names are refused even when an entry point is installed. A known
    name is refused when the feature is not licensed or the plugin is absent.
    The factory is not called in those cases.
    """
    feature = feature_for(group, name)
    if feature is None:
        raise ConfigurationError(f"unknown plugin {name!r} in {group}")
    table = features.plugins.get(group) or {}
    installed = name in table
    licensed = feature in features.enabled
    if feature in features.unavailable and not installed:
        raise ConfigurationError(f"plugin {name!r} is not installed")
    if not licensed:
        raise ConfigurationError(f"plugin {name!r} is not licensed")
    if not installed:
        raise ConfigurationError(f"plugin {name!r} is not installed")
    factory = table[name]
    if not callable(factory):
        raise ConfigurationError(f"plugin {name!r} is not callable")
    return factory


def apply_identity(settings: Any, features: FeatureSet) -> None:
    """Replace settings.principal with the selected identity plugin's answer.

    The default plugin returns the principal load_settings already resolved.
    An unknown, unlicensed or missing auth plugin refuses startup.
    """
    provider = _call(load_named(features, AUTH_GROUP, settings.auth), settings, label=settings.auth)
    _check_identity(provider)
    resolved = provider.resolve()
    if not isinstance(resolved, dict):
        raise ConfigurationError("identity plugin did not return a principal")
    settings.principal = Principal(
        id=str(resolved.get("id") or ""),
        name=str(resolved.get("name") or ""),
        role=str(resolved.get("role") or ""),
    )
    settings.validate()


def build_components(settings: Any, features: FeatureSet) -> tuple[Any, dict[str, Any]]:
    """Build the signer, store and reporters selected by settings."""
    signer = _call(load_named(features, SIGNERS_GROUP, settings.signer), settings, label=settings.signer)
    _check_signer(signer)
    store = _call(
        load_named(features, STORAGE_GROUP, settings.storage),
        settings,
        signer,
        label=settings.storage,
    )
    _check_store(store)
    reporters: dict[str, Any] = {}
    for name in settings.reporters:
        reporter = _call(load_named(features, REPORTERS_GROUP, name), settings, label=name)
        _check_reporter(reporter)
        reporters[name] = reporter
    return store, reporters


def _call(factory: Any, *args: Any, label: str) -> Any:
    try:
        return factory(*args)
    except ConfigurationError:
        raise
    except Exception as exc:
        raise ConfigurationError(f"plugin {label!r} failed to load: {exc}") from exc


def _check_identity(provider: Any) -> None:
    if isinstance(provider, type):
        raise ConfigurationError("identity plugin factory must return an instance")
    name = getattr(provider, "name", None)
    if not isinstance(name, str) or not name:
        raise ConfigurationError("identity plugin has no name")
    if not callable(getattr(provider, "resolve", None)):
        raise ConfigurationError(f"identity plugin {name!r} does not implement IdentityProvider")


def _check_signer(signer: Any) -> None:
    if isinstance(signer, type):
        raise ConfigurationError("signer plugin factory must return an instance")
    name = getattr(signer, "name", None)
    if not isinstance(name, str) or not name:
        raise ConfigurationError("signer plugin has no name")
    if not callable(getattr(signer, "sign", None)) or not callable(getattr(signer, "verify", None)):
        raise ConfigurationError(f"signer plugin {name!r} does not implement Signer")


def _check_store(store: Any) -> None:
    if isinstance(store, type):
        raise ConfigurationError("storage plugin factory must return an instance")
    for method in ("health", "read_entries", "append_event"):
        if not callable(getattr(store, method, None)):
            raise ConfigurationError(f"storage plugin does not implement AuditStore.{method}")


def _check_reporter(reporter: Any) -> None:
    if isinstance(reporter, type):
        raise ConfigurationError("reporter plugin factory must return an instance")
    name = getattr(reporter, "name", None)
    if not isinstance(name, str) or not name:
        raise ConfigurationError("reporter plugin has no name")
    if not isinstance(getattr(reporter, "media_type", None), str):
        raise ConfigurationError(f"reporter plugin {name!r} has no media_type")
    if not callable(getattr(reporter, "render", None)):
        raise ConfigurationError(f"reporter plugin {name!r} does not implement Reporter")
