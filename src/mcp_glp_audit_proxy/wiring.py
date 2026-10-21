"""Choose installed plugins from config. Pro implementations stay out of this repo.

Entry points are factories. This module checks the name, the licence and the
returned object. It does not construct a Pro backend itself.
"""

from __future__ import annotations

from typing import Any

from .config import Principal
from .errors import ConfigurationError
from .features import FeatureSet, declared_feature

STORAGE_GROUP = "mcp_glp_audit_proxy.storage"
SIGNERS_GROUP = "mcp_glp_audit_proxy.signers"
REPORTERS_GROUP = "mcp_glp_audit_proxy.reporters"
AUTH_GROUP = "mcp_glp_audit_proxy.auth"

def load_named(features: FeatureSet, group: str, name: str) -> Any:
    """Return the factory for one plugin, or refuse to start.

    The factory is not called unless it is installed, declares a licence
    feature, and that feature is enabled. An unlicensed plugin does not load.
    """
    table = features.plugins.get(group) or {}
    if name not in table:
        raise ConfigurationError(f"unknown plugin {name!r} in {group}")
    factory = table[name]
    if not callable(factory):
        raise ConfigurationError(f"plugin {name!r} is not callable")
    feature = declared_feature(factory)
    if feature is None:
        raise ConfigurationError(f"plugin {name!r} does not declare a licence feature")
    if feature not in features.enabled:
        raise ConfigurationError(f"plugin {name!r} is not licensed")
    return factory


def apply_identity(settings: Any, features: FeatureSet) -> None:
    """Replace settings.principal with the selected identity plugin's answer.

    The default plugin returns the principal load_settings already resolved.
    An unknown, unlicensed or missing auth plugin refuses startup.
    """
    provider = _call(
        load_named(features, AUTH_GROUP, settings.auth),
        settings,
        options=_group_options(settings, "auth"),
        label=settings.auth,
    )
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
    signer = _call(
        load_named(features, SIGNERS_GROUP, settings.signer),
        settings,
        options=_group_options(settings, "signer"),
        label=settings.signer,
    )
    _check_signer(signer)
    store = _call(
        load_named(features, STORAGE_GROUP, settings.storage),
        settings,
        signer,
        options=_group_options(settings, "storage"),
        label=settings.storage,
    )
    _check_store(store)
    reporters: dict[str, Any] = {}
    reporter_options = _group_options(settings, "reporters")
    for name in settings.reporters:
        one = reporter_options.get(name) or {}
        if not isinstance(one, dict):
            raise ConfigurationError(f"plugins.reporters.options[{name!r}] must be an object")
        reporter = _call(
            load_named(features, REPORTERS_GROUP, name),
            settings,
            options=dict(one),
            label=name,
        )
        _check_reporter(reporter)
        reporters[name] = reporter
    return store, reporters


def _call(factory: Any, *args: Any, options: dict[str, Any], label: str) -> Any:
    """Call a plugin factory. ``options`` is the plugins.<group>.options object."""
    try:
        return factory(*args, options=dict(options))
    except ConfigurationError:
        raise
    except Exception as exc:
        raise ConfigurationError(f"plugin {label!r} failed to load: {exc}") from exc


def _group_options(settings: Any, group: str) -> dict[str, Any]:
    block = getattr(settings, "plugin_options", None) or {}
    if not isinstance(block, dict):
        raise ConfigurationError("plugin options must be an object")
    selected = block.get(group) or {}
    if not isinstance(selected, dict):
        raise ConfigurationError(f"plugins.{group}.options must be an object")
    return dict(selected)


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
