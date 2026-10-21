"""Check checkpoint signatures with one licensed signer and a pinned key.

Community checkpoints are unsigned. ``verify --pubkey`` does not ask the
unsigned signer to accept a key. A Pro signer registers in
``mcp_glp_audit_proxy.signers``, declares a licence feature outside the
Community set, and implements ``verify(payload, signature, public_key=...)``.
"""

from __future__ import annotations

from typing import Any

from .canonical import canonicalize
from .errors import ConfigurationError
from .features import COMMUNITY_FEATURES, FeatureSet, declared_feature
from .wiring import SIGNERS_GROUP


def licensed_signer(features: FeatureSet) -> Any:
    """Return the one licensed signer. The unsigned factory is not called."""
    table = features.plugins.get(SIGNERS_GROUP) or {}
    chosen: tuple[str, Any] | None = None
    names: list[str] = []
    for name in sorted(table):
        factory = table[name]
        feature = declared_feature(factory)
        if feature is None or feature in COMMUNITY_FEATURES or feature not in features.enabled:
            continue
        names.append(name)
        chosen = (name, factory)
    if not names or chosen is None:
        raise ConfigurationError("no licensed signer plugin")
    if len(names) > 1:
        raise ConfigurationError("more than one licensed signer plugin")
    name, factory = chosen
    if not callable(factory):
        raise ConfigurationError(f"signer plugin {name!r} is not callable")
    try:
        signer = factory(None, options={})
    except ConfigurationError:
        raise
    except Exception as exc:
        raise ConfigurationError(f"signer plugin {name!r} failed to load: {exc}") from exc
    if not callable(getattr(signer, "verify", None)):
        raise ConfigurationError(f"signer plugin {name!r} does not verify")
    return signer


def signature_errors(entries: list[dict[str, Any]], public_key: bytes, signer: Any) -> list[str]:
    """Return plain errors. An empty list means every checkpoint matched the key."""
    checkpoints = [entry for entry in entries if entry.get("method") == "audit/checkpoint"]
    if not checkpoints:
        return ["no checkpoint to check"]
    errors: list[str] = []
    for entry in checkpoints:
        seq = entry.get("seq")
        signature = (entry.get("result") or {}).get("signature") if isinstance(entry.get("result"), dict) else None
        if not isinstance(signature, dict):
            errors.append(f"checkpoint seq {seq} has no signature")
            continue
        if signature.get("signed") is False and signature.get("value") is None:
            errors.append(f"checkpoint seq {seq} is unsigned")
            continue
        try:
            arguments = entry["arguments"]
            payload = canonicalize(
                {
                    "head_hash": arguments["head_hash"],
                    "seq": arguments["seq"],
                    "timestamp": entry["timestamp"],
                }
            )
        except (KeyError, TypeError):
            errors.append(f"checkpoint seq {seq} has no signature payload")
            continue
        try:
            ok = signer.verify(payload, signature, public_key=public_key)
        except TypeError:
            errors.append("signer plugin does not accept a pinned public key")
            break
        except Exception as exc:
            errors.append(f"checkpoint seq {seq} could not be checked: {exc}")
            continue
        if ok is not True:
            errors.append(f"checkpoint seq {seq} does not match the pinned public key")
    return errors


def check_log(
    entries: list[dict[str, Any]],
    public_key: bytes,
    features: FeatureSet | None = None,
) -> list[str]:
    """Load the licensed signer, then check every checkpoint."""
    try:
        signer = licensed_signer(features if features is not None else FeatureSet.load(None))
    except ConfigurationError as exc:
        return [str(exc)]
    return signature_errors(entries, public_key, signer)
