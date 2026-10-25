"""Fields added to audit/startup. Secrets stay out of the record."""

from __future__ import annotations

from typing import Any

from .canonical import canonicalize, sha256_hex
from .config import Settings

# Compared across startups. clock, config_sha256, config_changed, and
# change_reason are not configuration values.
COMPARED = (
    "body_mode",
    "fail_closed",
    "identities",
    "listen",
    "plugins",
    "policy",
    "principal",
    "redact_paths",
    "retention",
)

_SECRET_PARTS = ("token", "password", "secret", "authorization")


def startup_arguments(
    settings: Settings,
    *,
    clock: dict[str, Any],
    plugins: dict[str, Any],
    previous: dict[str, Any] | None,
    change_reason: str | None,
) -> tuple[dict[str, Any], str | None]:
    """Return the startup arguments and a warning line, if one is needed."""
    current: dict[str, Any] = {
        "audit_enabled": True,
        "body_mode": settings.body_mode,
        "clock": clock,
        "fail_closed": settings.fail_closed,
        "identities": identity_rows(settings),
        "listen": listen_row(settings),
        "plugins": plugins,
        "policy": settings.policy.as_dict(),
        "principal": settings.principal.as_dict(),
        "redact_paths": list(settings.redact_paths),
        "retention": settings.retention.as_dict(),
    }
    hashed = {key: value for key, value in current.items() if key != "clock"}
    current["config_sha256"] = sha256_hex(canonicalize(_scrub(hashed)))
    changed = config_changed(previous, current)
    current["change_reason"] = change_reason
    current["config_changed"] = changed
    warning = None
    if (
        isinstance(changed, list)
        and changed
        and not change_reason
        and settings.policy.require_reason_for_writes
    ):
        warning = (
            "warning: configuration changed since the previous startup "
            "and no change reason was given"
        )
    return current, warning


def config_changed(previous: dict[str, Any] | None, current: dict[str, Any]) -> list[str] | None:
    """Null when this log has no earlier startup that recorded body_mode."""
    if not isinstance(previous, dict) or "body_mode" not in previous:
        return None
    changed = [key for key in COMPARED if previous.get(key) != current.get(key)]
    return sorted(changed)


def last_startup_arguments(entries: list[dict[str, Any]]) -> dict[str, Any] | None:
    for entry in reversed(entries):
        if entry.get("method") == "audit/startup":
            arguments = entry.get("arguments")
            return arguments if isinstance(arguments, dict) else {}
    return None


def identity_rows(settings: Settings) -> list[dict[str, str]]:
    rows = [
        {
            "id": settings.principal.id,
            "match": "stdio",
            "name": settings.principal.name,
            "role": settings.principal.role,
        }
    ]
    listen = settings.listen
    if listen is None:
        return rows
    identity = listen.identity
    for item in identity.principals:
        rows.append(
            {
                "id": item.id,
                "match": item.fingerprint or "",
                "name": item.name,
                "role": item.role,
            }
        )
    if identity.bearer_principal is not None:
        rows.append(
            {
                "id": identity.bearer_principal.id,
                "match": f"bearer:{identity.bearer_token_file or ''}",
                "name": identity.bearer_principal.name,
                "role": identity.bearer_principal.role,
            }
        )
    for item in identity.end_users:
        rows.append(
            {
                "id": item.id,
                "match": f"header:{identity.end_user_header or ''}",
                "name": item.name,
                "role": item.role,
            }
        )
    return rows


def listen_row(settings: Settings) -> dict[str, Any] | None:
    listen = settings.listen
    if listen is None:
        return None
    return {
        "host": listen.bind,
        "identity": listen.identity.mode,
        "port": listen.port,
        "tls": "1.3",
    }


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if _secret_key(str(key)):
                cleaned[key] = "***"
            else:
                cleaned[key] = _scrub(item)
        return cleaned
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    return value


def _secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in _SECRET_PARTS)
