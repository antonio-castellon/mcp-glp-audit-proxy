"""Community identity plugin.

The principal is chosen in load_settings from GLP_PRINCIPAL_* or config.json.
This module returns that principal. It does not contact an identity provider.
SSO and OAuth register in the same entry-point group from a separate package.
"""

from __future__ import annotations

from typing import Any

from .config import Principal


class EnvIdentity:
    name = "env"

    def __init__(self, principal: Principal) -> None:
        self._principal = principal

    def resolve(self) -> dict[str, str]:
        return self._principal.as_dict()


def env_identity(settings: Any) -> EnvIdentity:
    """Entry point factory. Pro auth plugins use the same (settings,) signature."""
    return EnvIdentity(settings.principal)
