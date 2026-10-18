"""Tool allow / deny policy. Deny wins. An empty allow list denies every upstream tool."""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch


@dataclass(frozen=True)
class Decision:
    action: str  # allow, deny
    rule: str


@dataclass
class Policy:
    allow: list[str]
    deny: list[str]
    write_tools: list[str]
    require_approval_for_writes: bool = False
    require_reason_for_writes: bool = True

    def decide(self, tool: str, role: str) -> Decision:
        if role != "operator":
            return Decision("deny", f"role:{role}")
        for pattern in self.deny:
            if fnmatch.fnmatchcase(tool, pattern):
                return Decision("deny", f"deny:{pattern}")
        if not any(fnmatch.fnmatchcase(tool, pattern) for pattern in self.allow):
            return Decision("deny", "allow:none")
        return Decision("allow", "allow")

    def is_write(self, tool: str) -> bool:
        return any(fnmatch.fnmatchcase(tool, pattern) for pattern in self.write_tools)

    def as_dict(self) -> dict[str, object]:
        return {
            "allow": list(self.allow),
            "deny": list(self.deny),
            "require_approval_for_writes": self.require_approval_for_writes,
            "require_reason_for_writes": self.require_reason_for_writes,
            "write_tools": list(self.write_tools),
        }

    @classmethod
    def from_mapping(cls, raw: dict[str, object]) -> Policy:
        unknown = set(raw) - {
            "allow",
            "deny",
            "write_tools",
            "require_approval_for_writes",
            "require_reason_for_writes",
        }
        if unknown:
            raise ValueError(f"unknown policy fields: {sorted(unknown)}")
        allow = _string_list(raw.get("allow", []), "allow")
        deny = _string_list(raw.get("deny", []), "deny")
        write_tools = _string_list(raw.get("write_tools", []), "write_tools")
        return cls(
            allow=allow,
            deny=deny,
            write_tools=write_tools,
            require_approval_for_writes=bool(raw.get("require_approval_for_writes", False)),
            require_reason_for_writes=bool(raw.get("require_reason_for_writes", True)),
        )


def _string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return list(value)
