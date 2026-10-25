"""Allow / deny policy. Deny wins. An empty allow list denies every call it covers.

Tool globs apply to MCP names (``server__tool``). HTTP rules apply to the
request method plus the request path. The two lists do not stand in for
each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import fnmatch
import re

# Exposed names are server__tool. Anything outside this set is denied so a
# lookalike, space or control character cannot slip past a glob.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,200}$")
_HTTP_METHOD = re.compile(r"^[A-Z]+$")
HTTP_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


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
    http_allow: list[str] = field(default_factory=list)
    http_deny: list[str] = field(default_factory=list)

    def decide(self, tool: str, role: str) -> Decision:
        if role != "operator":
            return Decision("deny", f"role:{role}")
        problem = name_problem(tool)
        if problem:
            return Decision("deny", problem)
        for pattern in self.deny:
            if fnmatch.fnmatchcase(tool, pattern):
                return Decision("deny", f"deny:{pattern}")
        if not any(fnmatch.fnmatchcase(tool, pattern) for pattern in self.allow):
            return Decision("deny", "allow:none")
        return Decision("allow", "allow")

    def decide_http(self, method: str, path: str, role: str) -> Decision:
        """Method plus request path. Deny wins. An empty allow list denies every path."""
        if role != "operator":
            return Decision("deny", f"role:{role}")
        verb = method.upper()
        for pattern in self.http_deny:
            if _http_match(pattern, verb, path):
                return Decision("deny", f"deny:{pattern}")
        if not any(_http_match(pattern, verb, path) for pattern in self.http_allow):
            return Decision("deny", "allow:none")
        return Decision("allow", "allow")

    def is_write(self, tool: str) -> bool:
        return any(fnmatch.fnmatchcase(tool, pattern) for pattern in self.write_tools)

    def is_http_write(self, method: str) -> bool:
        return method.upper() in HTTP_WRITE_METHODS

    def as_dict(self) -> dict[str, object]:
        return {
            "allow": list(self.allow),
            "deny": list(self.deny),
            "http_allow": list(self.http_allow),
            "http_deny": list(self.http_deny),
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
            "http_allow",
            "http_deny",
        }
        if unknown:
            raise ValueError(f"unknown policy fields: {sorted(unknown)}")
        allow = _string_list(raw.get("allow", []), "allow")
        deny = _string_list(raw.get("deny", []), "deny")
        write_tools = _string_list(raw.get("write_tools", []), "write_tools")
        http_allow = _http_patterns(raw.get("http_allow", []), "http_allow")
        http_deny = _http_patterns(raw.get("http_deny", []), "http_deny")
        return cls(
            allow=allow,
            deny=deny,
            write_tools=write_tools,
            require_approval_for_writes=bool(raw.get("require_approval_for_writes", False)),
            require_reason_for_writes=bool(raw.get("require_reason_for_writes", True)),
            http_allow=http_allow,
            http_deny=http_deny,
        )


def name_problem(tool: str) -> str | None:
    """Return a deny rule when the tool name is not a plain ASCII token."""
    if tool != tool.strip() or not tool.strip():
        return "name:whitespace"
    if not _SAFE_NAME.fullmatch(tool):
        return "name:charset"
    return None


def _string_list(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return list(value)


def _http_patterns(value: object, field: str) -> list[str]:
    patterns = _string_list(value, field)
    for pattern in patterns:
        method, sep, path = pattern.partition(" ")
        if not sep or " " in path or not path.startswith("/") or path.startswith("//"):
            raise ValueError(f"{field} entries must look like 'GET /v1/studies/*'")
        if method != "*" and not _HTTP_METHOD.fullmatch(method):
            raise ValueError(f"{field} method must be uppercase or *")
    return patterns


def _http_match(pattern: str, method: str, path: str) -> bool:
    rule_method, _, rule_path = pattern.partition(" ")
    if rule_method != "*" and rule_method != method:
        return False
    return fnmatch.fnmatchcase(path, rule_path)
