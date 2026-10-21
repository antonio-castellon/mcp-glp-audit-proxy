"""Interactive config writer and config check.

ASCII prompts only. This module does not open a socket.
"""

from __future__ import annotations

import errno
import json
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import ROLES, load_settings
from .errors import ConfigurationError
from .features import COMMUNITY_FEATURES, WIZARD_GROUP, FeatureSet, declared_feature

_KEY = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
_RESERVED = frozenset({"principal", "retention", "policy", "audit"})
_PROFILES = frozenset({"swiss_glp", "minimum"})
_OVERRIDES = (
    "GLP_PRINCIPAL_ID",
    "GLP_PRINCIPAL_NAME",
    "GLP_PRINCIPAL_ROLE",
    "GLP_AUDIT_PATH",
    "GLP_FAIL_CLOSED",
    "GLP_LICENCE_PATH",
    "GLP_REQUIRE_NTP",
)
_USAGE_INIT = "usage: mcp-glp-audit-proxy init [PATH]"
_USAGE_CONFIG = "usage: mcp-glp-audit-proxy config check [PATH]"


@dataclass(frozen=True)
class WizardQuestion:
    """One extra prompt from a licensed wizard plugin."""

    key: str
    prompt: str
    default: str | None = None


def init_main(argv: list[str] | None = None) -> int:
    """Write a config. ``argv`` is everything after the ``init`` word."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] in (["--help"], ["-h"]):
        print(_USAGE_INIT)
        return 0
    if any(item.startswith("-") for item in args) or len(args) > 1:
        print(_USAGE_INIT, file=sys.stderr)
        return 2
    path = args[0] if args else os.environ.get("GLP_CONFIG", "config.json")
    return run_init(Path(path))


def config_main(argv: list[str] | None = None) -> int:
    """``config check`` loads a file and prints a plain-language error."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] in (["--help"], ["-h"]):
        print(_USAGE_CONFIG)
        return 0
    if not args or args[0] != "check":
        print(_USAGE_CONFIG, file=sys.stderr)
        return 2
    rest = args[1:]
    if rest[:1] in (["--help"], ["-h"]):
        print(_USAGE_CONFIG)
        return 0
    if any(item.startswith("-") for item in rest) or len(rest) > 1:
        print(_USAGE_CONFIG, file=sys.stderr)
        return 2
    path = rest[0] if rest else os.environ.get("GLP_CONFIG", "config.json")
    return check_config(Path(path))


def _write_private(path: Path, payload: bytes) -> None:
    """Create ``path`` as mode 0600. The umask cannot leave it group-readable."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = payload
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError(errno.EIO, "short write")
            view = view[written:]
        os.fsync(fd)
    except OSError:
        os.close(fd)
        raise
    os.close(fd)


def run_init(
    dest: Path,
    *,
    input_fn: Callable[[str], str] | None = None,
    features: FeatureSet | None = None,
) -> int:
    """Ask the built-in questions, then licensed plugin questions, and write."""
    ask = input if input_fn is None else input_fn
    temporary: Path | None = None
    try:
        _ascii_path(dest)
        flags = features if features is not None else _features_for_plugins(ask)
        document = _builtin_document(ask)
        tools = _licensed_tools(flags)
        _apply_plugin_answers(document, tools, ask)
        if not dest.parent.is_dir():
            raise ConfigurationError(f"config directory does not exist: {dest.parent}")
        if dest.exists() and dest.is_dir():
            raise ConfigurationError(f"config path is a directory: {dest}")
        text = json.dumps(document, indent=2, sort_keys=True) + "\n"
        text.encode("ascii")
        temporary = dest.with_name(f".{dest.name}.{os.getpid()}.tmp")
        _write_private(temporary, text.encode("ascii"))
        _load_without_overrides(temporary)
        _validate_tools(tools, document)
        if dest.exists() and not _confirmed(ask):
            _say("not overwritten", sys.stderr)
            return 1
        os.replace(temporary, dest)
        temporary = None
        _say(f"wrote {dest}", sys.stdout)
        return 0
    except EOFError:
        _say("input ended before the config was written", sys.stderr)
        return 1
    except (ConfigurationError, OSError, ValueError) as exc:
        _say(f"mcp-glp-audit-proxy: {_plain(exc)}", sys.stderr)
        return 1
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return 1


def check_config(path: Path, *, features: FeatureSet | None = None) -> int:
    """Exit 0 when the file loads. Exit 1 with a plain sentence otherwise."""
    try:
        settings = load_settings(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ConfigurationError("config must be a JSON object")
        flags = (
            features
            if features is not None
            else FeatureSet.load(settings.licence_path, client_id=settings.client_id)
        )
        _validate_tools(_licensed_tools(flags), raw)
    except (ConfigurationError, OSError, ValueError) as exc:
        _say(f"config check failed: {_plain(exc)}", sys.stderr)
        return 1
    _say("config check ok", sys.stdout)
    return 0


def _builtin_document(ask: Callable[[str], str]) -> dict[str, Any]:
    log_path = _ask(
        "Audit log path [./data/audit.jsonl]: ",
        ask,
        _with_default("./data/audit.jsonl", _parse_log_path),
    )
    allow = _ask(
        "Allow list (comma-separated globs; empty denies every tool): ",
        ask,
        _parse_allow,
    )
    principal_id = _ask("Principal id: ", ask, _parse_id)
    principal_name = _ask("Principal name: ", ask, _parse_name)
    role = _ask(
        "Principal role (operator, approver, qa, admin) [operator]: ",
        ask,
        _with_default("operator", _parse_role),
    )
    profile = _ask(
        "Retention profile (swiss_glp, minimum) [swiss_glp]: ",
        ask,
        _with_default("swiss_glp", _parse_profile),
    )
    legal_hold = _ask(
        "Legal hold (yes/no) [no]: ",
        ask,
        _with_default("no", _parse_yes_no),
    )
    return {
        "audit": {"path": log_path},
        "policy": {"allow": allow},
        "principal": {"id": principal_id, "name": principal_name, "role": role},
        "retention": {
            "legal_hold": legal_hold,
            "min_months": 6,
            "profile": profile,
            "years_after_study": 10,
        },
    }


def _features_for_plugins(ask: Callable[[str], str]) -> FeatureSet:
    """Ask for a licence only when a wizard entry point is installed."""
    from . import features as features_mod

    installed = features_mod.load_group(WIZARD_GROUP)
    if not installed:
        return FeatureSet.load(None)
    licence = _ask("Licence path (empty if none): ", ask, _parse_optional_ascii).strip()
    client_id = _ask("Client id (empty if none): ", ask, _parse_optional_ascii).strip()
    return FeatureSet.load(Path(licence) if licence else None, client_id=client_id or None)


def _licensed_tools(features: FeatureSet) -> list[tuple[str, Any]]:
    """Call factories whose licence feature is enabled. Skip every other one."""
    table = features.plugins.get(WIZARD_GROUP) or {}
    tools: list[tuple[str, Any]] = []
    for name in sorted(table):
        factory = table[name]
        feature = declared_feature(factory)
        # A Community feature is always enabled. It does not license a wizard.
        if feature is None or feature in COMMUNITY_FEATURES or feature not in features.enabled:
            continue
        if not callable(factory):
            raise ConfigurationError(f"wizard plugin {name!r} is not callable")
        try:
            tool = factory(options={})
        except ConfigurationError:
            raise
        except Exception as exc:
            raise ConfigurationError(f"wizard plugin {name!r} failed to load: {exc}") from exc
        if not callable(getattr(tool, "validate", None)):
            raise ConfigurationError(f"wizard plugin {name!r} does not validate")
        tools.append((name, tool))
    return tools


def _apply_plugin_answers(
    document: dict[str, Any],
    tools: list[tuple[str, Any]],
    ask: Callable[[str], str],
) -> None:
    for name, tool in tools:
        for question in _questions(tool, name):
            answer = _ask(
                f"{question.prompt}: ",
                ask,
                _with_default(question.default, _parse_plugin_answer),
            )
            _assign(document, question.key, answer)


def _questions(tool: Any, name: str) -> list[WizardQuestion]:
    method = getattr(tool, "questions", None)
    if not callable(method):
        raise ConfigurationError(f"wizard plugin {name!r} does not provide questions")
    found = method()
    if not isinstance(found, list):
        raise ConfigurationError(f"wizard plugin {name!r} questions must be a list")
    checked: list[WizardQuestion] = []
    for item in found:
        if not isinstance(item, WizardQuestion):
            raise ConfigurationError(f"wizard plugin {name!r} question is not a WizardQuestion")
        _check_question(item, name)
        checked.append(item)
    return checked


def _check_question(question: WizardQuestion, name: str) -> None:
    if not _KEY.fullmatch(question.key) or question.key.split(".", 1)[0] in _RESERVED:
        raise ConfigurationError(f"wizard plugin {name!r} has an invalid question key")
    _one_line(question.prompt, f"wizard plugin {name!r} prompt must be one ASCII line")
    if question.default is not None:
        _printable(question.default, f"wizard plugin {name!r} default must be printable ASCII")


def _validate_tools(tools: list[tuple[str, Any]], document: dict[str, Any]) -> None:
    for name, tool in tools:
        try:
            tool.validate(document)
        except (ConfigurationError, ValueError):
            raise
        except Exception as exc:
            raise ConfigurationError(f"wizard plugin {name!r} failed: {exc}") from exc


def _confirmed(ask: Callable[[str], str]) -> bool:
    answer = _read("Overwrite existing config? [y/N]: ", ask).strip().lower()
    return answer in {"y", "yes"}


def _ask(prompt: str, ask: Callable[[str], str], parse: Callable[[str], Any]) -> Any:
    while True:
        raw = _read(prompt, ask)
        try:
            return parse(raw)
        except ValueError as exc:
            _say(_plain(exc), sys.stderr)


def _read(prompt: str, ask: Callable[[str], str]) -> str:
    _one_line(prompt, "wizard prompt must be one ASCII line")
    answer = ask(prompt)
    if not isinstance(answer, str):
        raise ConfigurationError("wizard answer must be text")
    return answer


def _assign(document: dict[str, Any], key: str, value: str) -> None:
    cursor: dict[str, Any] = document
    parts = key.split(".")
    for part in parts[:-1]:
        current = cursor.get(part)
        if current is None:
            current = {}
            cursor[part] = current
        if not isinstance(current, dict):
            raise ConfigurationError(f"wizard key {key} conflicts with an existing value")
        cursor = current
    cursor[parts[-1]] = value


def _load_without_overrides(path: Path) -> None:
    saved = {key: os.environ.pop(key) for key in _OVERRIDES if key in os.environ}
    try:
        load_settings(path)
    finally:
        os.environ.update(saved)


def _with_default(default: str | None, parse: Callable[[str], Any]) -> Callable[[str], Any]:
    def inner(answer: str) -> Any:
        text = answer.strip()
        if text == "" and default is not None:
            text = default
        return parse(text)

    return inner


def _parse_log_path(text: str) -> str:
    _printable(text, "audit log path must be printable ASCII without spaces")
    if not text or any(ch.isspace() for ch in text):
        raise ValueError("audit log path must be printable ASCII without spaces")
    return text


def _parse_allow(text: str) -> list[str]:
    stripped = text.strip()
    if stripped == "":
        return []
    _printable(stripped, "allow list must be printable ASCII")
    parts = [item.strip() for item in stripped.split(",")]
    if any(not item or any(ch.isspace() for ch in item) for item in parts):
        raise ValueError("allow list patterns must be printable ASCII without spaces")
    return parts


def _parse_id(text: str) -> str:
    stripped = text.strip()
    _printable(stripped, "principal id must be printable ASCII without spaces")
    if not stripped or any(ch.isspace() for ch in stripped):
        raise ValueError("principal id must be printable ASCII without spaces")
    return stripped


def _parse_name(text: str) -> str:
    stripped = text.strip()
    _printable(stripped, "principal name must be printable ASCII")
    if not stripped:
        raise ValueError("principal name is required")
    return stripped


def _parse_role(text: str) -> str:
    if text not in ROLES:
        raise ValueError("role must be one of operator, approver, qa, admin")
    return text


def _parse_profile(text: str) -> str:
    if text not in _PROFILES:
        raise ValueError("retention profile must be swiss_glp or minimum")
    return text


def _parse_yes_no(text: str) -> bool:
    lowered = text.lower()
    if lowered in {"y", "yes"}:
        return True
    if lowered in {"n", "no"}:
        return False
    raise ValueError("legal hold must be yes or no")


def _parse_optional_ascii(text: str) -> str:
    _printable(text.strip(), "answer must be printable ASCII")
    return text.strip()


def _parse_plugin_answer(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        raise ValueError("answer is required")
    _printable(stripped, "answer must be printable ASCII")
    return stripped


def _printable(text: str, message: str) -> None:
    try:
        text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(message) from exc
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in text):
        raise ValueError(message)


def _ascii_path(path: Path) -> None:
    try:
        str(path).encode("ascii")
    except UnicodeEncodeError as exc:
        raise ConfigurationError("config path must be printable ASCII") from exc


def _plain(exc: BaseException) -> str:
    text = str(exc)
    try:
        text.encode("ascii")
    except UnicodeEncodeError:
        return "the error text was not ASCII"
    return text


def _say(message: str, stream: Any) -> None:
    try:
        message.encode("ascii")
    except UnicodeEncodeError:
        message = "the message was not ASCII"
    print(message, file=stream)


def _one_line(text: str, message: str) -> None:
    _printable(text, message)
    if not text.strip() or "\n" in text or "\r" in text:
        raise ConfigurationError(message)
