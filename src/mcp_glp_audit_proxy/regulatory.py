"""Offline regulatory configuration report.

Reads the config and the packaged map. Does not open the log, a socket,
an upstream, a TLS key, or a licence server, and does not start the proxy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

from .config import Settings, load_settings
from .errors import ConfigurationError

HEADER = (
    "This report reads the configuration only. It does not assess the customer's "
    "system, SOPs or validation. The customer's QA makes the final assessment."
)
_BANNED = ("compliant", "certified", "compliance")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-glp-audit-proxy regulatory-report")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--format", choices=("md", "json"), default="md")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--applies", default="glp,part11,ai_high_risk,gdpr_bodies")
    parser.add_argument("--fail-on-gap", action="store_true")
    args = parser.parse_args(argv)
    applies = tuple(part.strip() for part in str(args.applies).split(",") if part.strip())
    try:
        raw = args.config.read_bytes()
        settings = load_settings(args.config)
        mapping = load_map()
        document = build_report(
            settings,
            mapping,
            config_sha256=hashlib.sha256(raw).hexdigest(),
            applies=applies,
            profile=args.profile or settings.retention.profile,
        )
    except ConfigurationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    text = render_markdown(document) if args.format == "md" else _dumps(document)
    lowered = text.lower()
    if any(word in lowered for word in _BANNED):
        print("report text uses a banned word", file=sys.stderr)
        return 2
    if args.format == "md" and any(ord(char) > 127 for char in text):
        print("report is not ASCII", file=sys.stderr)
        return 2
    if args.out is None:
        sys.stdout.write(text)
    else:
        args.out.write_text(text, encoding="ascii" if args.format == "md" else "utf-8")
    if args.fail_on_gap and any(row["status"].startswith("not supported") for row in document["rows"]):
        return 1
    return 0


def load_map() -> dict[str, Any]:
    raw = files("mcp_glp_audit_proxy.data").joinpath("regulatory_map.json").read_text(encoding="utf-8")
    loaded = json.loads(raw)
    if not isinstance(loaded, dict) or not isinstance(loaded.get("entries"), list):
        raise ConfigurationError("regulatory map is invalid")
    return loaded


def build_report(
    settings: Settings,
    mapping: dict[str, Any],
    *,
    config_sha256: str,
    applies: tuple[str, ...],
    profile: str,
) -> dict[str, Any]:
    selected = set(applies)
    rows: list[dict[str, Any]] = []
    for entry in mapping["entries"]:
        rows.extend(_rows_for(entry, settings, selected))
    return {
        "applies": list(applies),
        "config_sha256": config_sha256,
        "header": HEADER,
        "mapping_version": mapping.get("mapping_version"),
        "profile": profile,
        "rows": rows,
    }


def render_markdown(document: dict[str, Any]) -> str:
    lines = [
        "# Regulatory configuration report",
        "",
        document["header"],
        "",
        f"mapping_version: {document['mapping_version']}",
        f"config_sha256: {document['config_sha256']}",
        f"profile: {document['profile']}",
        f"applies: {', '.join(document['applies'])}",
        "",
    ]
    current = None
    for row in document["rows"]:
        if row["group"] != current:
            current = row["group"]
            lines.extend(
                [
                    f"## {current}",
                    "",
                    "| instrument | clause | status | parameter | current | expected | consequence |",
                    "| --- | --- | --- | --- | --- | --- | --- |",
                ]
            )
        lines.append(
            "| {instrument} | {clause} | {status} | {parameter} | {current} | {expected} | {consequence} |".format(
                **{key: _cell(row[key]) for key in (
                    "instrument",
                    "clause",
                    "status",
                    "parameter",
                    "current",
                    "expected",
                    "consequence",
                )}
            )
        )
    lines.append("")
    return "\n".join(lines)


def _rows_for(entry: dict[str, Any], settings: Settings, selected: set[str]) -> list[dict[str, Any]]:
    base = {
        "clause": entry.get("clause") or "",
        "group": entry.get("group") or "Other",
        "id": entry.get("id"),
        "instrument": entry.get("instrument") or "",
    }
    applies_when = str(entry.get("applies_when") or "always")
    if applies_when != "always" and applies_when not in selected:
        return [
            {
                **base,
                "consequence": "",
                "current": "",
                "expected": "",
                "parameter": "",
                "status": "not applicable (applies_when not set)",
            }
        ]
    edition = str(entry.get("edition") or "")
    if _community_unavailable(edition):
        return [
            {
                **base,
                "consequence": "This edition does not include the control.",
                "current": "",
                "expected": "",
                "parameter": "",
                "status": "not available in Community",
            }
        ]
    checks = entry.get("checks") or []
    if not checks:
        return [
            {
                **base,
                "consequence": str(entry.get("procedural") or "customer procedure, see ARCHIVING.md"),
                "current": "",
                "expected": "",
                "parameter": "",
                "status": "procedural (customer procedure)",
            }
        ]
    rendered = []
    for check in checks:
        rendered.append({**base, **_evaluate(check, settings)})
    return rendered


def _evaluate(check: dict[str, Any], settings: Settings) -> dict[str, Any]:
    param = str(check.get("param") or "")
    expect = check.get("expect") or {}
    consequence = str(check.get("consequence_if_changed") or "")
    current = _current(settings, param)
    if expect.get("tradeoff") is True:
        return _result(param, current, "hash_only or redacted, and full or redacted", consequence, True, tradeoff=True)
    if expect.get("optional") is True:
        return {
            "consequence": consequence or "Not required by any cited clause.",
            "current": _show(current),
            "expected": "optional",
            "parameter": param,
            "status": "procedural (customer procedure)",
        }
    if expect.get("recommended") is True:
        matched = current is True
        return _result(param, current, "true (recommended)", consequence, matched, recommended=True)
    if expect.get("available") is True:
        return _result(param, current, "available", consequence, True)
    if "equals" in expect:
        matched = current == expect["equals"]
        return _result(param, current, expect["equals"], consequence, matched)
    if "min" in expect:
        try:
            matched = int(current) >= int(expect["min"])
        except (TypeError, ValueError):
            matched = False
        return _result(param, current, f">= {expect['min']}", consequence, matched)
    if "in" in expect:
        matched = current in set(expect["in"])
        return _result(param, current, " or ".join(str(item) for item in expect["in"]), consequence, matched)
    return _result(param, current, "", consequence, False)


def _result(
    param: str,
    current: Any,
    expected: Any,
    consequence: str,
    matched: bool,
    *,
    tradeoff: bool = False,
    recommended: bool = False,
) -> dict[str, Any]:
    if tradeoff:
        status = "supported by current config"
    elif recommended and not matched:
        status = "procedural (customer procedure)"
    elif matched:
        status = "supported by current config"
    else:
        status = "not supported by current config (not met)"
    return {
        "consequence": consequence,
        "current": _show(current),
        "expected": _show(expected),
        "parameter": param,
        "status": status,
    }


def _current(settings: Settings, param: str) -> Any:
    if param == "policy.require_reason_for_writes":
        return settings.policy.require_reason_for_writes
    if param == "policy.require_approval_for_writes":
        return settings.policy.require_approval_for_writes
    if param == "audit.fail_closed":
        return settings.fail_closed
    if param == "audit.body_mode":
        return settings.body_mode
    if param == "retention.min_months":
        return settings.retention.min_months
    if param == "retention.legal_hold":
        return "available"
    if param == "require_ntp":
        return settings.require_ntp
    if param == "identity.attribution":
        return _identity(settings)
    if param == "listen.tls":
        return "tls1.3" if settings.listen is not None else "tls1.3-when-listen-is-set"
    raise ConfigurationError(f"unknown regulatory parameter {param}")


def _identity(settings: Settings) -> str:
    listen = settings.listen
    if listen is None:
        return "stdio-principal"
    mode = listen.identity.mode
    if mode == "mtls" or listen.identity.end_user_header:
        return "per-person"
    if mode == "bearer":
        return "shared-bearer"
    return mode


def _community_unavailable(edition: str) -> bool:
    lowered = edition.lower()
    if lowered.startswith("community"):
        return False
    if "community" in lowered and "out of scope" not in lowered:
        return False
    return True


def _show(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _cell(value: Any) -> str:
    return str(value).replace("|", "/").replace("\n", " ")


def _dumps(document: dict[str, Any]) -> str:
    return json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
