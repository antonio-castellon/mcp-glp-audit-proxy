"""Offline regulatory-report. It does not open the log."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from mcp_glp_audit_proxy.regulatory import HEADER, main


def _write(config_path: Path, **audit) -> None:
    block = {"path": "audit.jsonl", "fail_closed": True, "body_mode": "hash_only"}
    block.update(audit)
    config_path.write_text(
        json.dumps(
            {
                "principal": {"id": "operator-1", "name": "Ada Analyst", "role": "operator"},
                "retention": {
                    "profile": "swiss_glp",
                    "min_months": 6,
                    "years_after_study": 10,
                    "legal_hold": False,
                },
                "policy": {
                    "allow": ["excel__*"],
                    "deny": [],
                    "write_tools": ["excel__write_cell"],
                    "require_reason_for_writes": True,
                    "require_approval_for_writes": False,
                },
                "audit": block,
                "require_ntp": False,
            }
        ),
        encoding="utf-8",
    )


def test_report_header_and_statuses(tmp_path: Path, capsys) -> None:
    config = tmp_path / "config.json"
    _write(config)
    assert main(["--config", str(config), "--format", "md"]) == 0
    text = capsys.readouterr().out
    assert HEADER in text
    assert "supported by current config" in text
    assert "not supported by current config" in text
    text.encode("ascii")


def test_reason_gap_names_the_parameter(tmp_path: Path, capsys) -> None:
    config = tmp_path / "config.json"
    _write(config)
    loaded = json.loads(config.read_text(encoding="utf-8"))
    loaded["policy"]["require_reason_for_writes"] = False
    config.write_text(json.dumps(loaded), encoding="utf-8")
    assert main(["--config", str(config)]) == 0
    text = capsys.readouterr().out
    for label in ("21 CFR Part 11", "Annex 11", "OECD"):
        assert label in text
    assert "policy.require_reason_for_writes" in text
    assert "| false |" in text
    assert "| true |" in text
    assert "reason" in text


def test_glp_retention_and_agit(tmp_path: Path, capsys) -> None:
    config = tmp_path / "config.json"
    _write(config)
    assert main(["--config", str(config), "--applies", "glp"]) == 0
    text = capsys.readouterr().out
    assert "OGLP" in text or "Swiss" in text
    assert "120" in text
    assert "not met" in text
    assert "AGIT Archiving" in text
    assert "customer procedure" in text
    loaded = json.loads(config.read_text(encoding="utf-8"))
    loaded["audit"]["fail_closed"] = False
    config.write_text(json.dumps(loaded), encoding="utf-8")
    assert main(["--config", str(config), "--applies", "glp"]) == 0
    follow = capsys.readouterr().out
    assert "AGIT Acquisition" in follow
    assert "audit.fail_closed" in follow
    assert "not met" in follow


def test_shared_bearer_and_body_tradeoff(tmp_path: Path, capsys) -> None:
    config = tmp_path / "config.json"
    _write(config)
    loaded = json.loads(config.read_text(encoding="utf-8"))
    loaded["listen"] = {
        "bind": "127.0.0.1",
        "port": 0,
        "cert_file": "cert.pem",
        "key_file": "key.pem",
        "identity": {
            "mode": "bearer",
            "bearer_token_file": "token",
            "bearer_principal": {"id": "gateway", "name": "Gateway", "role": "operator"},
        },
    }
    config.write_text(json.dumps(loaded), encoding="utf-8")
    assert main(["--config", str(config)]) == 0
    text = capsys.readouterr().out
    assert "shared-bearer" in text
    assert "identity.attribution" in text
    assert "not supported by current config" in text
    assert "hash_only" in text
    assert "full" in text
    assert "GDPR" in text
    assert "OECD" in text


def test_offline_unwritable_log_directory(tmp_path: Path, capsys) -> None:
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    config = tmp_path / "config.json"
    _write(config, path=str(blocked / "audit.jsonl"))
    if os.name != "nt":
        blocked.chmod(0)
    try:
        assert main(["--config", str(config), "--format", "json", "--out", str(tmp_path / "report.json")]) == 0
    finally:
        if os.name != "nt":
            blocked.chmod(stat.S_IRWXU)
    document = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    raw = config.read_bytes()
    assert document["config_sha256"] == hashlib.sha256(raw).hexdigest()
    assert document["header"] == HEADER
    assert document["mapping_version"]
    assert not (blocked / "audit.jsonl").exists()
    capsys.readouterr()


def test_banned_words_invalid_config_and_fail_on_gap(tmp_path: Path, capsys) -> None:
    root = Path(__file__).resolve().parents[1]
    mapping = (root / "src" / "mcp_glp_audit_proxy" / "data" / "regulatory_map.json").read_text(encoding="utf-8")
    lowered = mapping.lower()
    for word in ("compliant", "certified", "compliance"):
        assert word not in lowered
    config = tmp_path / "config.json"
    _write(config)
    assert main(["--config", str(config), "--format", "md", "--fail-on-gap"]) == 1
    text = capsys.readouterr().out
    text.encode("ascii")
    for word in ("compliant", "certified", "compliance"):
        assert word not in text.lower()
    config.write_text("{", encoding="utf-8")
    assert main(["--config", str(config)]) == 2
    import importlib.util

    module_path = Path(__file__).resolve().parents[1] / "scripts" / "gen_coverage.py"
    spec = importlib.util.spec_from_file_location("gen_coverage", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    assert module.drift() == []
