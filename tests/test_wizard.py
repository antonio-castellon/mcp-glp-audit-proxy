"""init writes a config the loader accepts. config check reports plain errors."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_glp_audit_proxy.config import load_settings
from mcp_glp_audit_proxy.errors import ConfigurationError
from mcp_glp_audit_proxy.features import COMMUNITY_FEATURES, WIZARD_GROUP, FeatureSet
from mcp_glp_audit_proxy.wizard import (
    WizardQuestion,
    check_config,
    config_main,
    init_main,
    run_init,
)

ROOT = Path(__file__).resolve().parents[1]
_GLP = (
    "GLP_CONFIG",
    "GLP_PRINCIPAL_ID",
    "GLP_PRINCIPAL_NAME",
    "GLP_PRINCIPAL_ROLE",
    "GLP_AUDIT_PATH",
    "GLP_FAIL_CLOSED",
    "GLP_LICENCE_PATH",
    "GLP_REQUIRE_NTP",
)
_ANSWERS = [
    "./data/audit.jsonl",
    "excel__*,lims__read",
    "operator-1",
    "Ada Analyst",
    "operator",
    "swiss_glp",
    "no",
]


def _script(answers: list[str]):
    prompts: list[str] = []
    pool = list(answers)

    def ask(prompt: str) -> str:
        prompts.append(prompt)
        prompt.encode("ascii")
        if not pool:
            raise EOFError
        return pool.pop(0)

    return ask, prompts


def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _GLP:
        monkeypatch.delenv(key, raising=False)


def _flags(factory: object, *, enabled: bool) -> FeatureSet:
    features = set(COMMUNITY_FEATURES)
    if enabled:
        features.add("storage.sql")
    return FeatureSet(enabled=features, plugins={WIZARD_GROUP: {"sql": factory}})


def test_init_writes_a_config_the_loader_accepts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    dest = tmp_path / "config.json"
    ask, prompts = _script(_ANSWERS)
    assert run_init(dest, input_fn=ask) == 0
    assert prompts
    for prompt in prompts:
        prompt.encode("ascii")
    text = dest.read_text(encoding="ascii")
    text.encode("ascii")
    raw = json.loads(text)
    assert raw["audit"]["path"] == "./data/audit.jsonl"
    assert raw["policy"]["allow"] == ["excel__*", "lims__read"]
    assert raw["principal"] == {"id": "operator-1", "name": "Ada Analyst", "role": "operator"}
    assert raw["retention"]["profile"] == "swiss_glp"
    assert raw["retention"]["legal_hold"] is False
    assert raw["retention"]["min_months"] == 6
    assert raw["retention"]["years_after_study"] == 10
    settings = load_settings(dest)
    assert settings.audit_path == (tmp_path / "data" / "audit.jsonl").resolve()
    assert settings.policy.allow == ["excel__*", "lims__read"]
    assert settings.principal.role == "operator"
    assert settings.retention.profile == "swiss_glp"
    assert settings.retention.legal_hold is False


def test_init_records_minimum_profile_and_legal_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear(monkeypatch)
    answers = [
        "",
        "",
        "qa-1",
        "Cara QA",
        "",
        "minimum",
        "yes",
    ]
    dest = tmp_path / "config.json"
    assert run_init(dest, input_fn=_script(answers)[0]) == 0
    raw = json.loads(dest.read_text(encoding="ascii"))
    assert raw["audit"]["path"] == "./data/audit.jsonl"
    assert raw["policy"]["allow"] == []
    assert raw["principal"]["role"] == "operator"
    assert raw["retention"]["profile"] == "minimum"
    assert raw["retention"]["legal_hold"] is True
    settings = load_settings(dest)
    assert settings.retention.profile == "minimum"
    assert settings.retention.legal_hold is True


def test_init_rejects_a_bad_answer_then_accepts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear(monkeypatch)
    answers = [
        "not a path",
        "./data/audit.jsonl",
        "excel__*",
        "",
        "operator-1",
        "caf\u00e9",
        "Ada Analyst",
        "boss",
        "qa",
        "forever",
        "swiss_glp",
        "maybe",
        "no",
    ]
    dest = tmp_path / "config.json"
    assert run_init(dest, input_fn=_script(answers)[0]) == 0
    err = capsys.readouterr().err
    err.encode("ascii")
    assert "audit log path must be printable ASCII without spaces" in err
    assert "principal id must be printable ASCII without spaces" in err
    assert "principal name must be printable ASCII" in err
    assert "role must be one of operator, approver, qa, admin" in err
    assert "retention profile must be swiss_glp or minimum" in err
    assert "legal hold must be yes or no" in err
    raw = json.loads(dest.read_text(encoding="ascii"))
    assert raw["principal"] == {"id": "operator-1", "name": "Ada Analyst", "role": "qa"}


def test_init_refuses_to_overwrite_without_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear(monkeypatch)
    dest = tmp_path / "config.json"
    dest.write_text("KEEP\n", encoding="ascii")
    assert run_init(dest, input_fn=_script(_ANSWERS + ["n"])[0]) == 1
    assert dest.read_text(encoding="ascii") == "KEEP\n"
    err = capsys.readouterr().err
    assert "not overwritten" in err
    assert list(tmp_path.glob(".config.json.*.tmp")) == []
    assert run_init(dest, input_fn=_script(_ANSWERS + ["yes"])[0]) == 0
    assert dest.read_text(encoding="ascii") != "KEEP\n"
    assert load_settings(dest).principal.id == "operator-1"


def test_config_check_reports_a_plain_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear(monkeypatch)
    missing = tmp_path / "missing.json"
    assert check_config(missing) == 1
    err = capsys.readouterr().err
    assert "config check failed:" in err
    assert "config file not found" in err
    assert "Traceback" not in err

    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="ascii")
    assert check_config(broken) == 1
    assert "config is not JSON" in capsys.readouterr().err

    role = tmp_path / "role.json"
    role.write_text(
        json.dumps(
            {
                "principal": {"id": "operator-1", "name": "Ada Analyst", "role": "boss"},
                "audit": {"path": "./data/audit.jsonl"},
            }
        ),
        encoding="ascii",
    )
    assert check_config(role) == 1
    assert "role must be one of" in capsys.readouterr().err

    ask, _prompts = _script(_ANSWERS)
    good = tmp_path / "config.json"
    assert run_init(good, input_fn=ask) == 0
    assert check_config(good) == 0
    assert "config check ok" in capsys.readouterr().out


def test_unlicensed_wizard_plugin_is_not_called(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(options: object = None) -> None:
        del options
        raise AssertionError("unlicensed wizard factory was called")

    boom.licence_feature = "storage.sql"  # type: ignore[attr-defined]

    def community_feature(options: object = None) -> None:
        del options
        raise AssertionError("community feature ran the wizard factory")

    community_feature.licence_feature = "storage.jsonl"  # type: ignore[attr-defined]
    mixed = FeatureSet(
        enabled=set(COMMUNITY_FEATURES),
        plugins={WIZARD_GROUP: {"sql": boom, "jsonl": community_feature}},
    )
    dest = tmp_path / "config.json"
    ask, prompts = _script(_ANSWERS)
    assert run_init(dest, input_fn=ask, features=mixed) == 0
    assert "Licence path" not in "".join(prompts)
    assert load_settings(dest).principal.id == "operator-1"

    from mcp_glp_audit_proxy import features as features_mod

    real = features_mod.load_group

    def fake(group: str) -> dict:
        found = dict(real(group))
        if group == WIZARD_GROUP:
            found["sql"] = boom
        return found

    monkeypatch.setattr(features_mod, "load_group", fake)
    other = tmp_path / "other.json"
    ask_again, prompts_again = _script(["", ""] + _ANSWERS)
    assert run_init(other, input_fn=ask_again) == 0
    assert prompts_again[0].startswith("Licence path")
    assert "lab_site" not in other.read_text(encoding="ascii")
    assert check_config(other) == 0


def test_licensed_plugin_question_is_written_and_checked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Tool:
        def __init__(self) -> None:
            self.questions_called = 0

        def questions(self) -> list[WizardQuestion]:
            self.questions_called += 1
            return [WizardQuestion("lab_site", "Lab site")]

        def validate(self, document: dict) -> None:
            if document.get("lab_site") != "basel":
                raise ConfigurationError("lab site is required")

    tool = Tool()

    def factory(options: object = None) -> Tool:
        del options
        factory.calls += 1
        return tool

    factory.calls = 0
    factory.licence_feature = "storage.sql"  # type: ignore[attr-defined]
    flags = _flags(factory, enabled=True)
    dest = tmp_path / "config.json"
    ask, prompts = _script(_ANSWERS + ["basel"])
    assert run_init(dest, input_fn=ask, features=flags) == 0
    assert factory.calls == 1
    assert tool.questions_called == 1
    assert any(prompt.startswith("Lab site:") for prompt in prompts)
    assert json.loads(dest.read_text(encoding="ascii"))["lab_site"] == "basel"
    assert load_settings(dest).principal.id == "operator-1"

    bare = tmp_path / "bare.json"
    body = json.loads(dest.read_text(encoding="ascii"))
    del body["lab_site"]
    bare.write_text(json.dumps(body), encoding="ascii")
    factory.calls = 0
    tool.questions_called = 0
    assert check_config(bare, features=flags) == 1
    assert "lab site is required" in capsys.readouterr().err
    assert "Traceback" not in capsys.readouterr().err
    assert factory.calls == 1
    assert tool.questions_called == 0
    assert check_config(dest, features=flags) == 0
    assert tool.questions_called == 0


def test_plugin_cannot_replace_builtin_fields(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    class Tool:
        def questions(self) -> list[WizardQuestion]:
            return [WizardQuestion("audit.path", "Log")]

        def validate(self, document: dict) -> None:
            del document

    def factory(options: object = None) -> Tool:
        del options
        return Tool()

    factory.licence_feature = "storage.sql"  # type: ignore[attr-defined]
    dest = tmp_path / "config.json"
    assert run_init(dest, input_fn=_script(_ANSWERS)[0], features=_flags(factory, enabled=True)) == 1
    assert not dest.exists()
    assert "invalid question key" in capsys.readouterr().err


def test_wizard_does_not_open_a_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("wizard opened a socket")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    dest = tmp_path / "config.json"
    assert run_init(dest, input_fn=_script(_ANSWERS)[0]) == 0
    assert check_config(dest) == 0


def test_init_ignores_principal_env_overrides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GLP_PRINCIPAL_ROLE", "nope")
    dest = tmp_path / "config.json"
    assert run_init(dest, input_fn=_script(_ANSWERS)[0]) == 0
    assert json.loads(dest.read_text(encoding="ascii"))["principal"]["role"] == "operator"
    assert check_config(dest) == 1
    assert "role must be one of" in capsys.readouterr().err


def test_usage_and_eof(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert init_main(["--help"]) == 0
    assert "mcp-glp-audit-proxy init" in capsys.readouterr().out
    assert init_main(["--port"]) == 2
    assert config_main([]) == 2
    assert config_main(["check", "--port"]) == 2
    assert "config check" in capsys.readouterr().err
    dest = tmp_path / "config.json"
    assert run_init(dest, input_fn=_script([])[0]) == 1
    assert not dest.exists()
    assert "input ended" in capsys.readouterr().err
    missing_dir = tmp_path / "missing" / "config.json"
    assert run_init(missing_dir, input_fn=_script(_ANSWERS)[0]) == 1
    assert "config directory does not exist" in capsys.readouterr().err


def test_cli_init_and_config_check(tmp_path: Path) -> None:
    env = os.environ.copy()
    for key in _GLP:
        env.pop(key, None)
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    dest = tmp_path / "config.json"
    completed = subprocess.run(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "init", str(dest)],
        input="\n".join(_ANSWERS) + "\n",
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env=env,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    completed.stdout.encode("ascii")
    completed.stderr.encode("ascii")
    assert load_settings(dest).policy.allow == ["excel__*", "lims__read"]
    check = subprocess.run(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "config", "check", str(dest)],
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env=env,
        check=False,
    )
    assert check.returncode == 0, check.stderr
    assert check.stdout.strip() == "config check ok"
    bad = subprocess.run(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "config", "check", str(tmp_path / "nope.json")],
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env=env,
        check=False,
    )
    assert bad.returncode == 1
    assert "config file not found" in bad.stderr
    assert "Traceback" not in bad.stderr
    usage = subprocess.run(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "config"],
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env=env,
        check=False,
    )
    assert usage.returncode == 2
    help_run = subprocess.run(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "--help"],
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env=env,
        check=False,
    )
    assert help_run.returncode == 0, help_run.stderr
    assert "--config" in help_run.stdout
    again = subprocess.run(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "init", str(dest)],
        input="\n".join(_ANSWERS + ["n"]) + "\n",
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env=env,
        check=False,
    )
    assert again.returncode == 1
    assert "not overwritten" in again.stderr
    assert load_settings(dest).principal.id == "operator-1"


def test_readme_documents_the_wizard() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme.encode("ascii")
    assert "## Configure" in readme
    assert "## Roadmap" in readme
    assert "mcp-glp-audit-proxy init" in readme
    assert "mcp-glp-audit-proxy config check" in readme
    assert "mcp_glp_audit_proxy.wizard" in readme
    plugins = (ROOT / "docs" / "PLUGINS.md").read_text(encoding="utf-8")
    plugins.encode("ascii")
    assert "mcp_glp_audit_proxy.wizard" in plugins
    assert "An unlicensed factory is not called" in plugins
