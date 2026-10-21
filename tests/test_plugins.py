"""Config selects storage, signer and reporter plugins. Fail closed otherwise."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_glp_audit_proxy.config import Principal, Retention, Settings, load_settings
from mcp_glp_audit_proxy.errors import ConfigurationError
from mcp_glp_audit_proxy.features import FeatureSet
from mcp_glp_audit_proxy.plugins import load_group
from mcp_glp_audit_proxy.policy import Policy
from mcp_glp_audit_proxy.server import main as server_main
from mcp_glp_audit_proxy.server import build_proxy
from mcp_glp_audit_proxy.signers.unsigned import UnsignedSigner
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore
from mcp_glp_audit_proxy.wiring import AUTH_GROUP, REPORTERS_GROUP, SIGNERS_GROUP, STORAGE_GROUP

from conftest import call_tool


def _plugin(factory: object, feature: str) -> object:
    factory.licence_feature = feature  # type: ignore[attr-defined]
    return factory


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    settings = Settings(
        principal=Principal(id="qa-1", name="Cara QA", role="qa"),
        retention=Retention(),
        policy=Policy(allow=["*"], deny=[], write_tools=["excel__write_cell"]),
        audit_path=tmp_path / "audit.jsonl",
        export_dir=tmp_path / "exports",
        checkpoint_every=0,
        upstreams=[],
    )
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


def _config(tmp_path: Path, **extra: object) -> Path:
    body = {
        "principal": {"id": "qa-1", "name": "Cara QA", "role": "qa"},
        "retention": {"profile": "minimum", "min_months": 6, "years_after_study": 1},
        "policy": {"allow": ["*"], "deny": [], "write_tools": []},
        "audit": {"path": "audit.jsonl", "fail_closed": True},
        "upstreams": [],
    }
    body.update(extra)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def test_client_id_from_config_is_passed_to_the_licence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    original = FeatureSet.load.__func__

    def spy(path: object, **kwargs: object) -> FeatureSet:
        captured["path"] = path
        captured["client_id"] = kwargs.get("client_id")
        return original(FeatureSet, None)

    monkeypatch.setattr(FeatureSet, "load", spy)
    loaded = load_settings(_config(tmp_path, client_id="lab-1", licence_path="licence.json"))
    assert loaded.client_id == "lab-1"
    build_proxy(loaded)
    assert captured["client_id"] == "lab-1"
    assert captured["path"] == loaded.licence_path
    absent = load_settings(_config(tmp_path, client_id=None))
    assert absent.client_id is None
    with pytest.raises(ConfigurationError, match="client_id"):
        load_settings(_config(tmp_path, client_id=""))
    with pytest.raises(ConfigurationError, match="client_id"):
        load_settings(_config(tmp_path, client_id=["lab-1"]))


def test_defaults_build_the_community_plugins(tmp_path: Path) -> None:
    loaded = load_group("mcp_glp_audit_proxy.storage")
    assert loaded["jsonl"].__name__ == "jsonl_store"
    assert loaded["jsonl"].licence_feature == "storage.jsonl"
    assert load_group("mcp_glp_audit_proxy.signers")["unsigned"].__name__ == "unsigned_signer"
    reporters = load_group("mcp_glp_audit_proxy.reporters")
    assert reporters["json"].__name__ == "json_reporter"
    assert reporters["text"].__name__ == "text_reporter"

    proxy = build_proxy(_settings(tmp_path, checkpoint_every=4))
    assert isinstance(proxy.store, JsonlAuditStore)
    assert isinstance(proxy.store.signer, UnsignedSigner)
    assert proxy.store.checkpoint_every == 4
    assert set(proxy.reporters) == {"json", "text"}
    sealed = proxy.startup()
    assert sealed["arguments"]["plugins"] == {
        "auth": "env",
        "reporters": ["json", "text"],
        "signer": "unsigned",
        "storage": "jsonl",
    }
    assert sealed["principal"]["id"] == "qa-1"

    plain = load_settings(_config(tmp_path))
    assert plain.storage == "jsonl"
    assert plain.signer == "unsigned"
    assert plain.reporters == ("json", "text")
    assert plain.plugin_options == {}
    example = load_settings(Path(__file__).resolve().parents[1] / "config.example.json")
    assert example.storage == "jsonl"
    assert example.reporters == ("json", "text")


def test_unknown_unlicensed_and_missing_plugins_refuse_startup(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    flags = FeatureSet.community()
    settings = _settings(tmp_path, storage="nope")
    with pytest.raises(ConfigurationError, match="unknown plugin 'nope'"):
        build_proxy(settings, flags)

    called = {"hit": False}

    def trap(*_args: object, **_kwargs: object) -> None:
        called["hit"] = True
        raise AssertionError("unknown plugin was called")

    flags.plugins[STORAGE_GROUP]["nope"] = trap
    with pytest.raises(ConfigurationError, match="does not declare a licence feature"):
        build_proxy(settings, flags)
    assert called["hit"] is False

    unlicensed = _settings(tmp_path, storage="postgres")
    with pytest.raises(ConfigurationError, match="unknown plugin 'postgres'"):
        build_proxy(unlicensed, flags)

    def undeclared(_settings: object, _signer: object, **_extra: object) -> None:
        raise AssertionError("undeclared plugin was called")

    flags.plugins[STORAGE_GROUP]["postgres"] = undeclared
    with pytest.raises(ConfigurationError, match="does not declare a licence feature"):
        build_proxy(unlicensed, flags)

    def unlicensed_factory(_settings: object, _signer: object, **_extra: object) -> None:
        raise AssertionError("unlicensed plugin was called")

    unlicensed_factory.licence_feature = "storage.sql"
    flags.plugins[STORAGE_GROUP]["postgres"] = unlicensed_factory
    with pytest.raises(ConfigurationError, match="not licensed"):
        build_proxy(unlicensed, flags)

    missing = FeatureSet.community()
    missing.unavailable.append("storage.postgres")
    with pytest.raises(ConfigurationError, match="unknown plugin 'postgres'"):
        build_proxy(_settings(tmp_path, storage="postgres"), missing)

    flags.plugins[SIGNERS_GROUP]["ed25519"] = "not-a-factory"
    flags.enabled.add("signer.ed25519")
    with pytest.raises(ConfigurationError, match="not callable"):
        build_proxy(_settings(tmp_path, signer="ed25519"), flags)

    def boom(_settings: object, **_extra: object) -> None:
        raise RuntimeError("signer init failed")

    boom.licence_feature = "signer.ed25519"
    flags.plugins[SIGNERS_GROUP]["ed25519"] = boom
    with pytest.raises(ConfigurationError, match="failed to load"):
        build_proxy(_settings(tmp_path, signer="ed25519"), flags)

    class Nameless:
        def sign(self, _payload: bytes) -> dict[str, object]:
            return {}

        def verify(self, _payload: bytes, _signature: dict[str, object]) -> bool:
            return False

    flags.plugins[SIGNERS_GROUP]["ed25519"] = _plugin(
        lambda _settings, **_extra: Nameless(), "signer.ed25519"
    )
    with pytest.raises(ConfigurationError, match="no name"):
        build_proxy(_settings(tmp_path, signer="ed25519"), flags)

    flags.plugins[SIGNERS_GROUP]["ed25519"] = _plugin(
        lambda _settings, **_extra: Nameless, "signer.ed25519"
    )
    with pytest.raises(ConfigurationError, match="instance"):
        build_proxy(_settings(tmp_path, signer="ed25519"), flags)

    class HalfStore:
        pass

    flags.enabled.add("storage.postgres")
    flags.plugins[STORAGE_GROUP]["postgres"] = _plugin(
        lambda _settings, _signer, **_extra: HalfStore(), "storage.postgres"
    )
    with pytest.raises(ConfigurationError, match="AuditStore.health"):
        build_proxy(_settings(tmp_path, storage="postgres"), flags)

    flags.plugins[STORAGE_GROUP]["postgres"] = _plugin(
        lambda _settings, _signer, **_extra: HalfStore, "storage.postgres"
    )
    with pytest.raises(ConfigurationError, match="instance"):
        build_proxy(_settings(tmp_path, storage="postgres"), flags)

    class BareReporter:
        name = "pdf"

        def render(self, _document: dict[str, object]) -> bytes:
            return b""

    flags.enabled.add("report.pdf")
    flags.plugins[REPORTERS_GROUP]["pdf"] = _plugin(
        lambda _settings, **_extra: BareReporter(), "report.pdf"
    )
    with pytest.raises(ConfigurationError, match="media_type"):
        build_proxy(_settings(tmp_path, reporters=("pdf",)), flags)

    broken = _config(tmp_path, plugins={"storage": "NotAName"})
    with pytest.raises(ConfigurationError, match="plugin name"):
        load_settings(broken)
    with pytest.raises(ConfigurationError, match="object"):
        load_settings(_config(tmp_path, plugins=["jsonl"]))
    with pytest.raises(ConfigurationError, match="unknown plugins fields"):
        load_settings(_config(tmp_path, plugins={"store": "jsonl"}))
    with pytest.raises(ConfigurationError, match="non-empty"):
        load_settings(_config(tmp_path, plugins={"reporters": []}))
    with pytest.raises(ConfigurationError, match="repeat"):
        load_settings(_config(tmp_path, plugins={"reporters": ["json", "json"]}))

    refused = _config(tmp_path, plugins={"storage": "nope"})
    with pytest.raises(SystemExit) as caught:
        server_main(["--config", str(refused)])
    assert caught.value.code == 1
    assert "unknown plugin" in capsys.readouterr().err


def test_selected_signer_and_reporter_are_used(tmp_path: Path) -> None:
    class FakeSigner:
        name = "ed25519"

        def sign(self, _payload: bytes) -> dict[str, object]:
            return {
                "algorithm": "ed25519",
                "key_id": "test",
                "label": "test",
                "signed": True,
                "value": "abc",
            }

        def verify(self, _payload: bytes, _signature: dict[str, object]) -> bool:
            return True

    class CsvReporter:
        name = "csv"
        media_type = "text/csv"

        def render(self, _document: dict[str, object]) -> bytes:
            return b"seq,status\n"

    flags = FeatureSet.community()
    flags.enabled.add("signer.ed25519")
    flags.enabled.add("report.csv")
    flags.plugins[SIGNERS_GROUP]["ed25519"] = _plugin(
        lambda _settings, **_extra: FakeSigner(), "signer.ed25519"
    )
    flags.plugins[REPORTERS_GROUP]["csv"] = _plugin(
        lambda _settings, **_extra: CsvReporter(), "report.csv"
    )
    settings = _settings(
        tmp_path,
        signer="ed25519",
        reporters=("json", "csv"),
        checkpoint_every=1,
    )
    proxy = build_proxy(settings, flags)
    assert proxy.store.signer.name == "ed25519"
    proxy.startup()
    checkpoints = [
        entry for entry in proxy.store.read_entries() if entry["method"] == "audit/checkpoint"
    ]
    assert checkpoints
    assert checkpoints[0]["result"]["signature"]["algorithm"] == "ed25519"
    assert checkpoints[0]["reason"] == "checkpoint signed by ed25519"
    assert proxy.store.read_entries()[0]["arguments"]["plugins"]["signer"] == "ed25519"

    exported = proxy.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "glp_export_audit",
                "arguments": {"format": "csv", "path": "trail.csv"},
            },
        }
    )
    assert exported is not None
    assert "error" not in exported
    assert (tmp_path / "exports" / "trail.csv").read_bytes() == b"seq,status\n"
    document = exported["result"]["structuredContent"]
    assert document["manifest"]["signer"] == "ed25519"


def test_env_identity_is_the_default_and_other_auth_plugins_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth = load_group("mcp_glp_audit_proxy.auth")
    assert auth["env"].__name__ == "env_identity"
    assert "sso" not in auth
    assert "oauth" not in auth

    monkeypatch.setenv("GLP_PRINCIPAL_ID", "operator-9")
    monkeypatch.setenv("GLP_PRINCIPAL_NAME", "Ada Analyst")
    monkeypatch.setenv("GLP_PRINCIPAL_ROLE", "operator")
    loaded = load_settings(_config(tmp_path))
    proxy = build_proxy(loaded)
    assert proxy.settings.auth == "env"
    assert proxy.settings.principal.id == "operator-9"
    assert proxy.settings.principal.role == "operator"
    assert proxy.startup()["principal"]["id"] == "operator-9"

    flags = FeatureSet.community()
    with pytest.raises(ConfigurationError, match="unknown plugin 'sso'"):
        build_proxy(_settings(tmp_path, auth="sso"), flags)

    missing = FeatureSet.community()
    missing.unavailable.append("auth.sso")
    with pytest.raises(ConfigurationError, match="unknown plugin 'sso'"):
        build_proxy(_settings(tmp_path, auth="sso"), missing)

    class Other:
        name = "sso"

        def resolve(self) -> dict[str, str]:
            return {"id": "from-plugin", "name": "Plugin User", "role": "qa"}

    flags.enabled.add("auth.sso")
    flags.plugins[AUTH_GROUP]["sso"] = _plugin(lambda _settings, **_extra: Other(), "auth.sso")
    replaced = build_proxy(_settings(tmp_path, auth="sso"), flags)
    assert replaced.settings.principal.id == "from-plugin"
    assert replaced.settings.principal.role == "qa"

    class BadRole:
        name = "sso"

        def resolve(self) -> dict[str, str]:
            return {"id": "x", "name": "Y", "role": "root"}

    flags.plugins[AUTH_GROUP]["sso"] = _plugin(lambda _settings, **_extra: BadRole(), "auth.sso")
    with pytest.raises(ConfigurationError, match="role must be"):
        build_proxy(_settings(tmp_path, auth="sso"), flags)

    class NotAPrincipal:
        name = "sso"

        def resolve(self) -> list[str]:
            return ["nope"]

    flags.plugins[AUTH_GROUP]["sso"] = _plugin(
        lambda _settings, **_extra: NotAPrincipal(), "auth.sso"
    )
    with pytest.raises(ConfigurationError, match="did not return a principal"):
        build_proxy(_settings(tmp_path, auth="sso"), flags)

    class Nameless:
        def resolve(self) -> dict[str, str]:
            return {"id": "x", "name": "Y", "role": "qa"}

    flags.plugins[AUTH_GROUP]["sso"] = _plugin(lambda _settings, **_extra: Nameless(), "auth.sso")
    with pytest.raises(ConfigurationError, match="no name"):
        build_proxy(_settings(tmp_path, auth="sso"), flags)

    flags.plugins[AUTH_GROUP]["sso"] = _plugin(lambda _settings, **_extra: Nameless, "auth.sso")
    with pytest.raises(ConfigurationError, match="instance"):
        build_proxy(_settings(tmp_path, auth="sso"), flags)

    with pytest.raises(ConfigurationError, match="unknown plugin 'nope'"):
        build_proxy(_settings(tmp_path, auth="nope"), flags)


def test_plugin_options_are_passed_to_the_factory(tmp_path: Path) -> None:
    seen: dict[str, object] = {}

    class FakeSigner:
        name = "ed25519"

        def sign(self, _payload: bytes) -> dict[str, object]:
            return {"algorithm": "ed25519", "signed": True, "value": "abc"}

        def verify(self, _payload: bytes, _signature: dict[str, object]) -> bool:
            return True

    class CsvReporter:
        name = "csv"
        media_type = "text/csv"

        def render(self, _document: dict[str, object]) -> bytes:
            return b"ok"

    def signer_factory(_settings: object, options: dict[str, object] | None = None) -> FakeSigner:
        seen["signer"] = options
        return FakeSigner()

    signer_factory.licence_feature = "signer.ed25519"

    def store_factory(_settings: object, signer: object, options: dict[str, object] | None = None):
        seen["storage"] = options
        return JsonlAuditStore(_settings.audit_path, signer=signer, checkpoint_every=0)  # type: ignore[attr-defined]

    store_factory.licence_feature = "storage.postgres"

    def reporter_factory(_settings: object, options: dict[str, object] | None = None) -> CsvReporter:
        seen["reporter"] = options
        return CsvReporter()

    reporter_factory.licence_feature = "report.csv"

    flags = FeatureSet.community()
    flags.enabled.update({"storage.postgres", "signer.ed25519", "report.csv"})
    flags.plugins[SIGNERS_GROUP]["ed25519"] = signer_factory
    flags.plugins[STORAGE_GROUP]["postgres"] = store_factory
    flags.plugins[REPORTERS_GROUP]["csv"] = reporter_factory
    loaded = load_settings(
        _config(
            tmp_path,
            plugins={
                "storage": {"name": "postgres", "options": {"dsn": "postgresql://db/lab"}},
                "signer": {"name": "ed25519", "options": {"key_id": "lab-1"}},
                "reporters": {"names": ["csv"], "options": {"csv": {"delimiter": ","}}},
                "auth": {"name": "env", "options": {}},
            },
        )
    )
    assert loaded.plugin_options["storage"] == {"dsn": "postgresql://db/lab"}
    proxy = build_proxy(loaded, flags)
    assert seen["storage"] == {"dsn": "postgresql://db/lab"}
    assert seen["signer"] == {"key_id": "lab-1"}
    assert seen["reporter"] == {"delimiter": ","}
    assert proxy.store.signer.name == "ed25519"

    with pytest.raises(ConfigurationError, match="options must be an object"):
        load_settings(_config(tmp_path, plugins={"storage": {"name": "jsonl", "options": []}}))
    with pytest.raises(ConfigurationError, match="unknown plugins.storage fields"):
        load_settings(_config(tmp_path, plugins={"storage": {"name": "jsonl", "extra": 1}}))
    with pytest.raises(ConfigurationError, match="not selected"):
        load_settings(
            _config(
                tmp_path,
                plugins={"reporters": {"names": ["json"], "options": {"text": {}}}},
            )
        )


def test_text_export_and_unknown_format(build) -> None:
    stack = build()
    call_tool(stack["proxies"]["operator"], "excel__read_cell", {"cell": "A1"})
    exported = call_tool(
        stack["proxies"]["qa"],
        "glp_export_audit",
        {"path": "trail.txt", "format": "text"},
        request_id=11,
    )
    assert exported["result"]["isError"] is False
    body = (stack["path"] / "exports" / "trail.txt").read_bytes()
    assert body.startswith(b"seq=")
    assert b"manifest " in body
    refused = call_tool(
        stack["proxies"]["qa"],
        "glp_export_audit",
        {"format": "pdf"},
        request_id=12,
    )
    assert refused["result"]["isError"] is True
    assert "not configured" in refused["result"]["content"][0]["text"]
