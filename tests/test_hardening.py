"""External head pin, private file modes, and the signer verify hook."""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

from mcp_glp_audit_proxy.anchor import write_head
from mcp_glp_audit_proxy.canonical import canonicalize
from mcp_glp_audit_proxy.chain import verify_bytes
from mcp_glp_audit_proxy.checkpoints import check_log, licensed_signer
from mcp_glp_audit_proxy.cli import main as verify_main
from mcp_glp_audit_proxy.features import COMMUNITY_FEATURES, FeatureSet
from mcp_glp_audit_proxy.signers.unsigned import unsigned_signer
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore
from mcp_glp_audit_proxy.wiring import SIGNERS_GROUP
from mcp_glp_audit_proxy.wizard import run_init

from test_faults import _event, _fill
from test_wizard import _ANSWERS, _clear, _script


def test_expect_head_accepts_the_tip_and_rejects_a_different_one(tmp_path: Path, capsys) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path, 4)
    assert verify_main([str(path), "--print-head"]) == 0
    printed = capsys.readouterr().out.strip().splitlines()[-1]
    seq, _, digest = printed.removeprefix("seq=").partition(" entry_hash=")
    assert verify_main([str(path), "--expect-head", f"{seq}:{digest}"]) == 0
    assert "chain ok" in capsys.readouterr().err

    assert verify_main([str(path), "--expect-head", f"{seq}:{'ab' * 32}"]) == 1
    err = capsys.readouterr().err
    assert "does not match expected" in err
    assert "chain ok" not in err

    assert verify_main([str(path), "--expect-head", f"{int(seq) - 1}:{digest}"]) == 1
    assert "does not match expected" in capsys.readouterr().err


def test_expect_head_file_reads_either_form_and_catches_a_moved_tip(tmp_path: Path, capsys) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path, 4)
    assert verify_main([str(path), "--print-head"]) == 0
    printed = capsys.readouterr().out.strip().splitlines()[-1]
    seq, _, digest = printed.removeprefix("seq=").partition(" entry_hash=")
    pair = tmp_path / "pair.txt"
    pair.write_text(f"{seq}:{digest}\n", encoding="ascii")
    copied = tmp_path / "copied.txt"
    copied.write_text(printed + "\n", encoding="ascii")
    assert verify_main([str(path), "--expect-head-file", str(pair)]) == 0
    assert verify_main([str(path), "--expect-head-file", str(copied)]) == 0
    assert verify_main(
        [str(path), "--expect-head", f"{seq}:{digest}", "--expect-head-file", str(copied)]
    ) == 0
    capsys.readouterr()

    other = tmp_path / "other.txt"
    other.write_text(f"1:{'cd' * 32}\n", encoding="ascii")
    assert verify_main(
        [str(path), "--expect-head", f"{seq}:{digest}", "--expect-head-file", str(other)]
    ) == 2
    assert "do not match" in capsys.readouterr().err

    lines = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join(lines[:2]))
    shortened = verify_bytes(path.read_bytes())
    tip = shortened.entries[-1]
    write_head(path, int(tip["seq"]), str(tip["entry_hash"]))
    assert verify_main([str(path), "--expect-head-file", str(copied)]) == 1
    assert "does not match expected" in capsys.readouterr().err


def test_expect_head_rejects_a_bad_value(tmp_path: Path, capsys) -> None:
    path = tmp_path / "audit.jsonl"
    _fill(path, 1)
    assert verify_main([str(path), "--expect-head", "nope"]) == 2
    assert "expected head" in capsys.readouterr().err
    missing = tmp_path / "missing.txt"
    assert verify_main([str(path), "--expect-head-file", str(missing)]) == 2
    assert "missing" in capsys.readouterr().err


def test_existing_log_and_head_are_set_to_0600(tmp_path: Path, caplog) -> None:
    caplog.set_level(logging.WARNING, logger="mcp_glp_audit_proxy.technical")
    path = tmp_path / "audit.jsonl"
    store = JsonlAuditStore(path, checkpoint_every=0)
    store.append_event(_event(1))
    head = path.with_name(path.name + ".head")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(head.stat().st_mode) == 0o600
    assert caplog.records == []
    os.chmod(path, 0o644)
    os.chmod(head, 0o644)
    store.append_event(_event(2))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(head.stat().st_mode) == 0o600
    assert any("0600" in record.message for record in caplog.records)


def test_owner_read_only_log_is_repaired(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    store = JsonlAuditStore(path, checkpoint_every=0)
    store.append_event(_event(1))
    os.chmod(path, 0o444)
    store.append_event(_event(2))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert len(store.read_entries()) == 2


def test_new_log_directory_is_0700_and_an_existing_one_is_left(tmp_path: Path) -> None:
    created = tmp_path / "fresh"
    JsonlAuditStore(created / "audit.jsonl", checkpoint_every=0).append_event(_event(1))
    assert stat.S_IMODE(created.stat().st_mode) == 0o700

    existing = tmp_path / "kept"
    existing.mkdir(mode=0o755)
    os.chmod(existing, 0o755)
    JsonlAuditStore(existing / "audit.jsonl", checkpoint_every=0).append_event(_event(1))
    assert stat.S_IMODE(existing.stat().st_mode) == 0o755


def test_init_writes_the_config_as_0600(tmp_path: Path, monkeypatch) -> None:
    _clear(monkeypatch)
    previous = os.umask(0o000)
    try:
        dest = tmp_path / "config.json"
        ask, _prompts = _script(list(_ANSWERS))
        assert run_init(dest, input_fn=ask, features=FeatureSet.community()) == 0
        assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    finally:
        os.umask(previous)


def test_pubkey_requires_one_licensed_signer(tmp_path: Path, capsys, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    JsonlAuditStore(path, checkpoint_every=1).append_event(_event(1))
    key = tmp_path / "key.pub"
    key.write_bytes(b"pin")

    def boom(*_args, **_kwargs):
        raise AssertionError("unsigned verify must not run")

    monkeypatch.setattr("mcp_glp_audit_proxy.signers.unsigned.UnsignedSigner.verify", boom)
    assert verify_main([str(path), "--pubkey", str(key)]) == 1
    err = capsys.readouterr().err
    assert "checkpoint signature invalid" in err
    assert "no licensed signer plugin" in err
    assert "chain ok" not in err

    assert verify_main([str(path), "--pubkey", str(tmp_path / "absent.pub")]) == 2
    assert "missing" in capsys.readouterr().err
    empty = tmp_path / "empty.pub"
    empty.write_bytes(b"")
    assert verify_main([str(path), "--pubkey", str(empty)]) == 2
    assert "empty" in capsys.readouterr().err


def test_pubkey_loads_an_explicit_licence(tmp_path: Path, capsys, monkeypatch) -> None:
    seen: list[tuple[Path, str | None]] = []

    class Local:
        def sign(self, _payload: bytes) -> dict[str, object]:
            return {"algorithm": "ed25519", "key_id": "k", "signed": True, "value": "ok"}

        def verify(self, _payload: bytes, _signature: dict[str, object], public_key: bytes | None = None) -> bool:
            return public_key == b"pin"

    def factory(_settings, options=None):
        assert options == {}
        return Local()

    factory.licence_feature = "signer.ed25519"  # type: ignore[attr-defined]
    flags = FeatureSet(
        enabled=set(COMMUNITY_FEATURES) | {"signer.ed25519"},
        plugins={SIGNERS_GROUP: {"ed25519": factory}},
    )

    def load(got, **kwargs):
        if not Path(got).is_file():
            raise FileNotFoundError(got)
        seen.append((Path(got), kwargs.get("client_id")))
        return flags

    monkeypatch.setattr("mcp_glp_audit_proxy.cli.FeatureSet.load", load)
    path = tmp_path / "audit.jsonl"
    JsonlAuditStore(path, signer=Local(), checkpoint_every=1).append_event(_event(1))
    key = tmp_path / "key.pub"
    key.write_bytes(b"pin")
    licence = tmp_path / "licence.json"
    licence.write_text("{}", encoding="utf-8")
    other = tmp_path / "other.json"
    other.write_text("{}", encoding="utf-8")

    assert verify_main([str(path), "--licence", str(other)]) == 0
    assert seen == []
    assert "chain ok" in capsys.readouterr().err

    monkeypatch.setenv("GLP_LICENCE_PATH", str(other))
    monkeypatch.setenv("GLP_CLIENT_ID", "from-env")
    assert (
        verify_main(
            [str(path), "--pubkey", str(key), "--licence", str(licence), "--client-id", "lab"]
        )
        == 0
    )
    assert seen == [(licence, "lab")]
    seen.clear()
    assert verify_main([str(path), "--pubkey", str(key)]) == 0
    assert seen == [(other, "from-env")]
    assert verify_main([str(path), "--pubkey", str(key), "--licence", str(tmp_path / "missing.json")]) == 2


def test_pubkey_calls_the_licensed_signer_with_the_pinned_key(tmp_path: Path, capsys, monkeypatch) -> None:
    seen: dict[str, object] = {}

    class Local:
        name = "ed25519"

        def sign(self, payload: bytes) -> dict[str, object]:
            seen["signed"] = payload
            return {
                "algorithm": "ed25519",
                "key_id": "k",
                "label": "ed25519",
                "signed": True,
                "value": "ok",
            }

        def verify(self, payload: bytes, signature: dict[str, object], public_key: bytes | None = None) -> bool:
            seen["payload"] = payload
            seen["key"] = public_key
            return public_key == b"pin" and signature.get("value") == "ok"

    path = tmp_path / "audit.jsonl"
    signer = Local()
    JsonlAuditStore(path, signer=signer, checkpoint_every=1).append_event(_event(1))
    key = tmp_path / "key.pub"
    key.write_bytes(b"pin")

    def factory(_settings, options=None):
        assert options == {}
        return signer

    factory.licence_feature = "signer.ed25519"  # type: ignore[attr-defined]
    flags = FeatureSet(
        enabled=set(COMMUNITY_FEATURES) | {"signer.ed25519"},
        plugins={SIGNERS_GROUP: {"unsigned": unsigned_signer, "ed25519": factory}},
    )
    monkeypatch.setattr(
        "mcp_glp_audit_proxy.checkpoints.FeatureSet.load",
        lambda *_args, **_kwargs: flags,
    )
    assert verify_main([str(path), "--pubkey", str(key)]) == 0
    assert "chain ok" in capsys.readouterr().err
    assert seen["key"] == b"pin"
    assert seen["payload"] == seen["signed"]
    checkpoint = [
        item for item in JsonlAuditStore(path, checkpoint_every=0).read_entries() if item["method"] == "audit/checkpoint"
    ][0]
    arguments = checkpoint["arguments"]
    assert seen["payload"] == canonicalize(
        {"head_hash": arguments["head_hash"], "seq": arguments["seq"], "timestamp": checkpoint["timestamp"]}
    )

    key.write_bytes(b"other")
    assert verify_main([str(path), "--pubkey", str(key)]) == 1
    assert "does not match the pinned public key" in capsys.readouterr().err


def test_unsigned_checkpoint_is_not_accepted_with_a_pinned_key(tmp_path: Path, capsys, monkeypatch) -> None:
    path = tmp_path / "audit.jsonl"
    JsonlAuditStore(path, checkpoint_every=1).append_event(_event(1))
    called: list[bytes] = []

    class Plugin:
        def verify(self, _payload: bytes, _signature: dict, public_key: bytes | None = None) -> bool:
            called.append(public_key or b"")
            return True

    def factory(_settings, options=None):
        return Plugin()

    factory.licence_feature = "signer.ed25519"  # type: ignore[attr-defined]
    flags = FeatureSet(
        enabled=set(COMMUNITY_FEATURES) | {"signer.ed25519"},
        plugins={SIGNERS_GROUP: {"ed25519": factory}},
    )
    monkeypatch.setattr(
        "mcp_glp_audit_proxy.checkpoints.FeatureSet.load",
        lambda *_args, **_kwargs: flags,
    )
    key = tmp_path / "key.pub"
    key.write_bytes(b"pin")
    assert verify_main([str(path), "--pubkey", str(key)]) == 1
    assert "is unsigned" in capsys.readouterr().err
    assert called == []
    assert licensed_signer(flags).verify(b"x", {"signed": True, "value": "ok"}, public_key=b"pin") is True


def test_two_licensed_signers_are_refused() -> None:
    def factory(_settings, options=None):
        return object()

    factory.licence_feature = "signer.ed25519"  # type: ignore[attr-defined]

    def other(_settings, options=None):
        return object()

    other.licence_feature = "signer.ecdsa"  # type: ignore[attr-defined]
    flags = FeatureSet(
        enabled=set(COMMUNITY_FEATURES) | {"signer.ed25519", "signer.ecdsa"},
        plugins={SIGNERS_GROUP: {"ed25519": factory, "ecdsa": other}},
    )
    assert check_log([], b"pin", flags) == ["more than one licensed signer plugin"]


def test_readme_says_the_chain_is_not_a_signature() -> None:
    readme = Path(__file__).resolve().parents[1].joinpath("README.md").read_text(encoding="utf-8")
    readme.encode("ascii")
    assert "Community is tamper-evident via the hash chain. It is not signed. Signing is Pro." in readme
    assert "--expect-head" in readme
    assert "--pubkey" in readme
