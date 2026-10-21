"""Offline feature flags, plugin entry points, TLS 1.3, SDK floor."""

from __future__ import annotations

import base64
import json
import socket
import ssl
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

import mcp_glp_audit_proxy.features as features_mod
from mcp_glp_audit_proxy.canonical import canonicalize
from mcp_glp_audit_proxy.errors import ConfigurationError, LicenceError, TlsRequired
from mcp_glp_audit_proxy.features import (
    COMMUNITY_FEATURES,
    PLUGIN_GROUPS,
    FeatureSet,
)
from mcp_glp_audit_proxy.identity import env_identity
from mcp_glp_audit_proxy.licence import (
    LICENCE_APP,
    LICENCE_KEY_ID,
    LICENCE_PUBLIC_KEY,
    LICENCE_RSA_PUBLIC_PEM,
    licence_fingerprint,
)
from mcp_glp_audit_proxy.plugins import load_group
from mcp_glp_audit_proxy.reporters.json_export import json_reporter
from mcp_glp_audit_proxy.reporters.text_export import text_reporter
from mcp_glp_audit_proxy.sdkcheck import assert_mcp_floor, parse_version
from mcp_glp_audit_proxy.signers.unsigned import unsigned_signer
from mcp_glp_audit_proxy.storage.jsonl import jsonl_store
from mcp_glp_audit_proxy.tlsutil import require_https, tls13_context
from mcp_glp_audit_proxy.wiring import STORAGE_GROUP, load_named


_CLIENT = "lab-1"


def _sign(body: dict, private: Ed25519PrivateKey) -> dict:
    signed = {key: value for key, value in body.items() if key != "signature"}
    value = base64.b64encode(private.sign(canonicalize(signed))).decode("ascii")
    signed["signature"] = {"algorithm": "ed25519", "key_id": "test", "value": value}
    return signed


def _bound(body: dict, names: list[str], client_id: str = _CLIENT) -> dict:
    copied = dict(body)
    copied["fingerprint"] = licence_fingerprint(client_id, names)
    return copied


def _public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _licence(tmp_path, body: dict):
    path = tmp_path / "licence.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def test_licence_is_local_and_does_not_phone_home(tmp_path, monkeypatch) -> None:
    def boom(*_args, **_kwargs):
        raise AssertionError("feature loader opened a socket")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)

    def verifier_called(*_args, **_kwargs):
        raise AssertionError("verifier called with no licence")

    monkeypatch.setattr(features_mod, "verify_ed25519_licence", verifier_called)
    flags = FeatureSet.load(None)
    assert flags.enabled == set(COMMUNITY_FEATURES)
    assert flags.unavailable == []
    assert not hasattr(features_mod, "PRO_FEATURES")
    assert not hasattr(features_mod, "PRO_PLUGINS")

    unsigned = _licence(
        tmp_path,
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": ["storage.sql", "report.json"],
        },
    )
    with pytest.raises(LicenceError, match="signature is required"):
        FeatureSet.load(unsigned)

    empty = _licence(
        tmp_path,
        {"format": "mcp-glp-audit-proxy-licence", "features": []},
    )
    accepted = FeatureSet.load(empty)
    assert "storage.jsonl" in accepted.enabled
    assert "storage.sql" not in accepted.enabled
    assert accepted.unavailable == []


def test_signed_licence_enables_only_a_declared_feature(tmp_path, monkeypatch) -> None:
    private = Ed25519PrivateKey.generate()
    public = _public(private)
    called = {"hit": False}

    def sql_store(_settings, _signer, options=None):
        del options
        called["hit"] = True
        raise AssertionError("plugin factory was called from the licence loader")

    sql_store.licence_feature = "storage.sql"
    real = load_group

    def fake(group: str) -> dict:
        found = dict(real(group))
        if group == STORAGE_GROUP:
            found["sql"] = sql_store
        return found

    monkeypatch.setattr(features_mod, "load_group", fake)
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    body = _bound(
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": ["storage.sql", "not-a-feature"],
            "expires": "2027-01-01T00:00:00+00:00",
        },
        ["sql"],
    )
    signed = tmp_path / "signed.json"
    signed.write_text(json.dumps(_sign(body, private)), encoding="utf-8")
    flags = FeatureSet.load(signed, public_key=public, client_id=_CLIENT, now=now)
    assert "storage.sql" in flags.enabled
    assert "storage.jsonl" in flags.enabled
    assert flags.unavailable == ["not-a-feature"]
    assert called["hit"] is False
    assert load_named(flags, STORAGE_GROUP, "sql") is sql_store
    assert called["hit"] is False

    omitted = tmp_path / "omitted.json"
    omitted.write_text(
        json.dumps(
            _sign(
                _bound(
                    {
                        "format": "mcp-glp-audit-proxy-licence",
                        "features": ["report.json"],
                        "expires": "2027-01-01T00:00:00Z",
                    },
                    ["sql"],
                ),
                private,
            )
        ),
        encoding="utf-8",
    )
    without = FeatureSet.load(omitted, public_key=public, client_id=_CLIENT, now=now)
    assert "storage.sql" not in without.enabled
    with pytest.raises(ConfigurationError, match="not licensed"):
        load_named(without, STORAGE_GROUP, "sql")
    assert called["hit"] is False

    tampered = json.loads(signed.read_text(encoding="utf-8"))
    tampered["features"] = ["storage.sql", "storage.extra"]
    bad = tmp_path / "tampered.json"
    bad.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(LicenceError, match="invalid"):
        FeatureSet.load(bad, public_key=public, now=now)

    moved = json.loads(signed.read_text(encoding="utf-8"))
    moved["signature"]["key_id"] = "other"
    kept = tmp_path / "keyid.json"
    kept.write_text(json.dumps(moved), encoding="utf-8")
    again = FeatureSet.load(kept, public_key=public, client_id=_CLIENT, now=now)
    assert "storage.sql" in again.enabled

    with pytest.raises(LicenceError, match="invalid"):
        FeatureSet.load(signed, now=now)


def test_expired_or_bad_signature_is_rejected(tmp_path) -> None:
    private = Ed25519PrivateKey.generate()
    public = _public(private)
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    expired = _licence(
        tmp_path,
        _sign(
            _bound(
                {
                    "format": "mcp-glp-audit-proxy-licence",
                    "features": [],
                    "expires": "2020-01-01T00:00:00+00:00",
                },
                [],
            ),
            private,
        ),
    )
    with pytest.raises(LicenceError, match="expired"):
        FeatureSet.load(expired, public_key=public, client_id=_CLIENT, now=now)

    unsigned_expired = _licence(
        tmp_path,
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": [],
            "expires": "2020-01-01T00:00:00+00:00",
        },
    )
    with pytest.raises(LicenceError, match="expired"):
        FeatureSet.load(unsigned_expired, now=now)

    naive = _licence(
        tmp_path,
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": [],
            "expires": "2027-01-01T00:00:00",
        },
    )
    with pytest.raises(LicenceError, match="time zone"):
        FeatureSet.load(naive)
    broken = _licence(
        tmp_path,
        {"format": "mcp-glp-audit-proxy-licence", "features": [], "expires": "tomorrow"},
    )
    with pytest.raises(LicenceError, match="RFC3339"):
        FeatureSet.load(broken)
    bad_signature = _licence(
        tmp_path,
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": [],
            "signature": "nope",
        },
    )
    with pytest.raises(LicenceError, match="must be an object"):
        FeatureSet.load(bad_signature)
    wrong_algorithm = _licence(
        tmp_path,
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": [],
            "signature": {"algorithm": "rsa", "value": "abc"},
        },
    )
    with pytest.raises(LicenceError, match="must be ed25519"):
        FeatureSet.load(wrong_algorithm)
    not_base64 = _licence(
        tmp_path,
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": [],
            "signature": {"algorithm": "ed25519", "value": "nope!"},
        },
    )
    with pytest.raises(LicenceError, match="must be base64"):
        FeatureSet.load(not_base64)
    short = _licence(
        tmp_path,
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": [],
            "signature": {"algorithm": "ed25519", "value": "nope"},
        },
    )
    with pytest.raises(LicenceError, match="invalid"):
        FeatureSet.load(short)
    zeros = _licence(
        tmp_path,
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": [],
            "signature": {
                "algorithm": "ed25519",
                "value": base64.b64encode(b"\x00" * 64).decode("ascii"),
            },
        },
    )
    with pytest.raises(LicenceError, match="invalid"):
        FeatureSet.load(zeros, public_key=public)
    not_object = tmp_path / "list.json"
    not_object.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        FeatureSet.load(not_object)
    assert len(LICENCE_PUBLIC_KEY) == 32
    assert LICENCE_KEY_ID == "mcp-glp-audit-proxy-licence"
    assert LICENCE_APP == "mcp-glp-audit-proxy"
    assert load_pem_public_key(LICENCE_RSA_PUBLIC_PEM.encode("ascii")).key_size == 2048


def _lm1_bytes(body: dict) -> bytes:
    """Bytes the issuer signs: compact JSON, sorted keys, raw non-ASCII."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _lm1(body: dict, private: rsa.RSAPrivateKey, *, raw: bytes | None = None) -> str:
    payload = _lm1_bytes(body) if raw is None else raw
    signature = private.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    encoded_body = base64.b64encode(payload).decode("ascii")
    encoded_sig = base64.b64encode(signature).decode("ascii")
    return f"LM1\n{encoded_body}\n{encoded_sig}\n"


def _issuer_lm1(names: list[str], **overrides: object) -> dict:
    body: dict[str, object] = {
        "app": "mcp-glp-audit-proxy",
        "expires": "2027-01-01",
        "fingerprint": licence_fingerprint(_CLIENT, names),
        "holder": "qa@lab.example",
        "issued": "2026-01-01",
        "kind": "year",
        "updates_until": "2020-01-01",
        "version": 1,
    }
    body.update(overrides)
    return body


def _rsa_pair() -> tuple[rsa.RSAPrivateKey, bytes]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return private, pem


def test_both_formats_bind_the_fingerprint(tmp_path, monkeypatch) -> None:
    ed_private = Ed25519PrivateKey.generate()
    ed_public = _public(ed_private)
    rsa_private, rsa_pem = _rsa_pair()
    called = {"sql": False, "pdf": False}
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)

    def sql_store(_settings, _signer, options=None):
        del options
        called["sql"] = True
        raise AssertionError("unlicensed or unused factory was called")

    def pdf_report(_settings, options=None):
        del options
        called["pdf"] = True
        raise AssertionError("extra plugin was called")

    sql_store.licence_feature = "storage.sql"
    pdf_report.licence_feature = "report.pdf"
    real = load_group
    installed = {"pdf": False}

    def fake(group: str) -> dict:
        found = dict(real(group))
        if group == STORAGE_GROUP:
            found["sql"] = sql_store
        if group == "mcp_glp_audit_proxy.reporters" and installed["pdf"]:
            found["pdf"] = pdf_report
        return found

    monkeypatch.setattr(features_mod, "load_group", fake)
    assert licence_fingerprint(_CLIENT, ["pdf", "sql"]) == licence_fingerprint(_CLIENT, ["sql", "pdf"])
    assert licence_fingerprint(_CLIENT, []) != licence_fingerprint(_CLIENT, ["jsonl"])

    def load_text(text: str, *, rsa_public_key: bytes | None = None):
        path = tmp_path / "bound.txt"
        path.write_text(text, encoding="utf-8")
        return FeatureSet.load(
            path,
            public_key=ed_public,
            rsa_public_key=rsa_public_key,
            client_id=_CLIENT,
            now=now,
        )

    json_body = _sign(
        _bound(
            {
                "format": "mcp-glp-audit-proxy-licence",
                "features": ["storage.sql", "not-a-feature"],
                "expires": "2027-01-01T00:00:00+00:00",
            },
            ["sql"],
        ),
        ed_private,
    )
    json_flags = load_text(json.dumps(json_body))
    assert "storage.sql" in json_flags.enabled
    assert "not-a-feature" in json_flags.unavailable

    lm1_payload = _issuer_lm1(["sql"])
    signed_bytes = _lm1_bytes(lm1_payload)
    assert b" " not in signed_bytes
    assert signed_bytes == json.dumps(
        lm1_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    lm1_flags = load_text(_lm1(lm1_payload, rsa_private), rsa_public_key=rsa_pem)
    assert "storage.sql" in lm1_flags.enabled
    assert "report.pdf" not in lm1_flags.enabled
    assert lm1_flags.unavailable == []
    assert "features" not in lm1_payload
    assert called == {"sql": False, "pdf": False}

    spaced = json.dumps(lm1_payload).encode("utf-8")
    assert b" " in spaced
    spaced_flags = load_text(_lm1(lm1_payload, rsa_private, raw=spaced), rsa_public_key=rsa_pem)
    assert "storage.sql" in spaced_flags.enabled

    perpetual = _issuer_lm1(["sql"], expires=None, kind="perpetual")
    perpetual_flags = load_text(_lm1(perpetual, rsa_private), rsa_public_key=rsa_pem)
    assert "storage.sql" in perpetual_flags.enabled
    trial = _issuer_lm1(["sql"], kind="trial", expires="2026-12-01")
    assert "storage.sql" in load_text(_lm1(trial, rsa_private), rsa_public_key=rsa_pem).enabled

    missing = _sign(
        {key: value for key, value in json_body.items() if key not in {"signature", "fingerprint"}},
        ed_private,
    )
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(missing), encoding="utf-8")
    with pytest.raises(LicenceError, match="fingerprint is required"):
        FeatureSet.load(bare, public_key=ed_public, client_id=_CLIENT, now=now)

    wrong = _sign(
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": ["storage.sql"],
            "expires": "2027-01-01T00:00:00+00:00",
            "fingerprint": licence_fingerprint("other-lab", ["sql"]),
        },
        ed_private,
    )
    wrong_path = tmp_path / "wrong.json"
    wrong_path.write_text(json.dumps(wrong), encoding="utf-8")
    with pytest.raises(LicenceError, match="does not match"):
        FeatureSet.load(wrong_path, public_key=ed_public, client_id=_CLIENT, now=now)
    with pytest.raises(LicenceError, match="client_id is required"):
        FeatureSet.load(wrong_path, public_key=ed_public, now=now)

    wrong_lm1 = _issuer_lm1(["sql"], fingerprint=licence_fingerprint("other-lab", ["sql"]))
    lm1_path = tmp_path / "wrong.lm1"
    lm1_path.write_text(_lm1(wrong_lm1, rsa_private), encoding="utf-8")
    with pytest.raises(LicenceError, match="does not match"):
        FeatureSet.load(lm1_path, rsa_public_key=rsa_pem, client_id=_CLIENT, now=now)

    tampered = _lm1(lm1_payload, rsa_private)
    body_b64 = tampered.split("\n")[1]
    flipped = ("A" if body_b64[0] != "A" else "B") + body_b64[1:]
    tampered_path = tmp_path / "tamper.lm1"
    tampered_path.write_text("LM1\n" + flipped + "\n" + tampered.split("\n")[2] + "\n", encoding="utf-8")
    with pytest.raises(LicenceError, match="invalid"):
        FeatureSet.load(tampered_path, rsa_public_key=rsa_pem, client_id=_CLIENT, now=now)

    other_private, other_pem = _rsa_pair()
    resigned = tmp_path / "other.lm1"
    resigned.write_text(_lm1(lm1_payload, other_private), encoding="utf-8")
    with pytest.raises(LicenceError, match="invalid"):
        FeatureSet.load(resigned, rsa_public_key=rsa_pem, client_id=_CLIENT, now=now)
    assert load_pem_public_key(other_pem).key_size == 2048

    installed["pdf"] = True
    extra = tmp_path / "extra.lm1"
    extra.write_text(_lm1(lm1_payload, rsa_private), encoding="utf-8")
    with pytest.raises(LicenceError, match="does not match"):
        FeatureSet.load(extra, rsa_public_key=rsa_pem, client_id=_CLIENT, now=now)
    extra_json = tmp_path / "extra.json"
    extra_json.write_text(json.dumps(json_body), encoding="utf-8")
    with pytest.raises(LicenceError, match="does not match"):
        FeatureSet.load(extra_json, public_key=ed_public, client_id=_CLIENT, now=now)
    assert called == {"sql": False, "pdf": False}

    both = _issuer_lm1(["pdf", "sql"], kind="year")
    both_flags = load_text(_lm1(both, rsa_private), rsa_public_key=rsa_pem)
    assert "storage.sql" in both_flags.enabled
    assert "report.pdf" in both_flags.enabled
    assert called == {"sql": False, "pdf": False}

    installed["pdf"] = False
    expired = _issuer_lm1(["sql"], expires="2020-01-01", kind="year")
    expired_path = tmp_path / "expired.lm1"
    expired_path.write_text(_lm1(expired, rsa_private), encoding="utf-8")
    with pytest.raises(LicenceError, match="expired"):
        FeatureSet.load(expired_path, rsa_public_key=rsa_pem, client_id=_CLIENT, now=now)
    bad_kind = _issuer_lm1(["sql"], kind="30d")
    kind_path = tmp_path / "kind.lm1"
    kind_path.write_text(_lm1(bad_kind, rsa_private), encoding="utf-8")
    with pytest.raises(LicenceError, match="trial, year or perpetual"):
        FeatureSet.load(kind_path, rsa_public_key=rsa_pem, client_id=_CLIENT, now=now)
    wrong_app = _issuer_lm1(["sql"], app="other-app")
    app_path = tmp_path / "app.lm1"
    app_path.write_text(_lm1(wrong_app, rsa_private), encoding="utf-8")
    with pytest.raises(LicenceError, match="app must be mcp-glp-audit-proxy"):
        FeatureSet.load(app_path, rsa_public_key=rsa_pem, client_id=_CLIENT, now=now)
    with_features = _issuer_lm1(["sql"])
    with_features["features"] = ["storage.sql"]
    feature_path = tmp_path / "features.lm1"
    feature_path.write_text(_lm1(with_features, rsa_private), encoding="utf-8")
    with pytest.raises(LicenceError, match="do not match the issuer"):
        FeatureSet.load(feature_path, rsa_public_key=rsa_pem, client_id=_CLIENT, now=now)
    assert called == {"sql": False, "pdf": False}


def test_community_entry_points_only() -> None:
    storage = load_group("mcp_glp_audit_proxy.storage")
    signers = load_group("mcp_glp_audit_proxy.signers")
    reporters = load_group("mcp_glp_audit_proxy.reporters")
    auth = load_group("mcp_glp_audit_proxy.auth")
    assert set(PLUGIN_GROUPS) == {
        "mcp_glp_audit_proxy.storage",
        "mcp_glp_audit_proxy.signers",
        "mcp_glp_audit_proxy.reporters",
        "mcp_glp_audit_proxy.auth",
    }
    assert storage["jsonl"].licence_feature == "storage.jsonl"
    assert signers["unsigned"].licence_feature == "signer.unsigned"
    assert reporters["json"].licence_feature == "report.json"
    assert reporters["text"].licence_feature == "report.text"
    assert auth["env"].licence_feature == "auth.env"
    for feature in (
        jsonl_store.licence_feature,
        unsigned_signer.licence_feature,
        json_reporter.licence_feature,
        text_reporter.licence_feature,
        env_identity.licence_feature,
    ):
        assert feature in COMMUNITY_FEATURES
    assert "jsonl" in storage
    assert "postgres" not in storage
    assert "sql" not in storage
    assert "unsigned" in signers
    assert "ed25519" not in signers
    assert set(reporters) == {"json", "text"}
    assert "sso" not in auth


def test_remote_transport_is_tls_1_3() -> None:
    context = tls13_context()
    assert context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert context.maximum_version is ssl.TLSVersion.TLSv1_3
    with pytest.raises(TlsRequired):
        require_https("http://instruments.example/mcp")
    assert require_https("https://instruments.example/mcp").startswith("https://")


def test_sdk_floor_rejects_the_advisory_range() -> None:
    parsed = assert_mcp_floor()
    assert parsed >= (2, 2, 0)
    assert parsed < (3, 0, 0)
    assert parse_version("2.1.1") < (2, 2, 0)
    assert parse_version("1.29.1") < (2, 2, 0)
