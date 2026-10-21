"""Offline feature flags, plugin entry points, TLS 1.3, SDK floor."""

from __future__ import annotations

import base64
import json
import socket
import ssl
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import mcp_glp_audit_proxy.features as features_mod
from mcp_glp_audit_proxy.canonical import canonicalize
from mcp_glp_audit_proxy.errors import ConfigurationError, LicenceError, TlsRequired
from mcp_glp_audit_proxy.features import (
    COMMUNITY_FEATURES,
    PLUGIN_GROUPS,
    FeatureSet,
)
from mcp_glp_audit_proxy.identity import env_identity
from mcp_glp_audit_proxy.licence import LICENCE_KEY_ID, LICENCE_PUBLIC_KEY
from mcp_glp_audit_proxy.plugins import load_group
from mcp_glp_audit_proxy.reporters.json_export import json_reporter
from mcp_glp_audit_proxy.reporters.text_export import text_reporter
from mcp_glp_audit_proxy.sdkcheck import assert_mcp_floor, parse_version
from mcp_glp_audit_proxy.signers.unsigned import unsigned_signer
from mcp_glp_audit_proxy.storage.jsonl import jsonl_store
from mcp_glp_audit_proxy.tlsutil import require_https, tls13_context
from mcp_glp_audit_proxy.wiring import STORAGE_GROUP, load_named


def _sign(body: dict, private: Ed25519PrivateKey) -> dict:
    signed = {key: value for key, value in body.items() if key != "signature"}
    value = base64.b64encode(private.sign(canonicalize(signed))).decode("ascii")
    signed["signature"] = {"algorithm": "ed25519", "key_id": "test", "value": value}
    return signed


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
    body = {
        "format": "mcp-glp-audit-proxy-licence",
        "features": ["storage.sql", "not-a-feature"],
        "expires": "2027-01-01T00:00:00+00:00",
    }
    signed = tmp_path / "signed.json"
    signed.write_text(json.dumps(_sign(body, private)), encoding="utf-8")
    flags = FeatureSet.load(signed, public_key=public, now=now)
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
                {
                    "format": "mcp-glp-audit-proxy-licence",
                    "features": ["report.json"],
                    "expires": "2027-01-01T00:00:00Z",
                },
                private,
            )
        ),
        encoding="utf-8",
    )
    without = FeatureSet.load(omitted, public_key=public, now=now)
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
    again = FeatureSet.load(kept, public_key=public, now=now)
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
            {
                "format": "mcp-glp-audit-proxy-licence",
                "features": [],
                "expires": "2020-01-01T00:00:00+00:00",
            },
            private,
        ),
    )
    with pytest.raises(LicenceError, match="expired"):
        FeatureSet.load(expired, public_key=public, now=now)

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
