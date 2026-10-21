"""Offline feature flags, plugin entry points, TLS 1.3, SDK floor."""

from __future__ import annotations

import json
import socket
import ssl
from datetime import datetime, timezone

import pytest

from mcp_glp_audit_proxy.errors import LicenceError, TlsRequired
from mcp_glp_audit_proxy.features import (
    COMMUNITY_FEATURES,
    LICENCE_GROUP,
    PRO_FEATURES,
    FeatureSet,
    resolve_licence_verifier,
)
from mcp_glp_audit_proxy.plugins import load_group
from mcp_glp_audit_proxy.sdkcheck import assert_mcp_floor, parse_version
from mcp_glp_audit_proxy.tlsutil import require_https, tls13_context


def test_licence_is_local_and_does_not_phone_home(tmp_path, monkeypatch) -> None:
    def boom(*_args, **_kwargs):
        raise AssertionError("feature loader opened a socket")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)

    flags = FeatureSet.load(None)
    assert COMMUNITY_FEATURES <= flags.enabled
    assert flags.enabled.isdisjoint(PRO_FEATURES)
    assert flags.unavailable == []

    licence = tmp_path / "licence.json"
    licence.write_text(
        json.dumps(
            {
                "format": "mcp-glp-audit-proxy-licence",
                "features": ["storage.postgres", "report.json", "not-a-feature"],
            }
        ),
        encoding="utf-8",
    )
    requested = FeatureSet.load(licence)
    assert "report.json" in requested.enabled
    assert "storage.postgres" not in requested.enabled
    assert "storage.postgres" in requested.unavailable
    assert "not-a-feature" in requested.unavailable


def _licence(tmp_path, body: dict) -> object:
    path = tmp_path / "licence.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def test_no_licence_skips_the_verifier() -> None:
    class Boom:
        def verify(self, _raw: dict) -> None:
            raise AssertionError("verifier called with no licence")

    flags = FeatureSet.load(None, verifier=Boom())
    assert COMMUNITY_FEATURES <= flags.enabled
    assert flags.enabled.isdisjoint(PRO_FEATURES)
    assert flags.unavailable == []


def test_expired_or_unsigned_signature_is_rejected(tmp_path) -> None:
    expired = _licence(
        tmp_path,
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": ["signer.ed25519"],
            "expires": "2020-01-01T00:00:00+00:00",
            "signature": {"algorithm": "ed25519", "value": "abc"},
        },
    )

    class Accept:
        def verify(self, _raw: dict) -> None:
            raise AssertionError("expired licence must be rejected before the verifier")

    with pytest.raises(LicenceError, match="expired"):
        FeatureSet.load(expired, verifier=Accept(), now=datetime(2026, 6, 1, tzinfo=timezone.utc))

    future = {
        "format": "mcp-glp-audit-proxy-licence",
        "features": ["signer.ed25519"],
        "expires": "2027-01-01T00:00:00Z",
        "signature": {"algorithm": "ed25519", "value": "abc"},
    }
    signed = _licence(tmp_path, future)
    with pytest.raises(LicenceError, match="no licence verifier"):
        FeatureSet.load(signed, now=datetime(2026, 6, 1, tzinfo=timezone.utc))

    class Bad:
        def verify(self, _raw: dict) -> None:
            raise LicenceError("bad signature")

    with pytest.raises(LicenceError, match="bad signature"):
        FeatureSet.load(signed, verifier=Bad(), now=datetime(2026, 6, 1, tzinfo=timezone.utc))

    class Nope:
        def verify(self, _raw: dict) -> bool:
            return False

    with pytest.raises(LicenceError, match="invalid"):
        FeatureSet.load(signed, verifier=Nope(), now=datetime(2026, 6, 1, tzinfo=timezone.utc))

    class Yes:
        def verify(self, raw: dict) -> None:
            assert raw["signature"]["value"] == "abc"

    accepted = FeatureSet.load(signed, verifier=Yes(), now=datetime(2026, 6, 1, tzinfo=timezone.utc))
    assert "storage.jsonl" in accepted.enabled
    assert "signer.ed25519" in accepted.unavailable

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
    not_object = tmp_path / "list.json"
    not_object.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        FeatureSet.load(not_object)


def test_licence_verifier_entry_point_is_used(tmp_path, monkeypatch) -> None:
    seen: dict[str, str] = {}

    class Installed:
        def verify(self, raw: dict) -> None:
            seen["value"] = raw["signature"]["value"]

    real = load_group

    def fake(group: str) -> dict:
        if group == LICENCE_GROUP:
            return {"acme": lambda: Installed()}
        return real(group)

    monkeypatch.setattr("mcp_glp_audit_proxy.features.load_group", fake)
    path = _licence(
        tmp_path,
        {
            "format": "mcp-glp-audit-proxy-licence",
            "features": [],
            "expires": "2027-01-01T00:00:00+00:00",
            "signature": {"algorithm": "ed25519", "value": "from-plugin"},
        },
    )
    flags = FeatureSet.load(path, now=datetime(2026, 6, 1, tzinfo=timezone.utc))
    assert seen["value"] == "from-plugin"
    assert "storage.jsonl" in flags.enabled

    def many(group: str) -> dict:
        if group == LICENCE_GROUP:
            return {"a": lambda: Installed(), "b": lambda: Installed()}
        return real(group)

    monkeypatch.setattr("mcp_glp_audit_proxy.features.load_group", many)
    with pytest.raises(LicenceError, match="default"):
        FeatureSet.load(path, now=datetime(2026, 6, 1, tzinfo=timezone.utc))

    def broken(group: str) -> dict:
        if group == LICENCE_GROUP:
            return {"default": lambda: object()}
        return real(group)

    monkeypatch.setattr("mcp_glp_audit_proxy.features.load_group", broken)
    with pytest.raises(LicenceError, match="does not implement verify"):
        resolve_licence_verifier()


def test_community_entry_points_only() -> None:
    storage = load_group("mcp_glp_audit_proxy.storage")
    signers = load_group("mcp_glp_audit_proxy.signers")
    reporters = load_group("mcp_glp_audit_proxy.reporters")
    assert "jsonl" in storage
    assert "postgres" not in storage
    assert "unsigned" in signers
    assert "ed25519" not in signers
    assert set(reporters) == {"json", "text"}


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
