"""Offline feature flags, plugin entry points, TLS 1.3, SDK floor."""

from __future__ import annotations

import json
import socket
import ssl

import pytest

from mcp_glp_audit_proxy.errors import TlsRequired
from mcp_glp_audit_proxy.features import COMMUNITY_FEATURES, PRO_FEATURES, FeatureSet
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
