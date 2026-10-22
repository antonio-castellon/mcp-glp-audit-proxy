"""Shipped trust anchors are the production set and nothing else."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from mcp_glp_audit_proxy.errors import LicenceError
from mcp_glp_audit_proxy.trust import _keys_from_document, trusted_key, trusted_keys

ROOT = Path(__file__).resolve().parents[1]

# Pinned independently of release_trust.json. Changing a shipped key fails here.
_PRODUCTION_SHA256 = {
    "ed25519-1": "79f397ee5ab330e261562f9af6b759538ee5763bbe8e4aa907f17f96060f04a9",
    "lm1-rsa-1": "8a4a3f1450511b25b4b1d9050fea4a2e3ec60658598fd2101198817ed9507b1d",
}
_BANNED = (
    "TEST TRUST",
    "TEST",
    "8b81069ec1a5f561e2bd0b335c9b32e202e3b02a7c56a0232859c625051759a6",
    "AmbqqoHuPlSeAy1NoMM",
    "a9f9def8fb5c0de7cbb768eb1bcab1fd28ed5fa285f61b2ad8edecd8b2e751f7",
)


def test_shipped_trust_keys_match_the_production_pins() -> None:
    keys = trusted_keys()
    assert [key.key_id for key in keys] == ["ed25519-1", "lm1-rsa-1"]
    by_id = {key.key_id: key for key in keys}
    ed25519 = by_id["ed25519-1"]
    assert ed25519.algorithm == "ed25519"
    assert ed25519.public_pem is None
    raw = ed25519.ed25519_bytes()
    assert len(raw) == 32
    assert hashlib.sha256(raw).hexdigest() == _PRODUCTION_SHA256["ed25519-1"]
    rsa = by_id["lm1-rsa-1"]
    assert rsa.algorithm == "rsa-pss-sha256"
    assert rsa.public_hex is None
    pem = rsa.rsa_pem_bytes()
    assert pem.startswith(b"-----BEGIN PUBLIC KEY-----\n")
    assert b"Az5MEqS9WM6YdVUdnEUiB" in pem
    assert hashlib.sha256(pem).hexdigest() == _PRODUCTION_SHA256["lm1-rsa-1"]
    assert trusted_key("ed25519-1") == ed25519
    assert trusted_key("lm1-rsa-1") == rsa
    with pytest.raises(LicenceError, match="not in the trust file"):
        trusted_key("other")


def test_no_test_anchor_ships_in_the_package() -> None:
    src = ROOT / "src"
    seen = 0
    for path in src.rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".json", ".md"}:
            continue
        seen += 1
        text = path.read_text(encoding="utf-8")
        for banned in _BANNED:
            assert banned not in text, f"{path} contains {banned}"
    assert seen >= 2
    packaged = src / "mcp_glp_audit_proxy" / "release_trust.json"
    assert packaged.is_file()
    assert "df94b07a4976983cff62239a567ab57f6402e23b0f3c137b947b3105b170a926" in packaged.read_text(
        encoding="utf-8"
    )


def test_trust_document_fails_closed() -> None:
    with pytest.raises(LicenceError, match="missing or malformed"):
        _keys_from_document({})
    with pytest.raises(LicenceError, match="missing or malformed"):
        _keys_from_document({"keys": []})
    with pytest.raises(LicenceError, match="missing or malformed"):
        _keys_from_document(
            {
                "keys": [
                    {
                        "key_id": "ed25519-1",
                        "algorithm": "ed25519",
                        "public_hex": "ab" * 32,
                    },
                    {
                        "key_id": "ed25519-1",
                        "algorithm": "ed25519",
                        "public_hex": "cd" * 32,
                    },
                ]
            }
        )
    with pytest.raises(LicenceError, match="missing or malformed"):
        _keys_from_document(
            {
                "keys": [
                    {
                        "key_id": "other",
                        "algorithm": "rsa",
                        "public_pem": "nope",
                    }
                ]
            }
        )


def test_missing_trust_file_fails_closed(monkeypatch) -> None:
    def broken(_package: str):
        raise FileNotFoundError("gone")

    monkeypatch.setattr("mcp_glp_audit_proxy.trust.files", broken)
    with pytest.raises(LicenceError, match="missing or malformed"):
        trusted_keys()
