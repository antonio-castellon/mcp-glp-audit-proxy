"""Bearer-file ACL rules, exercised with crafted DACL bytes on any OS.

The Win32 readers are not called. POSIX mode 0600 stays the non-Windows check.
"""

from __future__ import annotations

import ctypes
import os
from pathlib import Path

import pytest

from mcp_glp_audit_proxy.channels.identity import read_bearer
from mcp_glp_audit_proxy.channels.winacl import (
    SID_ADMINISTRATORS,
    SID_SYSTEM,
    AclEntry,
    assert_windows_bearer_acl,
    check_bearer_acl,
    icacls_fix_command,
    parse_acl,
)
from mcp_glp_audit_proxy.errors import ConfigurationError

USER = "S-1-5-21-1-2-3-1001"
OTHER = "S-1-5-21-9-9-9-2002"
EVERYONE = "S-1-1-0"
USERS = "S-1-5-32-545"
AUTHENTICATED = "S-1-5-11"
ICACLS = '/inheritance:r /grant:r "%USERNAME%:R" SYSTEM:F Administrators:F'


def _sid(text: str) -> bytes:
    parts = text.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    subs = [int(part) for part in parts[3:]]
    blob = bytes([revision, len(subs)]) + authority.to_bytes(6, "big")
    for sub in subs:
        blob += sub.to_bytes(4, "little")
    return blob


def _ace(sid: str, ace_type: int = 0, mask: int = 0x80000000, flags: int = 0) -> bytes:
    body = mask.to_bytes(4, "little") + _sid(sid)
    size = 4 + len(body)
    padded = size + (4 - size % 4) % 4
    header = bytes([ace_type, flags]) + padded.to_bytes(2, "little")
    return header + body + b"\x00" * (padded - size)


def _object_ace(sid: str, object_flags: int, ace_type: int = 5) -> bytes:
    extra = b""
    if object_flags & 0x1:
        extra += b"\x11" * 16
    if object_flags & 0x2:
        extra += b"\x22" * 16
    body = mask_bytes() + object_flags.to_bytes(4, "little") + extra + _sid(sid)
    size = 4 + len(body)
    padded = size + (4 - size % 4) % 4
    header = bytes([ace_type, 0]) + padded.to_bytes(2, "little")
    return header + body + b"\x00" * (padded - size)


def mask_bytes() -> bytes:
    return (0x80000000).to_bytes(4, "little")


def _acl(aces: list[bytes]) -> bytes:
    body = b"".join(aces)
    size = 8 + len(body)
    header = bytes([2, 0]) + size.to_bytes(2, "little") + len(aces).to_bytes(2, "little")
    header += (0).to_bytes(2, "little")
    return header + body


def _allow(*sids: str, flags: int = 0) -> list[AclEntry]:
    return parse_acl(_acl([_ace(sid, flags=flags) for sid in sids]))


def _expect_refused(path: Path, entries: list[AclEntry] | None, *labels: str) -> str:
    with pytest.raises(ConfigurationError) as caught:
        check_bearer_acl(path, entries, USER)
    text = str(caught.value)
    assert f"icacls {path} {ICACLS}" in text
    for label in labels:
        assert label in text
    return text


def test_other_principals_are_refused_with_the_icacls_command(tmp_path: Path) -> None:
    path = tmp_path / "bearer.token"
    _expect_refused(path, _allow(EVERYONE), "Everyone")
    _expect_refused(path, _allow(USERS), "BUILTIN\\Users")
    _expect_refused(path, _allow(AUTHENTICATED), "Authenticated Users")
    _expect_refused(path, _allow(OTHER), OTHER)
    both = _allow(EVERYONE, USERS, EVERYONE)
    text = _expect_refused(path, both, "Everyone", "BUILTIN\\Users")
    assert text.split("grants access to ", 1)[1].split(".", 1)[0] == "Everyone, BUILTIN\\Users"


def test_current_user_system_and_administrators_are_accepted(tmp_path: Path) -> None:
    path = tmp_path / "bearer.token"
    entries = _allow(USER.lower(), SID_SYSTEM.lower(), SID_ADMINISTRATORS)
    check_bearer_acl(path, entries, USER.lower())
    check_bearer_acl(path, [], USER)
    check_bearer_acl(path, parse_acl(_acl([])), USER)


def test_deny_inherit_only_and_zero_mask_do_not_grant_access(tmp_path: Path) -> None:
    path = tmp_path / "bearer.token"
    deny = parse_acl(_acl([_ace(EVERYONE, ace_type=1), _ace(USER)]))
    inherit = parse_acl(_acl([_ace(EVERYONE, flags=0x08), _ace(SID_SYSTEM)]))
    zero = parse_acl(_acl([_ace(USERS, mask=0), _ace(SID_ADMINISTRATORS)]))
    check_bearer_acl(path, deny, USER)
    check_bearer_acl(path, inherit, USER)
    check_bearer_acl(path, zero, USER)
    inherited = parse_acl(_acl([_ace(EVERYONE, flags=0x10)]))
    _expect_refused(path, inherited, "Everyone")


def test_null_dacl_unknown_ace_and_missing_sid_are_refused(tmp_path: Path) -> None:
    path = tmp_path / "bearer.token"
    text = _expect_refused(path, None, "NULL DACL")
    assert "every principal" in text
    unknown = [AclEntry(sid=USER, ace_type=4, mask=1, flags=0)]
    with pytest.raises(ConfigurationError, match="unrecognized ACE type 4") as caught:
        check_bearer_acl(path, unknown, USER)
    assert ICACLS in str(caught.value)
    with pytest.raises(ConfigurationError, match="current user SID") as missing:
        check_bearer_acl(path, _allow(USER), "")
    assert ICACLS in str(missing.value)


def test_parse_acl_reads_standard_and_object_aces() -> None:
    raw = _acl(
        [
            _ace(SID_SYSTEM, mask=0x120089, flags=0x02),
            _ace(SID_ADMINISTRATORS),
            _object_ace(EVERYONE, 0),
            _object_ace(OTHER, 0x1 | 0x2, ace_type=11),
        ]
    )
    entries = parse_acl(raw)
    assert [entry.sid for entry in entries] == [SID_SYSTEM, SID_ADMINISTRATORS, EVERYONE, OTHER]
    assert entries[0].mask == 0x120089
    assert entries[0].flags == 0x02
    assert entries[2].ace_type == 5
    assert entries[3].ace_type == 11
    with pytest.raises(ValueError):
        parse_acl(b"\x02\x00")
    with pytest.raises(ValueError):
        parse_acl(_acl([_ace(USER)])[:8])


def test_icacls_command_quotes_paths_cmd_would_split() -> None:
    plain = Path("bearer.token")
    assert icacls_fix_command(plain) == f"icacls bearer.token {ICACLS}"
    spaced = Path("C:/Lab/bearer token")
    assert icacls_fix_command(spaced) == f'icacls "C:/Lab/bearer token" {ICACLS}'
    ampersand = Path("C:/Lab/a&b")
    assert icacls_fix_command(ampersand) == f'icacls "C:/Lab/a&b" {ICACLS}'


def test_assert_windows_bearer_acl_uses_the_readers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "bearer.token"
    seen: dict[str, Path] = {}

    def fake_dacl(asked: Path) -> list[AclEntry]:
        seen["path"] = asked
        return _allow(EVERYONE)

    monkeypatch.setattr(
        "mcp_glp_audit_proxy.channels.winacl.read_windows_dacl",
        fake_dacl,
    )
    monkeypatch.setattr(
        "mcp_glp_audit_proxy.channels.winacl.read_current_user_sid",
        lambda: USER,
    )
    with pytest.raises(ConfigurationError, match="Everyone"):
        assert_windows_bearer_acl(path)
    assert seen["path"] == path


def test_posix_bearer_file_must_be_mode_0600(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode bits")
    path = tmp_path / "bearer.token"
    path.write_text("sekret\n", encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(ConfigurationError, match="0600"):
        read_bearer(path)
    path.chmod(0o600)
    assert read_bearer(path) == "sekret"


def test_windows_startup_checks_the_acl_and_does_not_call_win32(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "bearer.token"
    path.write_text("sekret\n", encoding="utf-8")
    path.chmod(0o644)
    monkeypatch.setattr(os, "name", "nt")

    def boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Win32 must not run in this test")

    monkeypatch.setattr(ctypes, "WinDLL", boom, raising=False)
    seen: list[Path] = []

    def fake(asked: Path) -> None:
        seen.append(asked)

    monkeypatch.setattr(
        "mcp_glp_audit_proxy.channels.winacl.assert_windows_bearer_acl",
        fake,
    )
    assert read_bearer(path) == "sekret"
    assert seen == [path]
