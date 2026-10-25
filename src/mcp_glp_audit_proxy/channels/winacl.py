"""NTFS ACL check for the bearer token file.

On Windows the POSIX mode 0600 bit does not exist. Startup reads the
discretionary ACL and allows access only for the current user, SYSTEM
(S-1-5-18), and BUILTIN\\Administrators (S-1-5-32-544). Any other allow
entry, and a NULL DACL, refuses startup. The error includes the icacls
command that replaces the ACL.

The byte parser is pure Python so tests can feed a crafted ACL on Linux.
The Win32 calls run only when this process asks for the live file.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from ..errors import ConfigurationError

SID_SYSTEM = "S-1-5-18"
SID_ADMINISTRATORS = "S-1-5-32-544"
INHERIT_ONLY_ACE = 0x08
# ACCESS_ALLOWED, ACCESS_ALLOWED_OBJECT, ACCESS_ALLOWED_CALLBACK,
# ACCESS_ALLOWED_CALLBACK_OBJECT.
_ALLOW_TYPES = frozenset({0, 5, 9, 11})
# ACCESS_DENIED and the object/callback deny forms. A deny does not grant access.
_DENY_TYPES = frozenset({1, 6, 10, 12})
_WELL_KNOWN = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
}
_ICACLS_TAIL = '/inheritance:r /grant:r "%USERNAME%:R" SYSTEM:F Administrators:F'


@dataclass(frozen=True)
class AclEntry:
    """One discretionary ACE. ``name`` is empty when the account was not resolved."""

    sid: str
    ace_type: int
    mask: int
    flags: int
    name: str = ""

    def label(self) -> str:
        if self.name:
            return self.name
        return _WELL_KNOWN.get(self.sid.upper(), self.sid)


def icacls_fix_command(path: Path) -> str:
    """The command that drops inherited ACEs and grants only the three principals."""
    shown = str(path)
    if any(char in shown for char in ' \t&'):
        shown = '"' + shown.replace('"', "") + '"'
    return f"icacls {shown} {_ICACLS_TAIL}"


def bearer_acl_error(path: Path, principals: list[str]) -> str:
    who = ", ".join(principals)
    return (
        f"bearer token file {path} grants access to {who}. "
        "Only the current user, SYSTEM, and BUILTIN\\Administrators may have any access. "
        f"Fix the ACL with: {icacls_fix_command(path)}"
    )


def check_bearer_acl(
    path: Path,
    entries: list[AclEntry] | None,
    current_user_sid: str,
) -> None:
    """Refuse when ``entries`` grants access to anyone else.

    ``entries is None`` is a NULL DACL, which Windows treats as access for
    every principal. An empty list grants nobody and is accepted.
    """
    if not current_user_sid:
        raise ConfigurationError(
            f"bearer token file {path}: the current user SID could not be read. "
            f"Fix the ACL with: {icacls_fix_command(path)}"
        )
    if entries is None:
        raise ConfigurationError(bearer_acl_error(path, ["NULL DACL (every principal)"]))
    allowed = {current_user_sid.upper(), SID_SYSTEM, SID_ADMINISTRATORS}
    offenders: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        if entry.flags & INHERIT_ONLY_ACE:
            continue
        if entry.ace_type in _DENY_TYPES or entry.mask == 0:
            continue
        if entry.ace_type not in _ALLOW_TYPES:
            raise ConfigurationError(
                f"bearer token file {path} has an unrecognized ACE type {entry.ace_type}. "
                "Only the current user, SYSTEM, and BUILTIN\\Administrators may have any access. "
                f"Fix the ACL with: {icacls_fix_command(path)}"
            )
        if entry.sid.upper() in allowed:
            continue
        label = entry.label()
        if label not in seen:
            seen.add(label)
            offenders.append(label)
    if offenders:
        raise ConfigurationError(bearer_acl_error(path, offenders))


def parse_acl(acl_bytes: bytes) -> list[AclEntry]:
    """Walk a DACL image. Raises ValueError when the bytes are not an ACL."""
    if len(acl_bytes) < 8:
        raise ValueError("ACL header is short")
    declared = int.from_bytes(acl_bytes[2:4], "little")
    if declared < 8 or declared > len(acl_bytes):
        raise ValueError("ACL size is invalid")
    count = int.from_bytes(acl_bytes[4:6], "little")
    offset = 8
    entries: list[AclEntry] = []
    for _ in range(count):
        if offset + 4 > declared:
            raise ValueError("ACE header is short")
        ace_type = acl_bytes[offset]
        flags = acl_bytes[offset + 1]
        ace_size = int.from_bytes(acl_bytes[offset + 2 : offset + 4], "little")
        if ace_size < 8 or offset + ace_size > declared:
            raise ValueError("ACE size is invalid")
        ace = acl_bytes[offset : offset + ace_size]
        entries.append(_parse_ace(ace_type, flags, ace))
        offset += ace_size
    return entries


def assert_windows_bearer_acl(path: Path) -> None:
    """Read the live DACL. Used on Windows only."""
    entries = read_windows_dacl(path)
    check_bearer_acl(path, entries, read_current_user_sid())


def read_windows_dacl(path: Path) -> list[AclEntry] | None:
    """Return the file DACL. None means a NULL DACL."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    get_info = advapi32.GetNamedSecurityInfoW
    get_info.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_info.restype = wintypes.DWORD
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    status = get_info(
        str(path),
        1,  # SE_FILE_OBJECT
        0x4,  # DACL_SECURITY_INFORMATION
        ctypes.byref(owner),
        ctypes.byref(group),
        ctypes.byref(dacl),
        ctypes.byref(sacl),
        ctypes.byref(descriptor),
    )
    try:
        if status != 0:
            raise ConfigurationError(
                f"bearer token file {path}: could not read the NTFS ACL (winerror {status}). "
                f"Fix the ACL with: {icacls_fix_command(path)}"
            )
        if not dacl.value:
            return None
        header = ctypes.string_at(dacl.value, 8)
        acl_size = int.from_bytes(header[2:4], "little")
        if acl_size < 8:
            raise ConfigurationError(
                f"bearer token file {path}: the NTFS ACL is truncated. "
                f"Fix the ACL with: {icacls_fix_command(path)}"
            )
        raw = ctypes.string_at(dacl.value, acl_size)
        try:
            entries = parse_acl(raw)
        except ValueError as exc:
            raise ConfigurationError(
                f"bearer token file {path}: the NTFS ACL could not be read ({exc}). "
                f"Fix the ACL with: {icacls_fix_command(path)}"
            ) from exc
        named: list[AclEntry] = []
        for entry in entries:
            named.append(
                AclEntry(
                    sid=entry.sid,
                    ace_type=entry.ace_type,
                    mask=entry.mask,
                    flags=entry.flags,
                    name=_lookup_sid(advapi32, raw, entry),
                )
            )
        return named
    finally:
        if descriptor.value:
            kernel32.LocalFree(descriptor)


def read_current_user_sid() -> str:
    """SID of the process token user."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise ConfigurationError("could not read the current user SID for the bearer ACL check")
    try:
        advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        needed = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))  # TokenUser
        if needed.value == 0:
            raise ConfigurationError("could not read the current user SID for the bearer ACL check")
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise ConfigurationError("could not read the current user SID for the bearer ACL check")
        # TOKEN_USER starts with a pointer-sized SID.
        sid_ptr = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value
        if not sid_ptr:
            raise ConfigurationError("could not read the current user SID for the bearer ACL check")
        return _sid_to_text(advapi32, kernel32, sid_ptr)
    finally:
        kernel32.CloseHandle(token)


def _parse_ace(ace_type: int, flags: int, ace: bytes) -> AclEntry:
    if len(ace) < 8:
        raise ValueError("ACE is short")
    mask = int.from_bytes(ace[4:8], "little")
    sid_at = _sid_offset(ace_type, ace)
    sid = _sid_string(ace[sid_at:])
    return AclEntry(sid=sid, ace_type=ace_type, mask=mask, flags=flags)


def _sid_offset(ace_type: int, ace: bytes) -> int:
    if ace_type in {0, 1, 9, 10}:
        return 8
    if ace_type in {5, 6, 11, 12}:
        if len(ace) < 12:
            raise ValueError("object ACE is short")
        object_flags = int.from_bytes(ace[8:12], "little")
        offset = 12
        if object_flags & 0x1:
            offset += 16
        if object_flags & 0x2:
            offset += 16
        return offset
    return 8


def _sid_string(blob: bytes) -> str:
    if len(blob) < 8:
        raise ValueError("SID is short")
    revision = blob[0]
    count = blob[1]
    if revision != 1 or count > 15:
        raise ValueError("SID revision is not 1")
    need = 8 + 4 * count
    if len(blob) < need:
        raise ValueError("SID is short")
    authority = int.from_bytes(blob[2:8], "big")
    parts = [f"S-{revision}-{authority}"]
    for index in range(count):
        start = 8 + 4 * index
        parts.append(str(int.from_bytes(blob[start : start + 4], "little")))
    return "-".join(parts)


def _lookup_sid(advapi32: ctypes.WinDLL, acl_bytes: bytes, entry: AclEntry) -> str:
    """Best-effort account name. A miss keeps the SID for the error text."""
    del acl_bytes, entry
    # Names are filled by the caller when it still holds the SID pointer.
    # Parsing from bytes has no SID pointer, so the well-known map is the label.
    return ""


def _sid_to_text(advapi32: ctypes.WinDLL, kernel32: ctypes.WinDLL, sid_ptr: int) -> str:
    convert = advapi32.ConvertSidToStringSidW
    convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    convert.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    text_ptr = ctypes.c_void_p()
    if not convert(sid_ptr, ctypes.byref(text_ptr)) or not text_ptr.value:
        raise ConfigurationError("could not format the current user SID")
    try:
        return ctypes.wstring_at(text_ptr.value)
    finally:
        kernel32.LocalFree(text_ptr)
