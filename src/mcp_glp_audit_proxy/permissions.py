"""Modes for the audit log, its sidecar, and files this process creates.

A new log directory is 0700. An existing directory is left alone. The log and
the sidecar are set to 0600 on open. A change to an existing file is logged.
"""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path

_LOG = logging.getLogger("mcp_glp_audit_proxy.technical")


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` when it is missing. The directory this call creates is 0700."""
    if path.is_dir():
        return
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def tighten_fd(fd: int, label: str, *, warn: bool) -> None:
    """Set an open file to 0600. Warn when an existing mode had to change."""
    try:
        current = os.fstat(fd).st_mode & 0o777
    except OSError as exc:
        if warn:
            _LOG.warning("could not read mode of %s: %s", label, exc)
        return
    if current == 0o600:
        return
    try:
        os.fchmod(fd, 0o600)
    except OSError as exc:
        if warn:
            _LOG.warning("could not set %s from mode %03o to 0600: %s", label, current, exc)
        return
    if warn:
        _LOG.warning("set %s from mode %03o to 0600", label, current)


def open_flags(base: int) -> int:
    """OR ``O_BINARY`` so Windows does not turn LF into CRLF."""
    return base | getattr(os, "O_BINARY", 0)


def open_private(path: Path, flags: int) -> int:
    """Open ``path`` and set it to 0600. An existing loose mode is warned about."""
    flags = open_flags(flags)
    existed = path.exists()
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno != errno.EACCES or not path.is_file():
            raise
        read_fd = os.open(path, open_flags(os.O_RDONLY))
        try:
            tighten_fd(read_fd, str(path), warn=True)
        finally:
            os.close(read_fd)
        fd = os.open(path, flags, 0o600)
        existed = True
    try:
        # Windows cannot store 0600. A failed fchmod must not refuse the open.
        if existed or os.name == "nt":
            tighten_fd(fd, str(path), warn=True)
        else:
            os.fchmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise
    return fd


def tighten_path(path: Path) -> None:
    """Set an existing file to 0600 when this process can open it."""
    if not path.is_file():
        return
    try:
        fd = os.open(path, open_flags(os.O_RDWR))
    except OSError as exc:
        if exc.errno not in {errno.EACCES, errno.EPERM}:
            return
        try:
            fd = os.open(path, open_flags(os.O_RDONLY))
        except OSError:
            return
    try:
        tighten_fd(fd, str(path), warn=True)
    finally:
        os.close(fd)
