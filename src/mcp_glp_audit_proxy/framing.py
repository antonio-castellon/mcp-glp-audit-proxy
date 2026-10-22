"""Bounded newline reads.

A peer that never sends a newline must not grow memory without a limit.
Once ``limit`` bytes have arrived with no newline, the read stops and raises
``LineTooLong``. Callers end the session. They do not scan for a later
newline: those bytes are not a framed message, and a newline inside an
untrusted payload would be easy to mistake for the next one.
"""

from __future__ import annotations

import os
import select
import time
from typing import Any

# One mebibyte on the wire. Larger messages are refused and not forwarded.
MAX_MESSAGE_BYTES = 1_048_576


class LineTooLong(Exception):
    def __init__(self, limit: int) -> None:
        super().__init__(f"message exceeds {limit} bytes without a newline")
        self.limit = limit


class BoundedLineReader:
    def __init__(self, stream: Any, limit: int, *, timeout: float | None = None) -> None:
        if limit < 1:
            raise ValueError("limit must be positive")
        self.stream = stream
        self.limit = limit
        self.timeout = timeout
        self._pending = bytearray()

    def readline(self) -> bytes:
        """One line, including its newline, or b'' at EOF.

        A final partial line within the limit is returned without a newline.
        ``LineTooLong`` means the session must stop. ``TimeoutError`` means
        the peer went quiet before a newline.
        """
        deadline = None if self.timeout is None else time.monotonic() + self.timeout
        while True:
            newline = self._pending.find(b"\n")
            if newline != -1:
                length = newline + 1
                if length > self.limit:
                    self._pending.clear()
                    raise LineTooLong(self.limit)
                line = bytes(self._pending[:length])
                del self._pending[:length]
                return line
            if len(self._pending) > self.limit:
                self._pending.clear()
                raise LineTooLong(self.limit)
            chunk = self._read_some(deadline)
            if chunk is None:
                raise TimeoutError(f"timed out after {self.timeout}s")
            if chunk == b"":
                line = bytes(self._pending)
                self._pending.clear()
                if len(line) > self.limit:
                    raise LineTooLong(self.limit)
                return line
            self._pending.extend(chunk)

    def _read_some(self, deadline: float | None) -> bytes | None:
        room = self.limit - len(self._pending) + 1
        if room <= 0:
            return b""
        size = min(65536, room)
        if deadline is None:
            # BufferedReader.read(n) waits for n bytes or EOF. A live stdio
            # session must return as soon as a chunk arrives, so use read1.
            read1 = getattr(self.stream, "read1", None)
            if read1 is not None:
                return read1(size) or b""
            return self.stream.read(size) or b""
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        pipe = _windows_pipe_ready(self.stream, remaining)
        if pipe is False:
            return None
        if pipe is True:
            return os.read(self.stream.fileno(), size)
        ready, _, _ = select.select([self.stream], [], [], remaining)
        if not ready:
            return None
        return os.read(self.stream.fileno(), size)


def _windows_pipe_ready(stream: Any, timeout: float) -> bool | None:
    """Wait until a Windows pipe has data. ``None`` means this is not a pipe.

    ``select`` on a pipe raises ``WinError 10038``. Sockets still use ``select``.
    """
    if os.name != "nt":
        return None
    try:
        import msvcrt

        handle = msvcrt.get_osfhandle(stream.fileno())
    except (OSError, AttributeError, ValueError):
        return None
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.PeekNamedPipe.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    kernel.PeekNamedPipe.restype = wintypes.BOOL
    available = wintypes.DWORD()
    deadline = time.monotonic() + timeout
    while True:
        ok = kernel.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None)
        if not ok:
            err = ctypes.get_last_error()
            if err in (1, 6):
                return None
            if err == 109:
                return True
            if err != 232:
                raise OSError(err, "PeekNamedPipe")
        elif available.value:
            return True
        now = time.monotonic()
        if now >= deadline:
            return False
        time.sleep(min(0.01, deadline - now))
