"""Clock-sync status recorded at startup. Ordering of the log is by sequence, not the clock."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any


def probe_clock() -> dict[str, Any]:
    """Best-effort NTP status. Unknown is recorded; it does not invent a sync."""
    binary = shutil.which("timedatectl")
    if not binary:
        return {
            "detail": "timedatectl not found; operator must sync time (RFC 5905)",
            "ntp_synchronized": None,
            "source": "unverified",
        }
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            [binary, "show", "-p", "NTPSynchronized", "--value"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "detail": f"NTP status not available ({exc.__class__.__name__}); operator must sync time (RFC 5905)",
            "ntp_synchronized": None,
            "source": "unverified",
        }
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "timedatectl failed").strip()
        return {
            "detail": detail,
            "ntp_synchronized": None,
            "source": "unverified",
        }
    value = completed.stdout.strip().lower()
    synced = value == "yes"
    return {
        "detail": completed.stdout.strip(),
        "ntp_synchronized": synced,
        "source": "timedatectl",
    }
