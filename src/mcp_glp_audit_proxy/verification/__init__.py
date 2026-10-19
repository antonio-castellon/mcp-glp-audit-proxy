"""Verification evidence for the Community edition.

The reports here support a customer's own computerised-system work.
They are designed to support GLP / 21 CFR Part 11 / EU GMP Annex 11 workflows.
"""

from __future__ import annotations

__all__ = ["load_rtm"]


def load_rtm():
    from .rtm import load_rtm as _load

    return _load()
