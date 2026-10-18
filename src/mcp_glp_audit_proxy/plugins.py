"""Entry-point loader shared by Community and a future Pro package."""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any


def load_group(group: str) -> dict[str, Any]:
    """Return {entry point name: loaded object} for one group.

    Missing groups return an empty dict. Nothing here contacts a network.
    """
    discovered = entry_points()
    selected = discovered.select(group=group) if hasattr(discovered, "select") else discovered.get(group, [])
    loaded: dict[str, Any] = {}
    for item in selected:
        loaded[item.name] = item.load()
    return loaded
