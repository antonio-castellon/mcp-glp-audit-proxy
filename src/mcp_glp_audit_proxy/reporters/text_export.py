"""Plain-text rendering of audit entries for the verify CLI."""

from __future__ import annotations

from typing import Any


def text_reporter(_settings: Any, options: dict[str, Any] | None = None) -> TextReporter:
    """Entry point factory. Pro reporters use (settings, options=).

    Community ignores ``options``. The mapping is plugins.reporters.options.text.
    """
    del options
    return TextReporter()


text_reporter.licence_feature = "report.text"


class TextReporter:
    name = "text"
    licence_feature = "report.text"
    media_type = "text/plain"

    def render(self, document: dict[str, Any]) -> bytes:
        lines = [format_entry(entry) for entry in document.get("entries", [])]
        manifest = document.get("manifest") or {}
        lines.append(
            "manifest "
            f"count={manifest.get('exported_count')} "
            f"head={manifest.get('full_head_hash')} "
            f"chain_valid={manifest.get('chain_valid')} "
            f"complete={manifest.get('complete')}"
        )
        return ("\n".join(lines) + "\n").encode("ascii", errors="replace")


def format_entry(entry: dict[str, Any]) -> str:
    principal = entry.get("principal") or {}
    tool = entry.get("tool") or "-"
    return (
        f"seq={entry.get('seq')} time={entry.get('timestamp')} "
        f"class={entry.get('record_class')} status={entry.get('status')} "
        f"principal={principal.get('id')} role={principal.get('role')} "
        f"method={entry.get('method')} tool={tool} server={entry.get('server')}"
    )
