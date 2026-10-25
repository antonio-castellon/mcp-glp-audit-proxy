"""stdio entrypoint. Identity comes from the environment, per the MCP auth spec."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
from typing import Any

from mcp.client.stdio import StdioServerParameters

from .config import Settings, load_settings
from .chain import integrity_text
from .errors import AuditStoreError, ChainIntegrityError, ConfigurationError
from .features import FeatureSet
from .framing import BoundedLineReader, LineTooLong
from .proxy import MAX_MESSAGE_BYTES, AuditProxy
from .sdkcheck import assert_mcp_floor
from .upstream import HttpsTransport, JsonRpcUpstream, StdioTransport
from .wiring import apply_identity, build_components


def build_proxy(settings: Settings, features: FeatureSet | None = None) -> AuditProxy:
    flags = features or FeatureSet.load(settings.licence_path, client_id=settings.client_id)
    settings.validate()
    apply_identity(settings, flags)
    store, reporters = build_components(settings, flags)
    upstreams = [_build_upstream(item, settings) for item in settings.upstreams or []]
    return AuditProxy(settings, store, upstreams, features=flags, reporters=reporters)


def serve_stdio(proxy: AuditProxy) -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )
    previous = _install_stop_signals(proxy)
    try:
        _serve_stdio_loop(proxy)
    finally:
        _restore_stop_signals(previous)


def _serve_stdio_loop(proxy: AuditProxy) -> None:
    try:
        proxy.startup()
    except ChainIntegrityError as exc:
        print(f"mcp-glp-audit-proxy: refusing to start: {integrity_text(exc.report or _empty_report(exc))}", file=sys.stderr)
        raise SystemExit(3) from exc
    except (ConfigurationError, AuditStoreError) as exc:
        print(f"mcp-glp-audit-proxy: refusing to start: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    if proxy.features.unavailable:
        print(
            "mcp-glp-audit-proxy: licence requested features with no plugin: "
            + ", ".join(proxy.features.unavailable),
            file=sys.stderr,
        )
    reader = BoundedLineReader(sys.stdin.buffer, MAX_MESSAGE_BYTES)
    try:
        while True:
            try:
                raw = reader.readline()
            except LineTooLong:
                # Stop. Do not read until the next newline.
                _end_unbounded(proxy)
                raise SystemExit(1)
            if not raw:
                break
            if not raw.strip():
                continue
            try:
                message = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                _write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
                continue
            if not isinstance(message, dict):
                _write({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}})
                continue
            try:
                proxy.maybe_check_integrity()
                response = proxy.handle(message)
            except ChainIntegrityError as exc:
                report = getattr(exc, "report", None) or _empty_report(exc)
                proxy._break_integrity(report)
                print(f"mcp-glp-audit-proxy: {integrity_text(report)}", file=sys.stderr)
                raise SystemExit(3) from exc
            except Exception as exc:  # last resort: do not forward, do not die silently
                if proxy.settings.fail_closed:
                    proxy._dead = True
                logging.getLogger("mcp_glp_audit_proxy.technical").exception("proxy handle failed")
                response = {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {
                        "code": -32000,
                        "message": "audit log unavailable; request was not completed",
                        "data": {"detail": str(exc), "reason": "fail_closed"},
                    },
                }
            if response is not None:
                _write(response)
            if proxy._integrity_stop:
                raise SystemExit(3)
    finally:
        if not proxy._integrity_broken:
            proxy.shutdown("eof")
        proxy.close()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="mcp-glp-audit-proxy")
    parser.add_argument(
        "--config",
        default=os.environ.get("GLP_CONFIG", "config.json"),
        help="Path to the JSON config file",
    )
    args = parser.parse_args(argv)
    try:
        assert_mcp_floor()
        settings = load_settings(args.config)
        proxy = build_proxy(settings)
    except (ConfigurationError, OSError, ValueError, RuntimeError) as exc:
        print(f"mcp-glp-audit-proxy: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    if settings.listen is not None:
        from .channels.https_inbound import serve_https

        serve_https(proxy, settings)
        return
    serve_stdio(proxy)


def _end_unbounded(proxy: AuditProxy) -> None:
    """Refuse a stream that never framed a message, then end the session."""
    logging.getLogger("mcp_glp_audit_proxy.technical").error(
        "message exceeds size limit without a newline; ending session"
    )
    if proxy.settings.fail_closed:
        proxy._dead = True
    response = proxy.reject_oversized_line(MAX_MESSAGE_BYTES + 1)
    if response is not None:
        _write(response)


def _build_upstream(item: Any, settings: Any | None = None) -> Any:
    kind = getattr(item, "kind", "mcp")
    if kind in {"api", "llm"}:
        from .channels.api_upstream import ApiUpstream

        if not item.url:
            raise ConfigurationError(f"upstream {item.name}: https transport requires url")
        body_mode = getattr(settings, "body_mode", "hash_only")
        redact_paths = getattr(settings, "redact_paths", ())
        max_body = getattr(settings, "max_body_bytes", 1_048_576)
        return ApiUpstream(
            name=item.name,
            kind=kind,
            url=item.url,
            ca_file=item.ca_file,
            headers=item.headers,
            timeout=item.timeout if item.timeout is not None else 30.0,
            endpoints=list(item.endpoints),
            body_mode=body_mode,
            redact_paths=redact_paths,
            max_body_bytes=max_body,
        )
    if item.transport == "https":
        if not item.url:
            raise ConfigurationError(f"upstream {item.name}: https transport requires url")
        timeout = item.timeout if item.timeout is not None else 30.0
        transport = HttpsTransport(item.url, item.headers, timeout=timeout, ca_file=item.ca_file)
    else:
        if not item.command:
            raise ConfigurationError(f"upstream {item.name}: stdio transport requires command")
        params = StdioServerParameters(
            command=item.command,
            args=list(item.args or []),
            env=dict(item.env or {}),
            cwd=item.cwd,
        )
        transport = StdioTransport(params, timeout=item.timeout if item.timeout is not None else 60.0)
    return JsonRpcUpstream(item.name, transport, item.protocol)


def _empty_report(exc: ChainIntegrityError) -> Any:
    report = getattr(exc, "report", None)
    if report is not None:
        return report
    from .chain import VerifyReport

    return VerifyReport(ok=False, errors=[str(exc)], kind="edited")


def _install_stop_signals(proxy: AuditProxy) -> list[tuple[int, Any]]:
    if threading.current_thread() is not threading.main_thread():
        return []
    previous: list[tuple[int, Any]] = []

    def _stop(signum: int, _frame: Any) -> None:
        name = signal.Signals(signum).name
        proxy.shutdown(f"signal:{name}")
        raise SystemExit(0)

    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            previous.append((signum, signal.getsignal(signum)))
            signal.signal(signum, _stop)
        except (ValueError, OSError):
            continue
    return previous


def _restore_stop_signals(previous: list[tuple[int, Any]]) -> None:
    for signum, handler in previous:
        try:
            signal.signal(signum, handler)
        except (ValueError, OSError):
            continue


def _write(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()
