"""In-process stdio loop, HTTPS error paths, and small reporters."""

from __future__ import annotations

import base64
import io
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_glp_audit_proxy.anchor import verify_anchored
from mcp_glp_audit_proxy.canonical import canonicalize
from mcp_glp_audit_proxy.config import Settings, UpstreamConfig
from mcp_glp_audit_proxy.errors import ConfigurationError, LicenceError, TlsRequired, UpstreamError
from mcp_glp_audit_proxy.features import FeatureSet
from mcp_glp_audit_proxy.licence import licence_fingerprint
from mcp_glp_audit_proxy.proxy import AuditProxy
from mcp_glp_audit_proxy.reporters.text_export import TextReporter
from mcp_glp_audit_proxy.server import _build_upstream, main as server_main, serve_stdio
from mcp_glp_audit_proxy.signers.unsigned import UnsignedSigner
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore
from mcp_glp_audit_proxy import upstream as upstream_mod
from mcp_glp_audit_proxy.upstream import HttpsTransport
from mcp_glp_audit_proxy.verification import __main__ as verification_main
from mcp_glp_audit_proxy.verification import rtm as rtm_mod

from conftest import Clock, assemble


def test_serve_stdio_session_parse_and_call(tmp_path: Path, monkeypatch) -> None:
    stack = assemble(tmp_path)
    proxy = stack["proxies"]["operator"]
    payload = "\n".join(
        [
            "",
            "not-json",
            "[]",
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {"name": "excel__read_cell", "arguments": {"cell": "C3"}},
                }
            ),
        ]
    ) + "\n"
    _bind_stdio(monkeypatch, payload.encode("utf-8"))
    serve_stdio(proxy)
    text = sys.stdout.getvalue()
    assert "parse error" in text
    assert "invalid request" in text
    assert "C3" in text


def test_serve_stdio_ends_a_newline_less_stream(tmp_path: Path, monkeypatch) -> None:
    import mcp_glp_audit_proxy.server as server_mod

    stack = assemble(tmp_path)
    proxy = stack["proxies"]["operator"]
    monkeypatch.setattr(server_mod, "MAX_MESSAGE_BYTES", 8)
    _bind_stdio(monkeypatch, b"0123456789ABCDEF")
    with pytest.raises(SystemExit) as caught:
        serve_stdio(proxy)
    assert caught.value.code == 1
    assert "message exceeds size limit" in sys.stdout.getvalue()
    assert proxy._dead is True
    report = verify_anchored(stack["store"].path)
    assert report.ok, report.errors


def test_serve_stdio_refuses_a_disagreeing_head(tmp_path: Path, monkeypatch, capsys) -> None:
    stack = assemble(tmp_path)
    path = stack["store"].path
    path.write_bytes(b"")
    clock = stack["clock"]
    settings = stack["proxies"]["operator"].settings
    proxy = AuditProxy(
        settings,
        JsonlAuditStore(path, checkpoint_every=0, now=clock),
        [],
        now=clock,
        clock_probe=lambda: {"detail": "yes", "ntp_synchronized": True, "source": "test"},
    )
    _bind_stdio(monkeypatch, b"")
    with pytest.raises(SystemExit) as caught:
        serve_stdio(proxy)
    assert caught.value.code == 1
    assert "refusing to start" in capsys.readouterr().err


def test_serve_stdio_last_resort_and_unknown_licence(tmp_path: Path, monkeypatch, capsys) -> None:
    stack = assemble(tmp_path)
    proxy = stack["proxies"]["operator"]

    def boom(_message):
        raise RuntimeError("boom")

    proxy.handle = boom  # type: ignore[method-assign]
    _bind_stdio(monkeypatch, b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
    serve_stdio(proxy)
    assert "fail_closed" in sys.stdout.getvalue()
    assert proxy._dead is True

    unsigned = tmp_path / "unsigned.json"
    unsigned.write_text(
        json.dumps({"format": "mcp-glp-audit-proxy-licence", "features": ["not-a-feature"]}),
        encoding="utf-8",
    )
    with pytest.raises(LicenceError, match="signature is required"):
        FeatureSet.load(unsigned)

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    body = {
        "format": "mcp-glp-audit-proxy-licence",
        "features": ["not-a-feature"],
        "fingerprint": licence_fingerprint("lab-1", []),
    }
    body["signature"] = {
        "algorithm": "ed25519",
        "key_id": "test",
        "value": base64.b64encode(private.sign(canonicalize(body))).decode("ascii"),
    }
    licence = tmp_path / "licence.json"
    licence.write_text(json.dumps(body), encoding="utf-8")
    flagged = AuditProxy(
        stack["proxies"]["qa"].settings,
        stack["store"],
        [],
        features=FeatureSet.load(licence, public_key=public, client_id="lab-1"),
        now=stack["clock"],
        clock_probe=lambda: {"detail": "yes", "ntp_synchronized": True, "source": "test"},
    )
    _bind_stdio(monkeypatch, b"")
    serve_stdio(flagged)
    assert "not-a-feature" in capsys.readouterr().err


def test_server_main_and_upstream_builders(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        server_main(["--config", str(tmp_path / "missing.json")])
    with pytest.raises(ConfigurationError):
        _build_upstream(UpstreamConfig(name="excel", transport="https", url=None))
    with pytest.raises(ConfigurationError):
        _build_upstream(UpstreamConfig(name="excel", transport="stdio", command=None))


def test_https_transport_errors(monkeypatch) -> None:
    with pytest.raises(TlsRequired):
        HttpsTransport("http://example.test/mcp")

    class Response:
        def __init__(self, body: bytes, session: str | None = "sess") -> None:
            self._body = body
            self.headers = {"Mcp-Session-Id": session} if session else {}

        def read(self) -> bytes:
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> bool:
            return False

    monkeypatch.setattr(upstream_mod, "urlopen", lambda *_a, **_k: Response(b'{"ok": true}'))
    transport = HttpsTransport("https://example.test/mcp", {"authorization": "secret"})
    transport.send({"jsonrpc": "2.0", "id": 1, "method": "ping"}, session_id="sess")
    assert transport.receive() == {"ok": True}
    assert transport.response_session_id == "sess"
    transport.close()

    monkeypatch.setattr(upstream_mod, "urlopen", lambda *_a, **_k: Response(b""))
    transport.send({"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert transport.receive() == {}

    monkeypatch.setattr(upstream_mod, "urlopen", lambda *_a, **_k: Response(b"["))
    with pytest.raises(UpstreamError, match="non-JSON"):
        transport.send({"jsonrpc": "2.0", "id": 3, "method": "ping"})

    monkeypatch.setattr(upstream_mod, "urlopen", lambda *_a, **_k: Response(b"[1]"))
    with pytest.raises(UpstreamError, match="non-object"):
        transport.send({"jsonrpc": "2.0", "id": 4, "method": "ping"})

    def explode(*_args, **_kwargs):
        raise OSError("network down")

    monkeypatch.setattr(upstream_mod, "urlopen", explode)
    with pytest.raises(UpstreamError, match="https upstream failed"):
        transport.send({"jsonrpc": "2.0", "id": 5, "method": "ping"})
    with pytest.raises(UpstreamError, match="nothing"):
        transport.receive()


def test_text_reporter_and_unsigned_signer() -> None:
    rendered = TextReporter().render(
        {
            "entries": [{"seq": 1, "timestamp": "t", "record_class": "access", "status": "ok", "method": "ping"}],
            "manifest": {"exported_count": 1, "full_head_hash": "ab", "chain_valid": True, "complete": True},
        }
    )
    assert b"manifest " in rendered
    signer = UnsignedSigner()
    signature = signer.sign(b"{}")
    assert signer.verify(b"{}", signature) is True
    assert signer.verify(b"{}", {"signed": True, "value": "x"}) is False
    with pytest.raises(TypeError):
        signer.sign("nope")  # type: ignore[arg-type]


def test_empty_log_with_a_head_fails(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b"")
    head = path.with_name(path.name + ".head")
    head.write_text('{"seq": true, "entry_hash": "' + ("ab" * 32) + '"}\n', encoding="utf-8")
    with pytest.raises(Exception, match="seq is invalid"):
        from mcp_glp_audit_proxy.anchor import read_head

        read_head(path)
    head.write_text("[]\n", encoding="utf-8")
    report = verify_anchored(path)
    assert report.ok is False
    assert any("not an object" in error or "unreadable" in error for error in report.errors)
    head.write_text(json.dumps({"seq": 1, "entry_hash": "ab" * 32}) + "\n", encoding="utf-8")
    report = verify_anchored(path)
    assert report.ok is False
    assert any("empty" in error for error in report.errors)


def test_rtm_cli_and_junit_statuses(tmp_path: Path, capsys, monkeypatch) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(
        """<?xml version="1.0" ?>
<testsuite>
  <testcase classname="tests.test_x" name="test_fail"><failure message="no"/></testcase>
  <testcase classname="tests.test_x" name="test_err"><error message="no"/></testcase>
  <testcase classname="tests.test_x" name="test_skip"><skipped message="no"/></testcase>
</testsuite>
""",
        encoding="utf-8",
    )
    found = rtm_mod.junit_results(junit)
    assert found["tests/test_x.py::test_fail"] == "fail"
    assert found["tests/test_x.py::test_err"] == "error"
    assert found["tests/test_x.py::test_skip"] == "skip"
    assert rtm_mod.main([]) == 2
    assert rtm_mod.main([str(junit)]) == 1
    monkeypatch.setattr(rtm_mod, "community_gaps", lambda *_a, **_k: [])
    assert rtm_mod.main([str(junit)]) == 0
    assert "traceability ok" in capsys.readouterr().out

    bad = tmp_path / "rtm.yaml"
    bad.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError):
        rtm_mod.load_rtm(bad)


def test_verification_package_loads_the_matrix() -> None:
    from mcp_glp_audit_proxy.verification import load_rtm

    loaded = load_rtm()
    assert loaded["requirements"]


def test_verification_module_entry(tmp_path: Path, monkeypatch) -> None:
    case = tmp_path / "test_ok_case.py"
    case.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    monkeypatch.setattr(
        "mcp_glp_audit_proxy.verification.oq.community_gaps",
        lambda *_a, **_k: [],
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verification",
            "--junit",
            str(tmp_path / "junit.xml"),
            "--markdown",
            str(tmp_path / "oq.md"),
            "--json",
            str(tmp_path / "oq.json"),
            "--coverage-json",
            str(tmp_path / "coverage.json"),
            "--pytest-arg",
            str(case),
        ],
    )
    with pytest.raises(SystemExit) as caught:
        verification_main.run()
    assert caught.value.code == 0


def _bind_stdio(monkeypatch, payload: bytes) -> None:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8"))
    monkeypatch.setattr(sys, "stdout", io.StringIO())
