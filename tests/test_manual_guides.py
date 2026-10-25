"""Smoke-test every manual-guide snippet against the real parser and process.

Proxy JSON is loaded with load_settings and, where it can run here, started
over stdio. Client JSON is checked for the real --config flag. Bash snippets
may only pass flags that --help actually prints.
"""

from __future__ import annotations

import ast
import asyncio
import copy
import json
import os
import re
import select
import subprocess
import sys
import textwrap
import threading
import zipfile
from pathlib import Path

import pytest
import yaml

from mcp_glp_audit_proxy.cli import main as verify_main
from mcp_glp_audit_proxy.config import load_settings
from mcp_glp_audit_proxy.tlsutil import require_https

ROOT = Path(__file__).resolve().parents[1]
GUIDES = ROOT / "docs" / "manual-guides"
FAKE = Path(__file__).resolve().parent / "fake_upstream_server.py"
FENCE = re.compile(r"```([^\n]*)\n(.*?)```", re.DOTALL)
HEADINGS = (
    "## Prerequisites",
    "## Install",
    "## Minimal config",
    "## Hardened config",
    "## Verification",
    "## Pitfalls",
)
BANNED = ("certified", "compliant", "validated")
PRIVATE = "https://github.com/antonio-castellon/" + "mcp-glp-audit-proxy-pro"
GLP_ENV = {
    "GLP_CONFIG",
    "GLP_PRINCIPAL_ID",
    "GLP_PRINCIPAL_NAME",
    "GLP_PRINCIPAL_ROLE",
    "GLP_AUDIT_PATH",
    "GLP_FAIL_CLOSED",
    "GLP_LICENCE_PATH",
    "GLP_REQUIRE_NTP",
}
INVENTED = ("--port", "--http", "--stdio", "--listen", "--host", "--daemon", "--cert")


def _guides() -> list[Path]:
    return sorted(GUIDES.rglob("*.md"))


def _fences(path: Path) -> list[tuple[str, str]]:
    text = path.read_text(encoding="utf-8")
    return [(info.strip(), body.strip("\n") + "\n") for info, body in FENCE.findall(text)]


def _help_flags(import_path: str) -> set[str]:
    completed = subprocess.run(
        [sys.executable, "-c", f"from {import_path} import main; main(['--help'])"],
        check=False,
        capture_output=True,
        text=True,
    )
    # argparse exits 0 after printing help. main() may raise SystemExit.
    assert completed.returncode == 0, completed.stderr
    return set(re.findall(r"--[a-z0-9][a-z0-9-]*", completed.stdout)) | {"--help"}


@pytest.fixture(scope="module")
def help_flags() -> dict[str, set[str]]:
    return {
        "proxy": _help_flags("mcp_glp_audit_proxy.server"),
        "verify": _help_flags("mcp_glp_audit_proxy.cli"),
        "oq": _help_flags("mcp_glp_audit_proxy.verification.oq"),
    }


def test_readme_links_the_manuals() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/manual-guides/README.md" in readme
    assert "reachable only through this proxy" in readme


def test_guides_are_ascii_and_use_the_allowed_words() -> None:
    names = {path.name for path in _guides()}
    assert "README.md" in names
    assert len(names) >= 17
    for path in _guides():
        text = path.read_text(encoding="utf-8")
        text.encode("ascii")
        lowered = text.lower()
        for word in BANNED:
            assert word not in lowered, f"{path.name} contains {word}"
        assert PRIVATE not in text
        # QUICKSTART.md is the terminal audit, not a host page.
        if path.name not in {"README.md", "QUICKSTART.md"}:
            for heading in HEADINGS:
                assert heading in text, f"{path.name} missing {heading}"
        for invented in INVENTED:
            assert invented not in text, path.name


def test_proxy_configs_load_and_start(tmp_path: Path) -> None:
    seen = 0
    for path in _guides():
        for info, body in _fences(path):
            if not info.startswith("json proxy"):
                continue
            seen += 1
            raw = json.loads(body)
            config_path = tmp_path / f"{path.stem}-{seen}.json"
            config_path.write_text(json.dumps(raw), encoding="utf-8")
            loaded = load_settings(config_path)
            assert loaded.principal.role in {"operator", "approver", "qa", "admin"}
            _exercise(raw, tmp_path / f"run-{path.stem}-{seen}")
    assert seen >= 10


def test_manuals_do_not_ship_the_retired_json_licence() -> None:
    for path in _guides():
        text = path.read_text(encoding="utf-8")
        assert "mcp-glp-audit-proxy-licence" not in text
        assert "json licence" not in text
        for info, _body in _fences(path):
            assert not info.startswith("json licence")


def test_client_snippets_use_real_proxy_args() -> None:
    seen = 0
    for path in _guides():
        for info, body in _fences(path):
            if not info.startswith("json client"):
                continue
            seen += 1
            raw = json.loads(body)
            servers = raw.get("mcpServers", raw.get("servers"))
            assert isinstance(servers, dict) and servers
            for name, spec in servers.items():
                assert isinstance(spec, dict), name
                command = str(spec.get("command") or "")
                args = [str(item) for item in spec.get("args") or []]
                assert command
                env = spec.get("env") or {}
                for key in env:
                    if key.startswith("GLP_"):
                        assert key in GLP_ENV
                if "mcp-glp-audit-proxy" in command or "mcp_glp_audit_proxy" in " ".join(args):
                    flags = [item for item in args if item.startswith("--")]
                    assert flags == ["--config"] or flags == []
                    if "--config" in args:
                        assert args[args.index("--config") + 1]
                if command == "docker":
                    assert "-p" not in args
                    # The discovery image bakes --config into CMD. A lab run passes it.
                    if "--config" in args:
                        assert args[args.index("--config") + 1]
    assert seen >= 8


def test_rpc_and_yaml_snippets_parse() -> None:
    rpc = 0
    continue_yaml = 0
    for path in _guides():
        for info, body in _fences(path):
            if info.startswith("json rpc"):
                rpc += 1
                message = json.loads(body)
                assert message["jsonrpc"] == "2.0"
                assert message["method"] == "tools/call"
            if info.startswith("yaml continue"):
                continue_yaml += 1
                parsed = yaml.safe_load(body)
                assert parsed["schema"] == "v1"
                assert isinstance(parsed["mcpServers"], list)
    assert rpc >= 3
    assert continue_yaml >= 2


def test_python_snippets_parse() -> None:
    seen = 0
    for path in _guides():
        for info, body in _fences(path):
            if not info.startswith("python"):
                continue
            seen += 1
            ast.parse(textwrap.dedent(body))
    assert seen >= 4


def test_bash_flags_match_help(help_flags: dict[str, set[str]]) -> None:
    checked = 0
    for path in _guides():
        for info, body in _fences(path):
            if not info.startswith("bash"):
                continue
            for line in body.splitlines():
                if line.strip().startswith("#"):
                    continue
                tokens = line.replace("|", " ").split()
                mode: set[str] | None = None
                previous = ""
                for token in tokens:
                    if token in {"mcp-glp-audit-proxy-verify"} or token.endswith("mcp-glp-audit-proxy-verify"):
                        mode = help_flags["verify"]
                    elif token == "mcp-glp-audit-proxy" or token.endswith("/mcp-glp-audit-proxy"):
                        mode = help_flags["proxy"]
                    elif previous == "-m" and token == "mcp_glp_audit_proxy":
                        mode = help_flags["proxy"]
                    elif previous == "-m" and token == "mcp_glp_audit_proxy.verification.oq":
                        mode = help_flags["oq"]
                    elif token == "oq-report" and mode == help_flags["proxy"]:
                        mode = help_flags["oq"]
                    elif token == "verify" and mode == help_flags["proxy"]:
                        mode = help_flags["verify"]
                    elif token.startswith("--") and mode is not None:
                        assert token in mode, f"{path.name}: {token} not in {sorted(mode)}"
                        checked += 1
                    previous = token
    assert checked >= 5


def test_dockerfile_matches_the_guide_and_has_no_port() -> None:
    dockerfile = (GUIDES / "docker" / "Dockerfile").read_text(encoding="utf-8")
    dockerfile.encode("ascii")
    assert "EXPOSE" not in dockerfile
    assert 'ENTRYPOINT ["mcp-glp-audit-proxy"]' in dockerfile
    assert 'CMD ["--config", "/app/discovery.config.json"]' in dockerfile
    assert "USER proxy" in dockerfile
    guide = (GUIDES / "docker.md").read_text(encoding="utf-8")
    fenced = [body for info, body in _fences(GUIDES / "docker.md") if info.startswith("dockerfile")]
    assert len(fenced) == 1
    assert fenced[0].strip() == dockerfile.strip()
    discovery = json.loads((GUIDES / "docker" / "discovery.config.json").read_text(encoding="utf-8"))
    embedded = [
        json.loads(body)
        for info, body in _fences(GUIDES / "docker.md")
        if info.startswith("json proxy") and '"discovery"' in body
    ]
    assert embedded == [discovery]
    assert "reachable only through the proxy" in guide or "only through the proxy" in guide
    loaded_dir = GUIDES / "docker"
    # load_settings resolves relative paths next to the file. This one is absolute.
    copy_path = loaded_dir / "discovery.config.json"
    settings = load_settings(copy_path)
    assert settings.principal.role == "qa"
    assert settings.upstreams == []


def test_official_sdk_handshake(tmp_path: Path) -> None:
    """The python-sdk.md minimal shape: StdioServerParameters env plus initialize."""
    raw = _first_proxy(GUIDES / "generic-stdio.md")
    config = _prepare(raw, tmp_path)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def run() -> str:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_glp_audit_proxy", "--config", str(path)],
            env={
                "GLP_PRINCIPAL_ID": "operator-1",
                "GLP_PRINCIPAL_NAME": "Ada Analyst",
                "GLP_PRINCIPAL_ROLE": "operator",
            },
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                await session.list_tools()
                return init.server_info.name

    assert asyncio.run(run()) == "mcp-glp-audit-proxy"


def test_airgap_wheel_builds_without_deps(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(tmp_path), str(ROOT)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    wheels = list(tmp_path.glob("mcp_glp_audit_proxy-*.whl"))
    assert len(wheels) == 1
    assert "0.4.0" in wheels[0].name
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
    assert any(name.endswith("mcp_glp_audit_proxy/release_trust.json") for name in names)


def _first_proxy(path: Path) -> dict:
    for info, body in _fences(path):
        if info.startswith("json proxy"):
            return json.loads(body)
    raise AssertionError(path)


def _prepare(raw: dict, directory: Path) -> dict:
    config = copy.deepcopy(raw)
    directory.mkdir(parents=True, exist_ok=True)
    audit = config.setdefault("audit", {})
    audit["path"] = str(directory / "audit.jsonl")
    config["export_dir"] = str(directory / "exports")
    if config.get("licence_path"):
        config["licence_path"] = None
    for item in config.get("upstreams") or []:
        if item.get("transport", "stdio") == "https":
            require_https(str(item["url"]))
            continue
        item["command"] = sys.executable
        item["args"] = [str(FAKE), "legacy"]
        item["cwd"] = str(directory)
    return config


def _exercise(raw: dict, directory: Path) -> None:
    config = _prepare(raw, directory)
    if config.get("listen"):
        return
    https = any(item.get("transport") == "https" for item in config.get("upstreams") or [])
    path = directory / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GLP_"):
            env.pop(key)
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "--config", str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=directory,
    )
    stderr: list[str] = []

    def _drain() -> None:
        assert proc.stderr is not None
        stderr.append(proc.stderr.read())

    threading.Thread(target=_drain, daemon=True).start()
    try:
        init = _rpc(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "manual", "version": "0"},
                },
            },
            stderr,
        )
        assert init["result"]["serverInfo"]["name"] == "mcp-glp-audit-proxy"
        if not https:
            listed = _rpc(
                proc,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                stderr,
            )
            assert "error" not in listed, stderr
            assert "tools" in listed["result"]
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    code = verify_main([str(directory / "audit.jsonl"), "--print-head"])
    assert code == 0, stderr


def _rpc(proc: subprocess.Popen, message: dict, stderr: list[str], timeout: float = 20) -> dict:
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    if not ready:
        raise AssertionError(f"no response for {message.get('method')}: {stderr}")
    line = proc.stdout.readline()
    if not line:
        raise AssertionError(f"stdout closed: {stderr} rc={proc.poll()}")
    return json.loads(line)
