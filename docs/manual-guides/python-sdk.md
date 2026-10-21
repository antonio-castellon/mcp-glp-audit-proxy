# Python agents with the official MCP SDK

The `mcp` package that this proxy depends on (`mcp>=2.2.0,<3`) is the official Python SDK. `ClientSession` and `stdio_client` are exported from `mcp`. Use them to launch the proxy as a child. Do not launch the upstream from the agent. The proxy config's `upstreams` is the only place that command appears.

The SDK's stdio client passes a small environment allow-list plus `StdioServerParameters.env`. Set `GLP_PRINCIPAL_*` in `env`. Setting them only on the parent process does not copy them into the child.

## Prerequisites

- Python 3.11 or newer
- `mcp-glp-audit-proxy` installed (this pulls a compatible `mcp` SDK)
- A proxy `config.json` from [generic-stdio.md](generic-stdio.md)

## Install

```bash
python -m pip install mcp-glp-audit-proxy
```

You do not install a second MCP SDK. The proxy's dependency is the client library.

## Minimal config

```python sdk
import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    params = StdioServerParameters(
        command="mcp-glp-audit-proxy",
        args=["--config", "/srv/glp/config.json"],
        env={
            "GLP_PRINCIPAL_ID": "operator-1",
            "GLP_PRINCIPAL_NAME": "Ada Analyst",
            "GLP_PRINCIPAL_ROLE": "operator",
        },
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            print([tool.name for tool in listed.tools])


if __name__ == "__main__":
    asyncio.run(main())
```

`list_tools` for an `operator` asks every upstream for its tools. The upstream command in the proxy config must be a real MCP server or that call fails.

## Hardened config

Absolute interpreter, a dedicated log, and a read of one tool through the proxy. The approval and allow lists live in the proxy file, not in this script.

```python sdk
import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    params = StdioServerParameters(
        command="/opt/lab/venv/bin/mcp-glp-audit-proxy",
        args=["--config", "/srv/glp/config.json"],
        cwd="/srv/glp",
        env={
            "GLP_PRINCIPAL_ID": "operator-1",
            "GLP_PRINCIPAL_NAME": "Ada Analyst",
            "GLP_PRINCIPAL_ROLE": "operator",
            "GLP_AUDIT_PATH": "/srv/glp/operator-1/audit.jsonl",
        },
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print(init.server_info.name)
            await session.list_tools()


if __name__ == "__main__":
    asyncio.run(main())
```

`cwd` is a `StdioServerParameters` field. It is the proxy process working directory. It is not the upstream's `cwd`. Set that in `upstreams[].cwd` inside `config.json`. The JSON field on the wire is `serverInfo`. This SDK's `InitializeResult` attribute is `server_info`.

Do not construct a second `StdioServerParameters` for the Excel or LIMS server.

## Verification

Run the script. The printed server name is `mcp-glp-audit-proxy`. Then:

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --print-head
```

A direct check without the SDK is the `printf` initialize pipe in [generic-stdio.md](generic-stdio.md).

## Hello world

Audit two calls and one denied call through this host. Copy `examples/config.json` from a checkout and leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. Part 11 signatures are not part of this hello. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install the package the host will launch.

```bash
python -m pip install mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied config with the absolute path of the checkout. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

The script is the client. `principal` in `examples/config.json` is the identity if you omit `env`. This script sets `env` because the SDK does not copy `GLP_*` from the parent.

```python sdk
import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    params = StdioServerParameters(
        command="python",
        args=["-m", "mcp_glp_audit_proxy", "--config", "REPLACE_WITH_ABSOLUTE_PATH/examples/config.json"],
        env={
            "GLP_PRINCIPAL_ID": "operator-1",
            "GLP_PRINCIPAL_NAME": "Ada Analyst",
            "GLP_PRINCIPAL_ROLE": "operator",
        },
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            hello = await session.call_tool("lab__hello", {"name": "Ada"})
            saved = await session.call_tool("lab__save_note", {"text": "bench 1 is clean"})
            denied = await session.call_tool("lab__drop_all", {})
            print(hello, saved, denied)


if __name__ == "__main__":
    asyncio.run(main())
```

4. Run the script. Each run starts a new proxy process. There is no separate restart.

5. Ask the assistant to call `lab__hello` with name `Ada`, then `lab__save_note` with text `bench 1 is clean`, then a name that is not on the allow list, such as `lab__drop_all`.

You should see `Hello, Ada.`, `Saved: bench 1 is clean`, and `denied by policy (allow:none)`. The denied call is not forwarded. It is still logged with `status` `denied` and `result` null.

6. Open the JSONL log. With `examples/config.json`, that is `data/audit.jsonl` next to the config file, unless `GLP_AUDIT_PATH` overrides it. On the `lab__hello` line:

- `principal`: who called. `id`, `name`, and `role`.
- `timestamp`: when, UTC. It changes every run.
- `tool`: `lab__hello`.
- `arguments`: the call arguments. A normal line has no separate args hash. `entry_hash` covers them.
- `result`: what the proxy returned, including `Hello, Ada.`
- `prev_hash`: the previous line's `entry_hash`. The first line uses 64 zeroes.
- `entry_hash`: the chain hash. SHA-256 of the RFC 8785 JSON of the line with `entry_hash` removed.

A desktop or agent host also logs `tools/list`, so the hello line is not always line 3. Hashes change every run. The terminal transcript is in [QUICKSTART.md](QUICKSTART.md).

7. Check the chain. Exit 0. Stderr contains `chain ok`. `--print-head` adds `seq=<n> entry_hash=<64 hex>` on stdout. That hash equals the `head=` value.

```bash
python -m mcp_glp_audit_proxy verify REPLACE_WITH_ABSOLUTE_PATH/data/audit.jsonl
python -m mcp_glp_audit_proxy verify REPLACE_WITH_ABSOLUTE_PATH/data/audit.jsonl --print-head
```

`mcp-glp-audit-proxy-verify` is the same checker.

8. Copy the log aside. Change one character in one line (for example `Hello, Ada.` to `Hello, Ada!`). Run verify again. Stderr starts with `chain invalid` and includes `entry_hash mismatch`. Restore the original bytes. Verify prints `chain ok` again.

## If it does not work

- `REPLACE_WITH_ABSOLUTE_PATH` is still in the config or the host entry. `upstreams[].args` must be the absolute path of `examples/hello_upstream.py`, and `cwd` must be the `examples` directory.
- `require_approval_for_writes` was turned on. This hello leaves it false. A write with the gate on is not forwarded.
- `GLP_PRINCIPAL_ROLE` is not `operator`. Only that role may call `lab__hello` and `lab__save_note`.
- The log is not where you looked. `./data/audit.jsonl` is resolved next to the config file. `GLP_AUDIT_PATH` moves it.
- The host was not fully restarted, so it is still the old process.
- A second MCP server points at `hello_upstream.py` directly, so the call never hits the proxy.
- The proxy stderr shows a startup refusal and the process exits 1. There is no listening port.

## Pitfalls

- `env` replaces nothing from the allow-list. It is merged on top. You do not need to resend `PATH`.
- Omitting `GLP_PRINCIPAL_*` makes the proxy use `principal` from the JSON file. If both are missing, startup exits 1.
- `session.call_tool` sends a normal `tools/call`. A write still needs `_meta` for the reason and, when approval is on, for `io.github.antonio-castellon/approvalId`. See [approval-workflow.md](approval-workflow.md). The SDK can pass `_meta` on the call. Those keys are proxy fields, not SDK flags.
- Closing the context manager closes stdin. The proxy exits. It is not a daemon.
