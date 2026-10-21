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

## Pitfalls

- `env` replaces nothing from the allow-list. It is merged on top. You do not need to resend `PATH`.
- Omitting `GLP_PRINCIPAL_*` makes the proxy use `principal` from the JSON file. If both are missing, startup exits 1.
- `session.call_tool` sends a normal `tools/call`. A write still needs `_meta` for the reason and, when approval is on, for `io.github.antonio-castellon/approvalId`. See [approval-workflow.md](approval-workflow.md). The SDK can pass `_meta` on the call. Those keys are proxy fields, not SDK flags.
- Closing the context manager closes stdin. The proxy exits. It is not a daemon.
