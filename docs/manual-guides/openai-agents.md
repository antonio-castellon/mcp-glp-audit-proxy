# OpenAI Agents SDK

The OpenAI Agents SDK (Python) starts a local MCP server with `MCPServerStdio`. `params` is `MCPServerStdioParams`, which mirrors `mcp.client.stdio.StdioServerParameters`: `command`, `args`, `env`, `cwd`, `encoding`, `encoding_error_handler`. Put `GLP_PRINCIPAL_*` in `params["env"]`. The SDK does not copy the rest of the parent environment into the child.

`HostedMCPTool` asks the Responses API to call a public URL. This proxy is not a public URL. Do not use a hosted tool for it, and do not point a hosted tool at the upstream.

## Prerequisites

- Python 3.11 or newer
- `mcp-glp-audit-proxy` installed
- The `agents` package (`openai-agents`) in the agent environment
- A proxy `config.json` from [generic-stdio.md](generic-stdio.md)
- An OpenAI API key available to the agent process, not to the proxy and not to the upstream

## Install

```bash
python -m pip install mcp-glp-audit-proxy openai-agents
```

`openai-agents` is not a dependency of the proxy.

## Minimal config

```python sdk
import asyncio

from agents import Agent, Runner
from agents.mcp import MCPServerStdio


async def main() -> None:
    async with MCPServerStdio(
        name="glp-audit",
        params={
            "command": "mcp-glp-audit-proxy",
            "args": ["--config", "/srv/glp/config.json"],
            "env": {
                "GLP_PRINCIPAL_ID": "operator-1",
                "GLP_PRINCIPAL_NAME": "Ada Analyst",
                "GLP_PRINCIPAL_ROLE": "operator",
            },
        },
    ) as server:
        agent = Agent(
            name="lab",
            instructions="Use the audited tools. Do not invent a direct lab connection.",
            mcp_servers=[server],
        )
        result = await Runner.run(agent, "Which tools are on the audit proxy?")
        print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
```

## Hardened config

Absolute command, dedicated log, and a static tool filter so the model only sees names you list. `create_static_tool_filter` and `allowed_tool_names` are Agents SDK arguments, documented on its MCP page. They do not change the proxy allow list. Set both. The proxy still denies anything outside `policy.allow`.

```python sdk
import asyncio

from agents import Agent, Runner
from agents.mcp import MCPServerStdio, create_static_tool_filter


async def main() -> None:
    async with MCPServerStdio(
        name="glp-audit",
        params={
            "command": "/opt/lab/venv/bin/mcp-glp-audit-proxy",
            "args": ["--config", "/srv/glp/config.json"],
            "cwd": "/srv/glp",
            "env": {
                "GLP_PRINCIPAL_ID": "operator-1",
                "GLP_PRINCIPAL_NAME": "Ada Analyst",
                "GLP_PRINCIPAL_ROLE": "operator",
                "GLP_AUDIT_PATH": "/srv/glp/operator-1/audit.jsonl",
            },
        },
        tool_filter=create_static_tool_filter(
            allowed_tool_names=["excel__read_cell", "excel__list_sheets"]
        ),
    ) as server:
        agent = Agent(
            name="lab",
            instructions="Read through the audit proxy only.",
            mcp_servers=[server],
        )
        result = await Runner.run(agent, "Read the configured cell.")
        print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
```

The hardened proxy file should set `require_approval_for_writes` if this agent can call `excel__write_cell`. The SDK filter is not a substitute for that gate.

## Verification

Run the script with a real upstream command in the proxy config. Then:

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --tool excel__read_cell --status ok
```

`--tool` filters the printed lines. The chain check is still the whole file.

## Pitfalls

- `HostedMCPTool` and `MCPServerStreamableHttp` need a URL. This edition does not serve one. A URL aimed at the LIMS bypasses the log.
- `params["env"]` is the proxy's environment. It is not forwarded to the upstream. Upstream secrets belong in `upstreams[].env` or `headers`.
- `client_session_timeout_seconds` defaults to 5 in this SDK. A slow upstream can exceed it. The proxy's own stdio `timeout` defaults to 60 seconds. Raise the SDK timeout if the lab server is slower than five seconds. That argument is the SDK's, not a proxy flag.
- Approval is still `glp_approve` on a second process with role `approver`. The agent's tool filter should not be the only control.
