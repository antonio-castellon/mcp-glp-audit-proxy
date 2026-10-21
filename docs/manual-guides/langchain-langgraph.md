# LangChain and LangGraph

LangChain's current Python docs (`langchain[mcp]>=1.4.0`) connect to MCP through `langchain.mcp.MCPAdapter`. The adapter is in beta. Importing it raises `LangChainBetaWarning` once per process. The older `langchain-mcp-adapters` package is no longer maintained. Its migration page shows the replacement below.

LangGraph does not document a separate MCP client. Build the tool list with `MCPAdapter`, then pass that list into the graph the same way you pass any other LangChain tool. `create_agent` from `langchain.agents` is the constructor the MCP page uses. A `StateGraph` you assemble yourself should call those tools and no others.

The adapter must start the proxy, not the upstream. A script path or a second `mcpServers` entry for the lab server would skip the audit log.

`MCPAdapter` infers stdio from an `MCPConfig` entry that has `command` and `args`. That shape is the one on the LangChain connections page. A bare string is treated as an HTTP URL and is rejected when it is not `http` or `https`. Do not pass `"mcp-glp-audit-proxy"` as a string target.

## Prerequisites

- Python 3.11 or newer
- `mcp-glp-audit-proxy` installed
- `langchain[mcp]` at 1.4.0 or newer, in the same environment as the agent
- A proxy `config.json` from [generic-stdio.md](generic-stdio.md)

## Install

```bash
python -m pip install mcp-glp-audit-proxy "langchain[mcp]"
```

This extra is the agent's library. It is not a dependency of the proxy, and it is not required to run the proxy from an editor.

## Minimal config

Set identity in the environment of this process only if your adapter build copies the full parent environment. The official MCP SDK does not. Prefer the proxy `principal` inside `config.json` as well, so a missed `env` still has a person, and override it per process when you can pass `env`. The connections example uses `command` and `args`.

```python sdk
import asyncio

from langchain.agents import create_agent
from langchain.mcp import MCPAdapter

CONFIG = {
    "mcpServers": {
        "glp-audit": {
            "command": "mcp-glp-audit-proxy",
            "args": ["--config", "/srv/glp/config.json"],
        }
    }
}


async def main():
    async with MCPAdapter(CONFIG) as adapter:
        tools = await adapter.list_tools()
        agent = create_agent("claude-sonnet-5", tools)
        return await agent.ainvoke(
            {"messages": [{"role": "user", "content": "List the audited tools."}]}
        )


if __name__ == "__main__":
    asyncio.run(main())
```

The model name in `create_agent` is LangChain's argument, copied from the shape of their docs. Pick a model your account can call. It is not a proxy setting.

Before v1.4.0 the call looked like this. Do not start new work on it:

```python sdk
from langchain_mcp_adapters.client import MultiServerMCPClient

client = MultiServerMCPClient(
    {
        "glp-audit": {
            "transport": "stdio",
            "command": "mcp-glp-audit-proxy",
            "args": ["--config", "/srv/glp/config.json"],
        }
    }
)
```

## Hardened config

One server, the proxy, absolute command, and the principal fixed in the proxy file (hardened file in [generic-stdio.md](generic-stdio.md): approval on, narrow allow list). Keep the agent inside the `async with` block while you build it. The LangChain page says the tools hold the client after the block exits. A write tool is still gated by the proxy.

```python sdk
import asyncio

from langchain.agents import create_agent
from langchain.mcp import MCPAdapter

CONFIG = {
    "mcpServers": {
        "glp-audit": {
            "command": "/opt/lab/venv/bin/mcp-glp-audit-proxy",
            "args": ["--config", "/srv/glp/config.json"],
        }
    }
}


async def main():
    async with MCPAdapter(CONFIG) as adapter:
        tools = await adapter.list_tools()
        # LangGraph: pass `tools` into your graph's tool node.
        # Do not add a second adapter aimed at the upstream.
        agent = create_agent("claude-sonnet-5", tools)
        return agent


if __name__ == "__main__":
    asyncio.run(main())
```

A multi-server `MCPConfig` prefixes tool names. You do not need a second server to reach `excel__read_cell`. That name is already the proxy's exposed tool. Adding the Excel process as another `mcpServers` entry would call it with no audit record.

## Verification

Run the script and confirm the tool list contains `glp_verify_chain` (visible to `qa`, `approver`, and `admin`; an `operator` list is the upstream tools the allow list keeps, plus the local tools that role may see). Then:

```bash
mcp-glp-audit-proxy-verify /srv/glp/data/audit.jsonl --print-head
```

Adjust the path to `audit.path` or `GLP_AUDIT_PATH`.

## Pitfalls

- `MCPAdapter("https://lims.lab.example/mcp")` talks to the LIMS directly. Use it only if that URL is the proxy, which this edition never is.
- `langchain-mcp-adapters` is unmaintained. New agents should call `MCPAdapter`.
- The adapter does not know about `glp_approve`. A write can still come back as an error until an approver records `meaning` `approved`. See [approval-workflow.md](approval-workflow.md).
- FastMCP and LangChain are not started by the proxy's Docker image. They stay in the agent environment.
