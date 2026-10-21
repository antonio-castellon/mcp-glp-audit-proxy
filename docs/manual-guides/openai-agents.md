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

## Hello world

Audit two calls and one denied call through this host. Copy `examples/config.json` from a checkout and leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. Part 11 signatures are not part of this hello. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install the package the host will launch.

```bash
python -m pip install mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied config with the absolute path of the checkout. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

```python sdk
import asyncio

from agents import Agent, Runner
from agents.mcp import MCPServerStdio


async def main() -> None:
    async with MCPServerStdio(
        name="glp-audit",
        params={
            "command": "mcp-glp-audit-proxy",
            "args": ["--config", "REPLACE_WITH_ABSOLUTE_PATH/examples/config.json"],
            "env": {
                "GLP_PRINCIPAL_ID": "operator-1",
                "GLP_PRINCIPAL_NAME": "Ada Analyst",
                "GLP_PRINCIPAL_ROLE": "operator",
            },
        },
    ) as server:
        agent = Agent(
            name="lab",
            instructions="Call lab__hello and lab__save_note through this server only.",
            mcp_servers=[server],
        )
        result = await Runner.run(
            agent,
            "Call lab__hello for Ada, then save a note that bench 1 is clean.",
        )
        print(result.final_output)


if __name__ == "__main__":
    asyncio.run(main())
```

4. Run the script. The context manager starts the proxy. There is no separate restart.

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

- `HostedMCPTool` and `MCPServerStreamableHttp` need a URL. This edition does not serve one. A URL aimed at the LIMS bypasses the log.
- `params["env"]` is the proxy's environment. It is not forwarded to the upstream. Upstream secrets belong in `upstreams[].env` or `headers`.
- `client_session_timeout_seconds` defaults to 5 in this SDK. A slow upstream can exceed it. The proxy's own stdio `timeout` defaults to 60 seconds. Raise the SDK timeout if the lab server is slower than five seconds. That argument is the SDK's, not a proxy flag.
- Approval is still `glp_approve` on a second process with role `approver`. The agent's tool filter should not be the only control.
