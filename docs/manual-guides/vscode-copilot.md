# VS Code and GitHub Copilot agent mode

VS Code documents two MCP files. They are not interchangeable.

| File | Top-level key | Who reads it |
|---|---|---|
| `.vscode/mcp.json` or the user-profile `mcp.json` | `servers` | VS Code. The Copilot harness docs mark this destination deprecated for agent sessions. Input variables and `envFile` exist here |
| Workspace `.mcp.json`, or `~/.copilot/mcp-config.json` (`$COPILOT_HOME/mcp-config.json` when that variable is set) | `mcpServers` | Copilot agent mode reads this directly |

Use `.mcp.json` for Copilot agent mode. Use `.vscode/mcp.json` when you need the VS Code form. Do not register the upstream in either file. The upstream is only in the proxy config. See [generic-stdio.md](generic-stdio.md).

GitHub's Copilot docs also require, for an organisation that sets the policy, that "MCP servers in Copilot" is enabled. That is an organisation switch, not a proxy flag.

## Prerequisites

- VS Code 1.99 or newer for the Copilot MCP flow GitHub documents
- Python 3.11 or newer
- `mcp-glp-audit-proxy` installed

## Install

```bash
python -m pip install mcp-glp-audit-proxy
```

The VS Code command `MCP: Add Server` can write the file for you. The JSON below is the manual form. `code --add-mcp` writes a user-profile server from a JSON object. The object uses VS Code's `name` and `type` fields:

```bash
code --add-mcp "{\"name\":\"glp-audit\",\"type\":\"stdio\",\"command\":\"mcp-glp-audit-proxy\",\"args\":[\"--config\",\"/srv/glp/config.json\"]}"
```

Prefer the files below so `GLP_PRINCIPAL_*` is present. The one-line command above does not set them.

## Minimal config

Copilot agent mode, workspace `.mcp.json`:

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "mcp-glp-audit-proxy",
      "args": ["--config", "/srv/glp/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator"
      }
    }
  }
}
```

VS Code format, `.vscode/mcp.json`. The key is `servers`, and `type` is `stdio`.

```json client
{
  "servers": {
    "glp-audit": {
      "type": "stdio",
      "command": "mcp-glp-audit-proxy",
      "args": ["--config", "/srv/glp/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator"
      }
    }
  }
}
```

## Hardened config

Copilot portable files do not support `envFile` or `${input:...}` variables. Put identity in `env`. Keep secrets out of the committed file by using a user-level `mcp-config.json` for the personal values, and a workspace file that only has the command if the whole team shares one read-only config path.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "/opt/lab/venv/bin/mcp-glp-audit-proxy",
      "args": ["--config", "/srv/glp/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator",
        "GLP_AUDIT_PATH": "/srv/glp/operator-1/audit.jsonl"
      }
    }
  }
}
```

Hardened VS Code form, with a working directory so relative proxy paths resolve where you expect. `cwd` is a VS Code field. The proxy itself does not have a `--cwd` flag. Its own `upstreams[].cwd` is separate and applies to the upstream child.

```json client
{
  "servers": {
    "glp-audit": {
      "type": "stdio",
      "command": "/opt/lab/venv/bin/mcp-glp-audit-proxy",
      "args": ["--config", "/srv/glp/config.json"],
      "cwd": "/srv/glp",
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator",
        "GLP_AUDIT_PATH": "/srv/glp/operator-1/audit.jsonl"
      }
    }
  }
}
```

There is still no second server for the upstream.

## Verification

In VS Code, run `MCP: List Servers` from the Command Palette, or start an agent chat and confirm `glp-audit` is available. Then:

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --print-head
```

A remote or Dev Container session runs the server where the config lives. Install Python and the package in that environment, not only on the laptop that displays the window.

## Hello world

Audit two calls and one denied call through this host. Copy `examples/config.json` from a checkout and leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. Part 11 signatures are not part of this hello. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install the package the host will launch.

```bash
python -m pip install mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied config with the absolute path of the checkout. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

Copilot agent mode, workspace `.mcp.json`:

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "mcp-glp-audit-proxy",
      "args": ["--config", "REPLACE_WITH_ABSOLUTE_PATH/examples/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator"
      }
    }
  }
}
```

VS Code `.vscode/mcp.json`. The key is `servers`.

```json client
{
  "servers": {
    "glp-audit": {
      "type": "stdio",
      "command": "mcp-glp-audit-proxy",
      "args": ["--config", "REPLACE_WITH_ABSOLUTE_PATH/examples/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator"
      }
    }
  }
}
```

4. Reload the window, run `MCP: List Servers`, and start a new agent chat.

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

- Copying a `servers` file into `.mcp.json` does not work. The Copilot harness looks for `mcpServers`.
- `${input:...}` and `envFile` are not forwarded into Copilot harness sessions. A server that depends on an interactive input never reaches the agent.
- Do not set the server `type` to `http` for this package. It does not listen on a port.
- The upstream stays behind the proxy. Adding it in the GitHub MCP gallery as well would bypass the log.
