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

## Pitfalls

- Copying a `servers` file into `.mcp.json` does not work. The Copilot harness looks for `mcpServers`.
- `${input:...}` and `envFile` are not forwarded into Copilot harness sessions. A server that depends on an interactive input never reaches the agent.
- Do not set the server `type` to `http` for this package. It does not listen on a port.
- The upstream stays behind the proxy. Adding it in the GitHub MCP gallery as well would bypass the log.
