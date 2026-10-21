# Cursor

Cursor reads MCP servers from `mcp.json` and merges the project file with the user file. The repository root `mcp.json` in this project is only a sample. Cursor does not load that path. Use the paths in the Cursor MCP docs:

- Project: `.cursor/mcp.json`
- User, all projects: `~/.cursor/mcp.json`

If the same server name is in both, the project entry wins. The Cursor CLI uses the same files.

The host entry is the proxy. The upstream is not a second server. It is `upstreams` inside the proxy config. See [generic-stdio.md](generic-stdio.md).

## Prerequisites

- Cursor, or the `agent` CLI
- Python 3.11 or newer
- `mcp-glp-audit-proxy` on PATH, or an absolute path to the script

## Install

```bash
python -m pip install mcp-glp-audit-proxy
```

Restart Cursor after saving `mcp.json`. In the product, Customize, then MCPs, shows the server.

## Minimal config

`.cursor/mcp.json`. The Cursor field table marks `type` as required for a stdio server. The short examples on the same page omit it. This sample includes it.

```json client
{
  "mcpServers": {
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

Absolute command, `envFile` kept out of git, and a dedicated log. `envFile` is a Cursor stdio field. It is not a proxy flag. Do not commit the file it names.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "type": "stdio",
      "command": "/opt/lab/venv/bin/mcp-glp-audit-proxy",
      "args": ["--config", "/srv/glp/config.json"],
      "envFile": "/srv/glp/operator-1.env",
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

`operator-1.env` holds only variables you accept the proxy process seeing. It is not passed to the upstream. Upstream credentials stay in the proxy config's `upstreams[].env`.

Do not add a `url` entry for the lab server. This edition of the proxy is not an HTTP MCP endpoint, and a direct URL would skip the audit log.

The root `mcp.json` sample in the repository is the same `mcpServers` shape, with placeholder paths. Keep using `.cursor/mcp.json` for a real workspace.

## Verification

Restart Cursor, open Customize, MCPs, and confirm `glp-audit` is enabled. Then:

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --print-head
```

The Cursor CLI login command `agent mcp login` is for a remote server that asks you to sign in. This proxy has no such login. Do not point that command at a lab upstream.

## Pitfalls

- A workspace committed `.cursor/mcp.json` shares the command with the team. Keep identity in `env` or `envFile`, not in a shared default role of `admin`.
- Interpolation such as `${env:NAME}` is Cursor's, documented on its MCP page. This proxy does not expand those strings.
- The proxy still has only `--config`. Anything else in `args` is rejected by its parser and the process exits 1.
- The upstream process must be started by the proxy, not by a second `mcpServers` entry.
