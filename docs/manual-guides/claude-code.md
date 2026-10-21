# Claude Code

Claude Code starts a stdio MCP server from `.mcp.json` (project scope, shared) or from `claude mcp add` (local or user scope). Register the proxy. Do not register the upstream. The upstream is only in the proxy config's `upstreams`.

Official scopes, from the Claude Code MCP docs:

| Scope | File | Who sees it |
|---|---|---|
| local (default) | `~/.claude.json`, under this project | Only you, this project |
| project | `.mcp.json` in the project root | Anyone who clones the project, after they approve it |
| user | `~/.claude.json`, top-level `mcpServers` | Only you, all projects |

On Windows, `~/.claude.json` is `%USERPROFILE%\.claude.json`. `CLAUDE_CONFIG_DIR`, when set, replaces the directory that holds `.claude.json`.

## Prerequisites

- Claude Code installed and `claude` on PATH
- Python 3.11 or newer
- A proxy `config.json` as in [generic-stdio.md](generic-stdio.md)

## Install

```bash
python -m pip install mcp-glp-audit-proxy
```

Add the server. Everything after `--` is the proxy command, not a Claude Code flag. `--config` is the proxy's flag.

```bash
claude mcp add --transport stdio --scope project glp-audit -- mcp-glp-audit-proxy --config /srv/glp/config.json
```

Identity has to be in the server environment. Put at least one other option between `--env` and the server name, as the Claude Code docs require, or the name is parsed as another `KEY=value` pair.

```bash
claude mcp add --env GLP_PRINCIPAL_ID=operator-1 --env GLP_PRINCIPAL_NAME="Ada Analyst" --env GLP_PRINCIPAL_ROLE=operator --transport stdio --scope user glp-audit -- mcp-glp-audit-proxy --config /srv/glp/config.json
```

Check the saved entry:

```bash
claude mcp list
```

## Minimal config

Project file `.mcp.json`. `type` `stdio` matches the local-server form in the Claude Code docs.

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

Absolute command, a per-person log, and no extra servers. Commit `.mcp.json` only if the paths work for every clone. Prefer user scope when the path is personal.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "type": "stdio",
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

The hardened proxy file (approval on, narrow allow list) is in [generic-stdio.md](generic-stdio.md). Do not add the LIMS or Excel server to this file.

Claude Code sets `CLAUDE_PROJECT_DIR` on the spawned server. This proxy does not read that variable. Paths in `--config` and in `config.json` should be absolute so they do not depend on the working directory.

## Verification

```bash
claude mcp list
```

A connected `glp-audit` entry means the process started. Then:

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --print-head
```

Inside a session, `/mcp` manages servers that are already added. That slash command is Claude Code's, not a proxy flag.

## Pitfalls

- Flags before `--` belong to `claude mcp add` (`--env`, `--transport`, `--scope`). Flags after `--` belong to the proxy, and the only one is `--config`.
- A project `.mcp.json` is shared. Do not put a personal access token in it. Upstream credentials belong in the proxy's `upstreams[].env` or `headers`, outside git.
- Approving a project MCP server still must not approve a direct path to the upstream.
- `claude mcp list` showing a failure is usually a missing command or a config the proxy rejected on stderr.
