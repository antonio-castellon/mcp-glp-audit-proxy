# Claude Desktop

Claude Desktop starts each MCP server as a local process. Point it at the proxy. Do not also add the upstream server. The upstream belongs in the proxy's `upstreams` list. The proxy file itself is the minimal or hardened file in [generic-stdio.md](generic-stdio.md).

## Prerequisites

- Claude Desktop from the publisher
- Python 3.11 or newer on the PATH Claude Desktop will use
- `mcp-glp-audit-proxy` installed for that same user
- A proxy `config.json` whose stdio `command` exists on this machine

The published MCP quickstart names these config files:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

That quickstart does not name a Linux path. On Linux, use Settings, Developer, Edit Config, and edit the file that action opens. If Edit Config on Windows opens a different path than `%APPDATA%\Claude`, edit that file. A February 2026 packaging bug briefly split the Windows path; the publisher marked it fixed. Trust the file the app opens.

## Install

```bash
python -m pip install mcp-glp-audit-proxy
mcp-glp-audit-proxy --help
```

On Windows, if `python` is the launcher stub:

```bash
py -3.12 -m pip install mcp-glp-audit-proxy
py -3.12 -m mcp_glp_audit_proxy --help
```

`--help` shows `--config` only.

## Minimal config

macOS or Linux JSON. The `env` block is required. A desktop app does not load your shell profile, and the child would not see `GLP_PRINCIPAL_*` from the profile anyway unless this block sets them.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "mcp-glp-audit-proxy",
      "args": ["--config", "/Users/ada/glp/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator"
      }
    }
  }
}
```

Windows uses the module and escaped backslashes:

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "py",
      "args": ["-3.12", "-m", "mcp_glp_audit_proxy", "--config", "C:\\Lab\\glp\\config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator"
      }
    }
  }
}
```

The proxy file at that `--config` path is a [generic-stdio.md](generic-stdio.md) config. Its `upstreams` command is the lab server. Claude's config does not list that server.

## Hardened config

Absolute paths, one person per `env` block, and the hardened proxy file (approval required, narrow allow list).

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "/Users/ada/glp/venv/bin/mcp-glp-audit-proxy",
      "args": ["--config", "/Users/ada/glp/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator",
        "GLP_AUDIT_PATH": "/Users/ada/glp/data/audit.jsonl"
      }
    }
  }
}
```

Do not add a second key such as `excel` or `lims` under `mcpServers`. That would call the upstream with no audit trail.

## Verification

Quit Claude Desktop completely and start it again. Developer settings should show `glp-audit` running. Then, outside the app, with the same config path:

```bash
mcp-glp-audit-proxy-verify /Users/ada/glp/data/audit.jsonl --print-head
```

A startup record in that file means this process wrote the log. If the server is missing from the app, the usual cause is a bad JSON file or a command that is not on the app's PATH. Run the same command in a terminal. Startup errors are printed to stderr and the process exits 1.

## Pitfalls

- Editing the config does nothing until the app is fully quit, not only the window closed.
- `command` must be an executable, not a shell line. `args` is the argument list. There is no `shell` key in this product.
- Claude Desktop has no flag that talks to this proxy except the args you put in `args`. The only proxy flag is `--config`.
- The upstream must not be reachable as its own MCP server from this app.
