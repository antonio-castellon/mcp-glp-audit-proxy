# Windsurf, Cline, and Continue

These three hosts document a stdio MCP config. Each one should start the proxy and should not start the upstream. The upstream is `upstreams` in the proxy file from [generic-stdio.md](generic-stdio.md).

Paths move between product versions. When the product has an "open MCP config" action, edit the file that action opens. The paths below are the ones in the publisher docs checked for this guide.

## Prerequisites

- The editor or CLI installed
- Python 3.11 or newer and `mcp-glp-audit-proxy` on PATH
- A proxy `config.json`

## Install

```bash
python -m pip install mcp-glp-audit-proxy
mcp-glp-audit-proxy --help
```

## Windsurf

Cascade's docs (docs.devin.ai) say Open MCP config opens a Cortex-managed file:

- macOS and Linux: `~/.config/devin/mcp_config.json`, or `$XDG_CONFIG_HOME/devin/mcp_config.json` when `XDG_CONFIG_HOME` is set
- Windows: `%AppData%\devin\mcp_config.json`

The same page says editor discovery uses a different file, `~/.codeium/windsurf/mcp_config.json` (stable channel). Use the file the menu opens. The object is `mcpServers`, the same shape as Claude Desktop. Press the refresh control after saving.

### Minimal config

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

### Hardened config

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

Windsurf documents stdio, Streamable HTTP, and SSE. Use stdio. This proxy has no URL.

## Cline

Cline's own docs say:

- CLI: `~/.cline/data/settings/cline_mcp_settings.json`, overridable with `CLINE_MCP_SETTINGS_PATH`
- IDE: MCP Servers icon, Configure, Configure MCP Servers, which opens the JSON the extension uses

The documented stdio object includes `disabled` and `autoApprove`. Leave `autoApprove` empty so a person still confirms tool calls in Cline. That confirmation is Cline's UI. It is not `glp_approve` and it is not an electronic signature.

### Minimal config

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
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Hardened config

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
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

Do not set `type` to `streamableHttp` for this package. Cline's docs say an omitted `type` selects legacy SSE for a URL entry. This package is stdio, so omit `url` and set `command`.

## Continue

Continue's docs use YAML. A global file is `~/.continue/config.yaml`. A project block is a file under `.continue/mcpServers/` (the directory name is plural). Continue also loads a JSON MCP file dropped in that directory, in the Claude-style object, if you already have one.

Every Continue YAML file needs top-level `name`, `version`, and `schema`. `mcpServers` is a list, not a map. Each entry has its own `name`. `type` may be `stdio`, `sse`, or `streamable-http`. Use `stdio`. MCP runs in Continue's agent mode.

### Minimal config

```yaml continue
name: Local Config
version: 1.0.0
schema: v1
mcpServers:
  - name: GLP audit
    type: stdio
    command: mcp-glp-audit-proxy
    args:
      - "--config"
      - "/srv/glp/config.json"
    env:
      GLP_PRINCIPAL_ID: operator-1
      GLP_PRINCIPAL_NAME: Ada Analyst
      GLP_PRINCIPAL_ROLE: operator
```

### Hardened config

Project block `.continue/mcpServers/glp-audit.yaml`:

```yaml continue
name: GLP audit proxy
version: 1.0.0
schema: v1
mcpServers:
  - name: GLP audit
    type: stdio
    command: /opt/lab/venv/bin/mcp-glp-audit-proxy
    args:
      - "--config"
      - "/srv/glp/config.json"
    env:
      GLP_PRINCIPAL_ID: operator-1
      GLP_PRINCIPAL_NAME: Ada Analyst
      GLP_PRINCIPAL_ROLE: operator
      GLP_AUDIT_PATH: /srv/glp/operator-1/audit.jsonl
```

## Verification

Refresh the host's MCP list, start one agent turn that can see the proxy, then:

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --print-head
```

If the list is empty, the file the product opened is not the file you edited.

## Pitfalls

- Three products, three files. A Claude Desktop config in the wrong folder is ignored.
- Cline `autoApprove` does not record `glp_approve` and does not satisfy `require_approval_for_writes`.
- Continue rejects a YAML file that has no `name`, `version`, and `schema`.
- None of these hosts should be given the upstream command. Only the proxy should.
