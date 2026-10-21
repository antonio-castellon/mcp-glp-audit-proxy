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

## Hello world

Audit two calls and one denied call through this host. Copy `examples/config.json` from a checkout and leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. Part 11 signatures are not part of this hello. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install the package the host will launch.

```bash
python -m pip install mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied config with the absolute path of the checkout. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

Windsurf, the file Open MCP config opens:

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

Cline settings JSON. Leave `autoApprove` empty. That list is Cline's UI confirmation, not an audit control.

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
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

Continue, `~/.continue/config.yaml` or `.continue/mcpServers/glp-audit.yaml`. `mcpServers` is a list.

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
      - "REPLACE_WITH_ABSOLUTE_PATH/examples/config.json"
    env:
      GLP_PRINCIPAL_ID: operator-1
      GLP_PRINCIPAL_NAME: Ada Analyst
      GLP_PRINCIPAL_ROLE: operator
```

4. Refresh the MCP list in the host you edited (Windsurf refresh, Cline's MCP list, or a new Continue agent turn).

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

- Three products, three files. A Claude Desktop config in the wrong folder is ignored.
- Cline `autoApprove` does not record `glp_approve` and does not satisfy `require_approval_for_writes`.
- Continue rejects a YAML file that has no `name`, `version`, and `schema`.
- None of these hosts should be given the upstream command. Only the proxy should.
