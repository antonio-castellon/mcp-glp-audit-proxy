# Generic MCP client over stdio

Use this when the host can start a local process and speak newline-delimited JSON-RPC on stdin and stdout. Claude, Cursor, VS Code, and the Python agents in the other guides are this shape with a different config file.

The upstream server must be reachable only through the proxy. Configure the upstream in `upstreams`. Do not also point the host at that server.

## Prerequisites

- Python 3.11, 3.12, or 3.13
- A host that launches a stdio MCP server and keeps the pipes open for the session
- The upstream command installed where the proxy can execute it, or an `https://` URL the proxy can reach

## Install

```bash
python -m pip install mcp-glp-audit-proxy
```

From a checkout, with the development tools:

```bash
python -m pip install -e ".[dev]"
```

Confirm the script and the one server flag:

```bash
mcp-glp-audit-proxy --help
```

The help text is the `--config` option. The server does not listen on a port and it has no HTTP switch. Stdio is the only transport.

## Minimal config

Proxy file, for example `/srv/glp/config.json`. Relative `audit.path` and `export_dir` resolve next to that file.

```json proxy
{
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "policy": {
    "allow": ["excel__read_*", "excel__list_*"],
    "deny": ["excel__drop_*"],
    "write_tools": ["excel__write_*", "excel__delete_*"],
    "require_approval_for_writes": false,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "./data/audit.jsonl",
    "fail_closed": true,
    "checkpoint_every": 100
  },
  "upstreams": [
    {
      "name": "excel",
      "transport": "stdio",
      "protocol": "auto",
      "command": "python",
      "args": ["-m", "your_excel_mcp_server"],
      "env": {}
    }
  ]
}
```

Replace `python` and `-m your_excel_mcp_server` with the real upstream. The name `excel` is the prefix on exposed tools (`excel__read_cell`).

Host side, the common `mcpServers` object. The key `glp-audit` is the host's name for the proxy, not an upstream.

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

## Hardened config

Narrow the allow list, require a second person for writes, pin plugins, and give the upstream only the environment it needs. Keep `fail_closed` true.

```json proxy
{
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "retention": {
    "profile": "swiss_glp",
    "min_months": 6,
    "years_after_study": 10,
    "legal_hold": false,
    "study_completion": null
  },
  "policy": {
    "allow": ["excel__read_cell", "excel__list_sheets"],
    "deny": ["excel__drop_*", "excel__delete_*"],
    "write_tools": ["excel__write_cell"],
    "require_approval_for_writes": true,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "/srv/glp/operator-1/audit.jsonl",
    "fail_closed": true,
    "checkpoint_every": 50
  },
  "approval_ttl_seconds": 900,
  "require_ntp": false,
  "export_dir": "/srv/glp/operator-1/exports",
  "licence_path": null,
  "plugins": {
    "storage": "jsonl",
    "signer": "unsigned",
    "reporters": ["json", "text"],
    "auth": "env"
  },
  "upstreams": [
    {
      "name": "excel",
      "transport": "stdio",
      "protocol": "auto",
      "command": "/opt/lab/venv/bin/python",
      "args": ["-m", "your_excel_mcp_server"],
      "cwd": "/opt/lab",
      "timeout": 30,
      "env": {
        "EXCEL_WORKBOOK_DIR": "/srv/lab/workbooks"
      }
    }
  ]
}
```

Set `GLP_REQUIRE_NTP=true` only on a host where `timedatectl show -p NTPSynchronized --value` prints `yes`. Otherwise the process refuses to start. A remote upstream uses `transport` `https` and an `https://` URL. Do not put the host's session token in `headers`. Put the upstream's own credential there, and do not commit it.

```json proxy
{
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "policy": {
    "allow": ["lims__read_*"],
    "deny": [],
    "write_tools": ["lims__write_*"],
    "require_approval_for_writes": true,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "/srv/glp/operator-1/audit.jsonl",
    "fail_closed": true
  },
  "upstreams": [
    {
      "name": "lims",
      "transport": "https",
      "protocol": "auto",
      "url": "https://lims.lab.example/mcp",
      "headers": {
        "authorization": "Bearer upstream-token-from-this-backend"
      }
    }
  ]
}
```

Hardened host entry: absolute command, absolute config, identity in `env`.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "/opt/lab/venv/bin/mcp-glp-audit-proxy",
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

## Verification

This handshake does not require a model. It fails if the config is rejected or if the stdio `command` cannot be started. Use a config whose upstream command exists before you treat a failure as a product fault.

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"check","version":"0"}}}' | GLP_PRINCIPAL_ID=operator-1 GLP_PRINCIPAL_NAME="Ada Analyst" GLP_PRINCIPAL_ROLE=operator mcp-glp-audit-proxy --config /srv/glp/config.json
```

The stdout line is JSON. `result.serverInfo.name` is `mcp-glp-audit-proxy`. Then, after a real session:

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --print-head
```

Exit 0 and a stderr line that starts with `chain ok` means the file verified. Store the stdout `seq=` line off this machine.

## Pitfalls

- A second MCP entry for the upstream bypasses the log.
- stdout must stay JSON-RPC. Do not wrap the command in a shell that prints a banner.
- `checkpoint_every` of 0 is stored as 100. It does not turn checkpoints off.
- The proxy child does not receive the host's full environment. Credentials the upstream needs belong in that upstream's `env`.
- `timeout` on an https upstream is accepted and then not applied. HTTPS uses 30 seconds in this edition.
- After a store failure the process latches. Restart it. See [troubleshooting.md](troubleshooting.md).
