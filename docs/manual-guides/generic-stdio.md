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

## Hello world

Audit two calls and one denied call through this host. Copy `examples/config.json` from a checkout and leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. Part 11 signatures are not part of this hello. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install the package the host will launch.

```bash
python -m pip install mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied config with the absolute path of the checkout. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

Proxy file. This is `examples/config.json`. The placeholder is literal until you replace it.

```json proxy
{
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "policy": {
    "allow": ["lab__hello", "lab__save_note"],
    "deny": [],
    "write_tools": ["lab__save_note"],
    "require_approval_for_writes": false,
    "require_reason_for_writes": false
  },
  "audit": {
    "path": "./data/audit.jsonl",
    "fail_closed": true
  },
  "require_ntp": false,
  "approval_ttl_seconds": 3600,
  "export_dir": "./data/exports",
  "plugins": {
    "storage": "jsonl",
    "signer": "unsigned",
    "reporters": ["json", "text"],
    "auth": "env"
  },
  "upstreams": [
    {
      "name": "lab",
      "transport": "stdio",
      "protocol": "legacy",
      "command": "python",
      "args": ["REPLACE_WITH_ABSOLUTE_PATH/examples/hello_upstream.py"],
      "cwd": "REPLACE_WITH_ABSOLUTE_PATH/examples",
      "env": {}
    }
  ]
}
```

Host entry:

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

4. Restart the host process that reads that entry.

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

- A second MCP entry for the upstream bypasses the log.
- stdout must stay JSON-RPC. Do not wrap the command in a shell that prints a banner.
- `checkpoint_every` of 0 is stored as 100. It does not turn checkpoints off.
- The proxy child does not receive the host's full environment. Credentials the upstream needs belong in that upstream's `env`.
- `timeout` on an https upstream is accepted and then not applied. HTTPS uses 30 seconds in this edition.
- After a store failure the process latches. Restart it. See [troubleshooting.md](troubleshooting.md).
