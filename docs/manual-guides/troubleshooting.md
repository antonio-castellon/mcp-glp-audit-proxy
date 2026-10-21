# Troubleshooting

Startup and call failures are fail-closed. The proxy prints the reason on stderr and, once a session is up, returns a JSON-RPC error instead of the upstream payload. Nothing in this page disables the audit log. `glp_update_policy` with `audit_enabled` false is denied.

The upstream is still reached only through the proxy. A denied call is not a reason to point the host at the upstream directly.

## Prerequisites

- The config file the host actually passes to `--config`
- stderr from the proxy process (the host's MCP log, or a terminal run)
- `mcp-glp-audit-proxy-verify` for the log path

## Install

```bash
python -m pip install mcp-glp-audit-proxy
mcp-glp-audit-proxy --help
mcp-glp-audit-proxy-verify --help
```

If `--help` is not found, the Scripts or `bin` directory is not on PATH. `python -m mcp_glp_audit_proxy --help` uses the module instead.

## Minimal config

A file that should start. Use it to separate a bad config from a bad host.

```json proxy
{
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "policy": {
    "allow": ["excel__read_*"],
    "deny": [],
    "write_tools": [],
    "require_approval_for_writes": false,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "./data/audit.jsonl",
    "fail_closed": true,
    "checkpoint_every": 100
  },
  "require_ntp": false,
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

```bash
GLP_PRINCIPAL_ID=operator-1 GLP_PRINCIPAL_NAME="Ada Analyst" GLP_PRINCIPAL_ROLE=operator mcp-glp-audit-proxy --config /srv/glp/config.json
```

The process waits on stdin when the config is accepted. Ctrl-D (Unix) or Ctrl-Z then Enter (Windows) closes stdin and the process exits. A line on stderr that starts with `mcp-glp-audit-proxy:` and exit code 1 means it refused to start.

## Hardened config

Keep fail-closed on. Narrow tools so a denial is expected and visible.

```json proxy
{
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "policy": {
    "allow": ["excel__read_cell"],
    "deny": ["excel__write_*", "excel__drop_*"],
    "write_tools": ["excel__write_*"],
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
      "protocol": "legacy",
      "command": "/opt/lab/venv/bin/python",
      "args": ["-m", "your_excel_mcp_server"],
      "timeout": 30,
      "env": {}
    }
  ]
}
```

## Verification

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --status denied --print-head
```

Denied calls are logged. `--status denied` only filters the printout.

## Fail-closed latch

If the store cannot append, the host receives JSON-RPC code `-32000`, message `audit log unavailable; request was not completed`, and `error.data.reason` `fail_closed`. The upstream payload is not returned. Later requests get the same error until the process restarts, except `glp_verify_chain`. Notifications are dropped.

Typical stderr text includes `refusing to start`, `proxy handle failed`, and `audit store write failed`. A full disk, a read-only file, or a chain that no longer verifies takes this path. The proxy does not retry the store.

Fix the cause. Do not delete sealed lines. Follow `docs/RECONCILIATION_SOP.md` if the upstream may already have applied the write. Then start a new process. The latch is in memory. It is not cleared by a later successful call.

`GLP_FAIL_CLOSED=false` is accepted (`0`, `false`, `no`, `off`) and is a worse setting. Leave the default true.

## 1 MiB cap

`MAX_MESSAGE_BYTES` is 1048576. A line longer than that, with no newline, ends the session. The proxy does not scan for a later newline. The bytes are not forwarded and are not stored as a tool call. The technical log says `message exceeds size limit without a newline; ending session`. Split the upstream's payload, or call a tool that returns a smaller page. There is no config key to raise the cap.

An upstream line over the same cap stops that child and surfaces as an upstream failure.

## Denied calls

The tool text is `denied by policy (<rule>)`. Rules you will see:

| Rule | Meaning |
|---|---|
| `role:<role>` | Caller is not `operator`. Approver, QA, and admin cannot call upstream tools |
| `name:whitespace` or `name:charset` | Exposed name is empty, padded, or not a plain ASCII token |
| `deny:<pattern>` | A `policy.deny` glob matched. Deny wins over allow |
| `allow:none` | No `policy.allow` glob matched. An empty allow list denies every upstream tool |
| `write:reason-missing` | Text is `a reason is required for write tools` |
| `approval:unknown`, `approval:consumed`, `approval:rejected`, `approval:meaning`, `approval:role`, `approval:self`, `approval:mismatch`, `approval:expired` | Text is `approval refused (<problem>)`. A missing `approvalId` does not use these rules. It records `pending_approval` and does not forward the call |
| `config:audit-disable` | `glp_update_policy` tried to turn auditing off |
| `reporter:unknown` | `glp_export_audit` `format` is not one of the configured reporters |

A denial is still an audit line. If you need the call, change policy as `admin` with `glp_update_policy` and a `reason`, or fix the allow list in the file and restart. Do not add the upstream to the host.

## Other startup refusals

| Stderr idea | What to fix |
|---|---|
| `config file not found` | `--config` or `GLP_CONFIG` path |
| `config is not JSON` | Trailing commas, comments, or a single trailing quote. JSON has no comments |
| `role must be one of` | `GLP_PRINCIPAL_ROLE` is not `operator`, `approver`, `qa`, or `admin` |
| `unknown plugins fields` or `must be a plugin name` | `plugins` keys or a name outside the lowercase pattern |
| `not licensed` or `not installed` | `plugins` selected a name this process cannot use. Community values are `jsonl`, `unsigned`, `json`, `text`, `env` |
| `require_ntp is set and the clock is not reported synchronized` | `timedatectl` missing or not reporting `yes`. Windows has no `timedatectl`. Leave `require_ntp` false there |
| `https transport requires url` or `remote transports require TLS 1.3` | `transport` `https` needs an `https://` URL. `http://` is refused |
| `stdio transport requires command` | stdio upstream with no `command` |
| `upstream name` | Empty name, or a name containing `__` |

`checkpoint_every` 0 and `approval_ttl_seconds` 0 are not errors. Both are stored as their defaults (100 and 3600) because the loader treats 0 as unset.

## Pitfalls

- The host MCP log is stderr. stdout that is not JSON-RPC confuses the host. Do not wrap the command in a shell that prints a banner.
- After a latch, restart the host so it spawns a new proxy. Killing only a pane can leave the old process.
- A successful `--help` does not mean the config is valid. `--help` does not open the config.
- Seeing a denial and then calling the upstream from a second MCP entry deletes the point of the proxy.
