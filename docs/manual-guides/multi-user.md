# Shared lab workstation

One workstation, several people. Each person gets their own OS account, their own `GLP_PRINCIPAL_*` values, and their own audit file. The proxy has no multi-user daemon and no login. Identity is the environment of the process the host starts. Two people must not share a process, and they must not append to the same log.

The upstream is still reached only through the proxy. A shared config file may describe the upstream. It must not be a server the host also launches.

## Prerequisites

- Separate OS accounts for operator, approver, QA, and admin. The proxy roles are not a substitute for OS accounts
- Python 3.11 or newer installed for each account, or one install whose Scripts directory each account can execute
- A config file those accounts can read and cannot rewrite (mode `0644`, owned by an admin account)
- A private data directory per person, mode `0700`

## Install

```bash
python -m pip install mcp-glp-audit-proxy
```

Put the shared file at `/srv/glp/config.json`. Create `/srv/glp/ada` and `/srv/glp/ben` owned by each person. The log is created mode `0600`.

## Minimal config

Shared file. The `principal` here is a placeholder. Each host entry overrides it. `GLP_AUDIT_PATH` overrides `audit.path`, so the shared file can point at a path the operator will not use.

```json proxy
{
  "principal": {
    "id": "unset",
    "name": "Unset",
    "role": "operator"
  },
  "policy": {
    "allow": ["excel__read_*", "excel__list_*"],
    "deny": ["excel__drop_*"],
    "write_tools": ["excel__write_*", "excel__delete_*"],
    "require_approval_for_writes": true,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "/srv/glp/shared-must-be-overridden.jsonl",
    "fail_closed": true,
    "checkpoint_every": 100
  },
  "approval_ttl_seconds": 900,
  "export_dir": "/srv/glp/exports",
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
      "env": {
        "EXCEL_WORKBOOK_DIR": "/srv/lab/workbooks"
      }
    }
  ]
}
```

Operator host entry:

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "mcp-glp-audit-proxy",
      "args": ["--config", "/srv/glp/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator",
        "GLP_AUDIT_PATH": "/srv/glp/ada/audit.jsonl"
      }
    }
  }
}
```

## Hardened config

Approver, on a second login, same config file, different identity and different log. QA uses role `qa` and yet another log. Admin uses role `admin`. Nobody uses role `operator` in an approver's session. Self-approval is denied: `glp_approve` refuses when `principal.id` equals the id that requested the write.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "/opt/lab/venv/bin/mcp-glp-audit-proxy",
      "args": ["--config", "/srv/glp/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "approver-1",
        "GLP_PRINCIPAL_NAME": "Ben Reviewer",
        "GLP_PRINCIPAL_ROLE": "approver",
        "GLP_AUDIT_PATH": "/srv/glp/ben/audit.jsonl"
      }
    }
  }
}
```

`export_dir` in the shared file is shared. A QA export should pass a relative `path` that stays inside that directory, or you set `export_dir` per process by using a per-person config copy. There is no `GLP_EXPORT_DIR` variable. The loader does not read one.

Do not point two processes at one `GLP_AUDIT_PATH`. The JSONL store is one writer. Two processes appending to the same file break the chain.

## Verification

On Ada's session, after a call:

```bash
mcp-glp-audit-proxy-verify /srv/glp/ada/audit.jsonl --principal operator-1 --print-head
```

On Ben's session:

```bash
mcp-glp-audit-proxy-verify /srv/glp/ben/audit.jsonl --principal approver-1 --print-head
```

`--principal` filters the printed lines. Each file is verified on its own. A startup line in Ada's file should show principal id `operator-1`. If it shows `unset`, the host did not pass `GLP_PRINCIPAL_ID`.

## Pitfalls

- A shared desktop session means a shared principal. Switch OS users. Do not only change a name in a chat box. The proxy never sees the chat identity.
- `auth` `env` returns that principal. It is not an identity provider. Anyone who can edit the host config can choose a role. OS permissions on the config and on the host's MCP file are the control this edition has.
- Approver and operator logs are separate files. `glp_approve` reads the log of the process that is running. Ben must open Ada's pending log to approve Ada's write, which means Ben's process must use `GLP_AUDIT_PATH=/srv/glp/ada/audit.jsonl` for that approval, then return to his own log. Two writers must not do that at the same time. Stop Ada's host before Ben opens her file. See [approval-workflow.md](approval-workflow.md).
- The upstream environment is shared. Do not put Ada's personal token in `upstreams[].env` of the shared file.
