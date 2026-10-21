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

## Hello world

Audit two calls and one denied call through this host. Copy `examples/config.json` from a checkout and leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. Part 11 signatures are not part of this hello. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install the package the host will launch.

```bash
python -m pip install mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied config with the absolute path of the checkout. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

This hello is one person, one process, one log. It uses `examples/config.json` (approval gate off), not the shared hardened file on this page. Give Ada her own `GLP_AUDIT_PATH`. Ben uses a different id, name, and log.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "mcp-glp-audit-proxy",
      "args": ["--config", "REPLACE_WITH_ABSOLUTE_PATH/examples/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator",
        "GLP_AUDIT_PATH": "REPLACE_WITH_ABSOLUTE_PATH/examples/data/ada-audit.jsonl"
      }
    }
  }
}
```

4. Each person restarts only their own host process.

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

- A shared desktop session means a shared principal. Switch OS users. Do not only change a name in a chat box. The proxy never sees the chat identity.
- `auth` `env` returns that principal. It is not an identity provider. Anyone who can edit the host config can choose a role. OS permissions on the config and on the host's MCP file are the control this edition has.
- Approver and operator logs are separate files. `glp_approve` reads the log of the process that is running. Ben must open Ada's pending log to approve Ada's write, which means Ben's process must use `GLP_AUDIT_PATH=/srv/glp/ada/audit.jsonl` for that approval, then return to his own log. Two writers must not do that at the same time. Stop Ada's host before Ben opens her file. See [approval-workflow.md](approval-workflow.md).
- The upstream environment is shared. Do not put Ada's personal token in `upstreams[].env` of the shared file.
