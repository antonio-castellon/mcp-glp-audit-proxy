# Approval workflow

A write can be held until a different person, in role `approver`, records `meaning` `approved`. The record's label is `approval`. It is not an electronic signature. `reviewed` is stored with status `reviewed` and does not authorise the write. `rejected` does not authorise it. Only `meaning` `approved` does.

The gate is `policy.require_approval_for_writes`. The tool name must also match `policy.write_tools`. The caller must be role `operator`. The approver's principal id must differ from the requester's id.

The upstream is called only after the gate passes, and only by the proxy. The approver's host must not call the upstream itself.

## Prerequisites

- Two OS users, or two host configs that are not running at the same time against one log
- Operator config with `require_approval_for_writes` true and the write tool listed in `write_tools`
- Approver config that reads the same audit file, role `approver`
- `mcp-glp-audit-proxy` installed for both

## Install

```bash
python -m pip install mcp-glp-audit-proxy
```

## Minimal config

Operator file. Approval on, one write tool, reason required (the default).

```json proxy
{
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "policy": {
    "allow": ["excel__read_cell", "excel__write_cell"],
    "deny": [],
    "write_tools": ["excel__write_cell"],
    "require_approval_for_writes": true,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "/srv/glp/study-14/audit.jsonl",
    "fail_closed": true
  },
  "approval_ttl_seconds": 3600,
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

Approver file. Same log. No need for the operator's allow list to be usable: role `approver` cannot call upstream tools. Keep the upstream block so the file still parses, or use an empty `upstreams` list. Empty is safer on the approver workstation. This sample uses an empty list.

```json proxy
{
  "principal": {
    "id": "approver-1",
    "name": "Ben Reviewer",
    "role": "approver"
  },
  "policy": {
    "allow": [],
    "deny": [],
    "write_tools": ["excel__write_cell"],
    "require_approval_for_writes": true,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "/srv/glp/study-14/audit.jsonl",
    "fail_closed": true
  },
  "approval_ttl_seconds": 3600,
  "upstreams": []
}
```

The operator's host `env` sets `GLP_PRINCIPAL_ROLE=operator`. The approver's host sets `approver`. Stop the operator process before the approver opens the same file. The store is one writer.

## Hardened config

Shorter TTL, explicit plugins, reason required. `approval_ttl_seconds` of 0 is stored as 3600. Use a positive number.

```json proxy
{
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "policy": {
    "allow": ["excel__read_cell", "excel__write_cell"],
    "deny": ["excel__drop_*"],
    "write_tools": ["excel__write_cell"],
    "require_approval_for_writes": true,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "/srv/glp/study-14/audit.jsonl",
    "fail_closed": true,
    "checkpoint_every": 50
  },
  "approval_ttl_seconds": 900,
  "require_ntp": false,
  "export_dir": "/srv/glp/study-14/exports",
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

1. Operator calls the write. The reason is `_meta["io.github.antonio-castellon/reason"]` or the argument `_glp_reason`. `_glp_reason` is removed before the approval hash and before the upstream call. The hash covers the tool name and the arguments the upstream would see.

```json rpc
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "excel__write_cell",
    "arguments": {
      "cell": "B2",
      "value": 1,
      "_glp_reason": "enter the calibration result"
    },
    "_meta": {
      "io.github.antonio-castellon/reason": "enter the calibration result"
    }
  }
}
```

The call is not forwarded. The tool text contains `approval_id=` and `args_hash=`. The audit status is `pending_approval`. `isError` is true.

2. Approver, on the same log, calls `glp_approve`.

```json rpc
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "glp_approve",
    "arguments": {
      "approval_id": "<the id from the pending text>",
      "meaning": "approved"
    }
  }
}
```

`meaning` `reviewed` stores status `reviewed` and the text says it does not authorise the write. `meaning` `rejected` stores status `rejected`. The operator cannot call `glp_approve` (role). The requester cannot approve their own id.

3. Operator calls the same tool with the same arguments and:

```json rpc
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "excel__write_cell",
    "arguments": {
      "cell": "B2",
      "value": 1
    },
    "_meta": {
      "io.github.antonio-castellon/reason": "enter the calibration result",
      "io.github.antonio-castellon/approvalId": "<the same id>"
    }
  }
}
```

A successful upstream call consumes the approval. The consumption is recorded even if an admin turned `require_approval_for_writes` off before this call, as long as the approval matches this tool and these arguments. A failed upstream call does not consume it. A mismatched id is not consumed. A second successful write with the same id is refused.

Then:

```bash
mcp-glp-audit-proxy-verify /srv/glp/study-14/audit.jsonl --tool glp_approve --print-head
mcp-glp-audit-proxy-verify /srv/glp/study-14/audit.jsonl --tool excel__write_cell --status ok
```

## Pitfalls

- Changing any upstream argument changes the hash. The old approval does not cover the new call.
- `approval_ttl_seconds` 0 becomes 3600. A short gate is a positive number such as 900.
- Two processes must not append to `study-14/audit.jsonl` at once.
- A host-side "approve tool" button is not `glp_approve` unless it calls that tool as role `approver`.
- Logs written before schema 1.1.0 may show a review as status `approved` with meaning `reviewed`. Those lines still verify and still do not authorise a write.
- An approval is single-use only for a matching successful write. It is not consumed by mentioning the id on a different tool.
