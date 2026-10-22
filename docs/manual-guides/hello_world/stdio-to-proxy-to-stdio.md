# stdio client to the proxy to a stdio target

The host, or the script below, speaks newline-delimited JSON-RPC on the proxy's stdin and stdout. The proxy starts `hello_server.py` as a child and speaks the same newline JSON-RPC to that child. This is the only client transport. The other target transport is [HTTPS](stdio-to-proxy-to-https.md).

A desktop host uses the same proxy process. The `mcpServers` block is in [generic-stdio.md](../generic-stdio.md). Do not also register `hello_server.py` in the host. The target is reached only through the proxy. See [the manual introduction](../README.md).

## Prerequisites

- Python 3.11, 3.12, or 3.13
- An empty directory. Work inside it for every command below
- Community storage for this walkthrough is that directory: `config.json`, `data/audit.jsonl`, and the one-line sidecar `data/audit.jsonl.head`. No database. SQL storage is available in Pro

## Install

```bash
python3 -m pip install mcp-glp-audit-proxy
python3 -m mcp_glp_audit_proxy --help
```

`--help` lists `--config` only. The process does not listen on a port. On Windows, the launcher in [windows-lab-pc.md](../windows-lab-pc.md) is `py -3` instead of `python3`.

## Minimal config

`init` asks for the log path, the allow list, the principal, and retention. It does not ask for a target server. You add `upstreams` after it writes the file.

```bash
python3 -m mcp_glp_audit_proxy init config.json
```

Type these answers. Press Enter alone to keep a default.

```text
Audit log path [./data/audit.jsonl]: ./data/audit.jsonl
Allow list (comma-separated globs; empty denies every tool): lab__hello
Principal id: operator-1
Principal name: Ada Analyst
Principal role (operator, approver, qa, admin) [operator]:
Retention profile (swiss_glp, minimum) [swiss_glp]:
Legal hold (yes/no) [no]:
```

The process prints `wrote config.json`. Open the file and add the `upstreams` array. The file is then:

```json proxy
{
  "audit": {
    "path": "./data/audit.jsonl"
  },
  "policy": {
    "allow": [
      "lab__hello"
    ]
  },
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "retention": {
    "legal_hold": false,
    "min_months": 6,
    "profile": "swiss_glp",
    "years_after_study": 10
  },
  "upstreams": [
    {
      "name": "lab",
      "transport": "stdio",
      "protocol": "legacy",
      "command": "python3",
      "args": [
        "hello_server.py"
      ]
    }
  ]
}
```

`lab` is the prefix. The host calls `lab__hello`. The child sees the tool name `hello`. `protocol` `legacy` matches the small server below (`initialize`). `auto` is described in [the manual introduction](../README.md).

```bash
python3 -m mcp_glp_audit_proxy config check config.json
```

A good file prints `config check ok`.

## Hardened config

Keep the allow list to the one read tool, and name the tool you do not want. `fail_closed` true is the default when the field is omitted. Set it in the file when you want it visible. Approval before writes is a separate manual: [approval-workflow.md](../approval-workflow.md). The off-host head copy is [anchoring-and-verification.md](../anchoring-and-verification.md).

```json proxy
{
  "audit": {
    "path": "./data/audit.jsonl",
    "fail_closed": true
  },
  "policy": {
    "allow": ["lab__hello"],
    "deny": ["lab__drop_*"],
    "require_approval_for_writes": false
  },
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "retention": {
    "legal_hold": false,
    "min_months": 6,
    "profile": "swiss_glp",
    "years_after_study": 10
  },
  "upstreams": [
    {
      "name": "lab",
      "transport": "stdio",
      "protocol": "legacy",
      "command": "python3",
      "args": ["hello_server.py"]
    }
  ]
}
```

The steps below use the minimal file, where `lab__drop_all` is blocked because it is not on the allow list.

## Verification

Save this target as `hello_server.py` in the same directory as `config.json`. It speaks stdio. It does not listen on a port.

```python
"""Stdio MCP server for the hello-world guide. One tool: hello."""
from __future__ import annotations

import json
import sys


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        message = json.loads(line)
        response = handle(message)
        if response is None:
            continue
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()


def handle(message: dict) -> dict | None:
    method = message.get("method")
    if "id" not in message:
        return None
    if method == "initialize":
        version = (message.get("params") or {}).get("protocolVersion")
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "hello-lab", "version": "0"},
            },
        }
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"tools": [_hello_tool()]},
        }
    if method == "tools/call":
        params = message.get("params") or {}
        if params.get("name") != "hello":
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32602, "message": "unknown tool"},
            }
        who = (params.get("arguments") or {}).get("name")
        text = "Hello, %s." % who if isinstance(who, str) and who.strip() else "Hello."
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {"content": [{"type": "text", "text": text}], "isError": False},
        }
    return {
        "jsonrpc": "2.0",
        "id": message.get("id"),
        "error": {"code": -32601, "message": "method not found"},
    }


def _hello_tool() -> dict:
    return {
        "name": "hello",
        "description": "Say hello. Read only.",
        "inputSchema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
            "additionalProperties": False,
        },
    }


if __name__ == "__main__":
    main()
```

Save this client as `call_lab.py`. It starts the proxy and sends one allowed call and one blocked call. The proxy command it runs is `python3 -m mcp_glp_audit_proxy --config config.json`. The official SDK shape is [python-sdk.md](../python-sdk.md).

```python
"""One allowed tool call and one blocked tool call through the proxy."""
from __future__ import annotations

import json
import os
import subprocess
import sys


def main() -> None:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GLP_")}
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_glp_audit_proxy", "--config", "config.json"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        env=env,
    )

    def rpc(message: dict) -> dict:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            raise SystemExit("proxy closed stdout")
        return json.loads(line)

    rpc(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "hello-world", "version": "0"},
            },
        }
    )
    allowed = rpc(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "lab__hello", "arguments": {"name": "Ada"}},
        }
    )
    blocked = rpc(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "lab__drop_all", "arguments": {}},
        }
    )
    print("ALLOWED", json.dumps(allowed["result"]))
    print("BLOCKED", json.dumps(blocked["result"]))
    proc.stdin.close()
    proc.wait(timeout=8)


if __name__ == "__main__":
    main()
```

```bash
python3 call_lab.py
```

Stdout ends with these two lines. The hash and the timestamps are not on these lines.

```text
ALLOWED {"content": [{"type": "text", "text": "Hello, Ada."}], "isError": false}
BLOCKED {"content": [{"type": "text", "text": "denied by policy (allow:none)"}], "isError": true}
```

`lab__hello` was forwarded to the child. `lab__drop_all` was not. The proxy still logs the blocked call. Read the four records:

```bash
python3 -c 'import json,pathlib
p=pathlib.Path("data/audit.jsonl")
for line in p.read_text().splitlines():
    if not line.strip():
        continue
    row=json.loads(line)
    print(row.get("method"), row.get("tool"), row.get("status"))
'
```

```text
audit/startup None ok
initialize None ok
tools/call lab__hello ok
tools/call lab__drop_all denied
```

Verify the chain. Exit 0. Stderr contains `chain ok entries=4 shown=4`. `--print-head` adds one stdout line `seq=4 entry_hash=<64 hex>`. The hex changes every run. Copy it off the machine. The field list is in [anchoring-and-verification.md](../anchoring-and-verification.md).

```bash
python3 -m mcp_glp_audit_proxy verify data/audit.jsonl --print-head
python3 -m mcp_glp_audit_proxy verify data/audit.jsonl --tool lab__hello --status ok
python3 -m mcp_glp_audit_proxy verify data/audit.jsonl --tool lab__drop_all --status denied
```

The `--tool` runs still print `chain ok`. `shown=1`. The hello line has `status=ok`. The drop line has `status=denied`.

## Pitfalls

- `GLP_PRINCIPAL_ID`, `GLP_PRINCIPAL_NAME`, and `GLP_PRINCIPAL_ROLE` override the file. `call_lab.py` removes every `GLP_*` variable before it starts the proxy. If you start the proxy yourself, unset those variables or the principal will not match this page.
- An empty allow list denies every target tool. `lab__hello` must be on the allow list or the allowed call is blocked too.
- The role must be `operator`. `qa`, `approver`, and `admin` cannot call a target tool.
- Do not point the host at `hello_server.py` and at the proxy. Calls that skip the proxy are not in the log.
- A PyPI install has no `examples/` directory. The checkout walkthrough is [QUICKSTART.md](../QUICKSTART.md).
- A refused startup prints `mcp-glp-audit-proxy:` on stderr and exits 1. There is no port. See [troubleshooting.md](../troubleshooting.md).
