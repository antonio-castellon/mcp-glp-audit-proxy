# stdio client to the proxy to an HTTPS target

The client side is the same stdio process as [stdio-to-proxy-to-stdio.md](stdio-to-proxy-to-stdio.md). The target is different: the proxy POSTs one JSON-RPC object to `https://127.0.0.1:8443/mcp`. TLS 1.3 is required. The response body is one JSON object. This package does not parse an SSE stream.

The proxy still does not listen. `https_lab.py` is the target, and it is the process that listens. Do not register that server in the host. See [the manual introduction](../README.md).

## Prerequisites

- Python 3.11, 3.12, or 3.13
- `openssl` on the same machine, to make a 2-day certificate for `127.0.0.1`
- An empty directory. Community storage here is `config.json`, `data/audit.jsonl`, and the one-line sidecar `data/audit.jsonl.head`. The certificate and key are extra files in that directory. They are not the audit trail. No database. SQL storage is available in Pro

## Install

```bash
python3 -m pip install mcp-glp-audit-proxy
python3 -m mcp_glp_audit_proxy --help
```

`--help` lists `--config` only. On Windows, use the launcher in [windows-lab-pc.md](../windows-lab-pc.md).

## Minimal config

Create a certificate whose name is the IP the proxy dials. The proxy checks the name.

```bash
openssl req -x509 -newkey rsa:2048 -keyout lab.key -out lab.crt -days 2 -nodes -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1"
```

`init` writes the principal, the allow list, and the log path. It does not ask for a URL.

```bash
python3 -m mcp_glp_audit_proxy init config.json
```

```text
Audit log path [./data/audit.jsonl]: ./data/audit.jsonl
Allow list (comma-separated globs; empty denies every tool): lab__hello
Principal id: operator-1
Principal name: Ada Analyst
Principal role (operator, approver, qa, admin) [operator]:
Retention profile (swiss_glp, minimum) [swiss_glp]:
Legal hold (yes/no) [no]:
```

The process prints `wrote config.json`. Add `upstreams`:

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
      "transport": "https",
      "protocol": "legacy",
      "url": "https://127.0.0.1:8443/mcp"
    }
  ]
}
```

`http://127.0.0.1:8443/mcp` is refused. Headers on an https target, when you need them, come from that upstream's `headers` object. The host token is not copied. See [generic-stdio.md](../generic-stdio.md).

```bash
python3 -m mcp_glp_audit_proxy config check config.json
```

A good file prints `config check ok`.

## Hardened config

Deny the tool you do not want, and keep TLS. `fail_closed` true refuses to continue after the audit log cannot be written. See [troubleshooting.md](../troubleshooting.md) and [anchoring-and-verification.md](../anchoring-and-verification.md).

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
      "transport": "https",
      "protocol": "legacy",
      "url": "https://127.0.0.1:8443/mcp"
    }
  ]
}
```

The steps below use the minimal file.

## Verification

Save this target as `https_lab.py`. It listens on `127.0.0.1:8443` only. Each POST returns one JSON object.

```python
"""HTTPS JSON-RPC MCP server for the hello-world guide. TLS 1.3. One tool: hello."""
from __future__ import annotations

import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


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


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        message = json.loads(self.rfile.read(length).decode("utf-8"))
        response = handle(message)
        if response is None:
            body = b"{}"
        else:
            body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("lab.crt", "lab.key")
    server = ThreadingHTTPServer(("127.0.0.1", 8443), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
```

Start it in one terminal and leave it running:

```bash
python3 https_lab.py
```

Save the same client used by the stdio walkthrough as `call_lab.py`. It starts `python3 -m mcp_glp_audit_proxy --config config.json` and sends the two calls.

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

Point the proxy at the certificate, then run the client from the directory that holds `config.json`:

```bash
export SSL_CERT_FILE="$PWD/lab.crt"
python3 call_lab.py
```

```text
ALLOWED {"content": [{"type": "text", "text": "Hello, Ada."}], "isError": false}
BLOCKED {"content": [{"type": "text", "text": "denied by policy (allow:none)"}], "isError": true}
```

The allowed call is the POST to the HTTPS target. The blocked call is not sent. Read the log:

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

```bash
python3 -m mcp_glp_audit_proxy verify data/audit.jsonl --print-head
python3 -m mcp_glp_audit_proxy verify data/audit.jsonl --tool lab__hello --status ok
python3 -m mcp_glp_audit_proxy verify data/audit.jsonl --tool lab__drop_all --status denied
```

Exit 0. Stderr contains `chain ok entries=4`. `--print-head` prints `seq=4 entry_hash=<64 hex>`. The `--tool` runs print `shown=1`, `status=ok` for hello and `status=denied` for drop. Stop `https_lab.py` with Ctrl-C when you are done.

## Pitfalls

- `SSL_CERT_FILE` must be the `lab.crt` you just wrote, and the URL host must be `127.0.0.1`. A certificate for `localhost` does not match that URL. Without the variable, the proxy rejects the certificate.
- Start `https_lab.py` before `call_lab.py`. The blocked call does not need the server. The allowed call does.
- `http://` is refused. An SSE body is not a JSON object, so it is refused too.
- `GLP_PRINCIPAL_*` overrides the file. `call_lab.py` drops those variables. Unset them if you start the proxy yourself.
- The role must be `operator`. An empty allow list denies every target tool.
- Do not publish port 8443 to the host as a second MCP server. Calls that skip the proxy are not in the log.
- A PyPI install has no `examples/` directory. The checkout walkthrough is [QUICKSTART.md](../QUICKSTART.md). The stdio child target is [stdio-to-proxy-to-stdio.md](stdio-to-proxy-to-stdio.md).
