# HTTPS gateway

Community 0.4.0 can sit on an HTTPS base URL. The client keeps its request and changes that URL to the proxy. The proxy writes one hash-chained record and calls the upstream over TLS 1.3. The commercial name is GxP Gateway Audit. The package name is still `mcp-glp-audit-proxy`.

This page is numbered. Do the stdio page first if you have not installed the package. The words below are what you should see. You do not need to know Python. You paste the programs.

The six flows are `mcp2mcp`, `mcp2api`, `api2mcp`, `api2api`, `mcp2llm`, and `api2llm`. This page builds `api2api` on the listener. The last config block is the stdio side of `mcp2api` and `mcp2llm`. `mcp2mcp` is the stdio-to-HTTPS page. `api2mcp` and `api2llm` are the extra routes in the hardened file.

## Prerequisites

- Python 3.11 or newer, with `python3` on Linux or macOS and `py -3` on Windows.
- OpenSSL on the PATH. The sample certificates exist only for this folder and expire in two days.
- A folder you can write, called `glp-hello-gateway`.

## Install

Step 1. Make the folder and move into it.

Linux or macOS:

```bash
mkdir glp-hello-gateway
cd glp-hello-gateway
python3 -m pip install mcp-glp-audit-proxy
```

Windows (Command Prompt):

```bash
mkdir glp-hello-gateway
cd glp-hello-gateway
py -3 -m pip install mcp-glp-audit-proxy
```

A new install ends with a line that contains `Successfully installed` and `mcp-glp-audit-proxy-0.4.0`. If it is already installed, the line says `Requirement already satisfied`.

Step 2. Check the version.

Linux or macOS:

```bash
python3 -m pip show mcp-glp-audit-proxy
```

Windows:

```bash
py -3 -m pip show mcp-glp-audit-proxy
```

`Version:` should be `0.4.0`.

## Minimal config

Step 3. Save this file as `server.ext` in `glp-hello-gateway`:

```text
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
```

Step 4. Make a tiny CA, a server certificate, and a client certificate. Stay in `glp-hello-gateway`. The commands are the same on Linux, macOS, and Windows.

```bash
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 2 -nodes -subj "/CN=lab-ca"
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes -subj "/CN=127.0.0.1"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 2 -extfile server.ext
openssl req -newkey rsa:2048 -keyout client.key -out client.csr -nodes -subj "/CN=operator-9"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 2
```

OpenSSL prints dots and plus signs while it makes a key. That is normal. When it finishes, the prompt comes back. You should have `ca.crt`, `server.crt`, `server.key`, `client.crt`, and `client.key`. Leave the keys in this folder. Do not send them to anyone.

Step 5. Print the client fingerprint. You will paste it into the config.

Linux or macOS:

```bash
openssl x509 -in client.crt -outform DER | openssl dgst -sha256
```

Windows:

```bash
openssl x509 -in client.crt -outform DER | openssl dgst -sha256
```

You should see `SHA256=` and 64 hex characters. Copy those 64 characters. Drop the `SHA256=` prefix and any colons.

Step 6. Save this file as `config.json`. Replace the 64 zeros with the fingerprint from step 5. The same file is used on Windows, macOS, and Linux.

```json proxy
{
  "audit": {
    "path": "./data/audit.jsonl",
    "body_mode": "hash_only",
    "fail_closed": true
  },
  "policy": {
    "allow": ["api__*"],
    "deny": [],
    "http_allow": ["GET /v1/studies/*"],
    "http_deny": ["GET /v1/studies/hidden"],
    "require_reason_for_writes": true
  },
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "retention": {
    "profile": "swiss_glp",
    "min_months": 6,
    "years_after_study": 10,
    "legal_hold": false
  },
  "listen": {
    "bind": "127.0.0.1",
    "port": 8443,
    "cert_file": "./server.crt",
    "key_file": "./server.key",
    "identity": {
      "mode": "mtls",
      "client_ca_file": "./ca.crt",
      "principals": [
        {
          "fingerprint": "0000000000000000000000000000000000000000000000000000000000000000",
          "id": "operator-9",
          "name": "Ada Analyst",
          "role": "operator"
        }
      ]
    }
  },
  "routes": [
    {
      "flow": "api2api",
      "methods": ["GET"],
      "path": "/v1/studies/{study}",
      "upstream": "api",
      "upstream_path": "/studies/{study}"
    }
  ],
  "upstreams": [
    {
      "name": "api",
      "transport": "https",
      "kind": "api",
      "url": "https://127.0.0.1:9443",
      "ca_file": "./ca.crt",
      "endpoints": [
        {"tool": "get_study", "method": "GET", "path": "/studies/{study}"}
      ]
    }
  ]
}
```

What the new fields mean:

- `audit.body_mode` `hash_only` stores the SHA-256 of the body and no body bytes. That is the default. `redacted` stores JSON with the paths in `redact_paths` replaced by `***`. `full` stores the request body in the log and also stores the response text as `response_body`. Which value to use is the customer's and QA's decision. The log is mode 0600. The hash is stored in every mode.
- `policy.http_allow` is `METHOD` then a space then a path glob. Empty denies every HTTPS route. It does not deny an MCP tool call.
- `policy.http_deny` wins over allow. `GET /v1/studies/hidden` is denied even if the allow glob matches.
- `listen` is what opens the socket. The command line is still only `--config`. `port` 8443 is the base URL the client uses.
- `identity.mode` `mtls` requires a client certificate. `bearer` reads one token from a private file. `mtls_and_bearer` requires both. There is no open mode.
- `routes` `flow` `api2api` forwards an HTTPS call to an HTTPS API. `upstream_path` is the path on that API. `{study}` is copied from the request path.
- `kind` `api` means the upstream is an HTTPS API. `kind` `llm` is the same transport with record kind `llm`. `kind` `mcp` is a JSON-RPC MCP server.

Step 7. Check that the file loads.

Linux or macOS:

```bash
python3 -m mcp_glp_audit_proxy config check config.json
```

Windows:

```bash
py -3 -m mcp_glp_audit_proxy config check config.json
```

You should see:

```text
config check ok
```

If the fingerprint is not 64 hex characters, the check prints a plain-language error and exits 1. Fix the fingerprint and run the check again.

## Hardened config

Step 8. You can skip this step and keep the file from step 6. This file adds a bearer token, redacted bodies, and the other inbound flows. Save it over `config.json` only if you want that. Create `bearer.token` first, one line, no quotes.

Linux or macOS:

```bash
chmod 600 bearer.token
```

Windows (Command Prompt or PowerShell). This removes inherited access and grants read to the current user and full control to SYSTEM and Administrators:

```text
icacls bearer.token /inheritance:r /grant:r "%USERNAME%:R" SYSTEM:F Administrators:F
```

If the path contains a space, put quotes around the file. Startup allows access only for the current user, SYSTEM, and BUILTIN\Administrators. If Everyone, Users, Authenticated Users, or another account has access, the process refuses to start and prints that command.

```json proxy
{
  "audit": {
    "path": "./data/audit.jsonl",
    "body_mode": "redacted",
    "redact_paths": ["$.password"],
    "max_body_bytes": 1048576,
    "fail_closed": true
  },
  "policy": {
    "allow": ["lab__*", "api__*", "llm__*"],
    "deny": [],
    "http_allow": ["GET /v1/studies/*", "POST /v1/studies/*", "POST /v1/chat", "POST /tools/hello"],
    "http_deny": ["POST /v1/studies/secret"],
    "require_reason_for_writes": true,
    "require_approval_for_writes": false
  },
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "retention": {
    "profile": "swiss_glp",
    "min_months": 6,
    "years_after_study": 10,
    "legal_hold": false
  },
  "listen": {
    "bind": "127.0.0.1",
    "port": 8443,
    "cert_file": "./server.crt",
    "key_file": "./server.key",
    "identity": {
      "mode": "mtls_and_bearer",
      "client_ca_file": "./ca.crt",
      "bearer_token_file": "./bearer.token",
      "bearer_principal": {
        "id": "gateway-1",
        "name": "Lab Gateway",
        "role": "operator"
      },
      "principals": [
        {
          "fingerprint": "0000000000000000000000000000000000000000000000000000000000000000",
          "id": "operator-9",
          "name": "Ada Analyst",
          "role": "operator"
        }
      ],
      "end_user_header": "X-Audit-End-User",
      "end_users": [
        {"id": "operator-9", "name": "Ada Analyst", "role": "operator"}
      ]
    }
  },
  "routes": [
    {
      "flow": "api2api",
      "methods": ["GET", "POST"],
      "path": "/v1/studies/{study}",
      "upstream": "api",
      "upstream_path": "/studies/{study}"
    },
    {
      "flow": "api2mcp",
      "methods": ["POST"],
      "path": "/tools/hello",
      "upstream": "lab",
      "tool": "hello"
    },
    {
      "flow": "api2llm",
      "methods": ["POST"],
      "path": "/v1/chat",
      "upstream": "llm",
      "upstream_path": "/v1/chat/completions"
    }
  ],
  "upstreams": [
    {
      "name": "api",
      "transport": "https",
      "kind": "api",
      "url": "https://127.0.0.1:9443",
      "ca_file": "./ca.crt",
      "endpoints": [
        {"tool": "get_study", "method": "GET", "path": "/studies/{study}"}
      ]
    },
    {
      "name": "lab",
      "transport": "https",
      "kind": "mcp",
      "protocol": "legacy",
      "url": "https://127.0.0.1:9443/mcp",
      "ca_file": "./ca.crt"
    },
    {
      "name": "llm",
      "transport": "https",
      "kind": "llm",
      "url": "https://127.0.0.1:9443",
      "ca_file": "./ca.crt",
      "endpoints": [
        {"tool": "chat", "method": "POST", "path": "/v1/chat/completions"}
      ]
    }
  ]
}
```

`end_user_header` is read only after mTLS and the bearer both succeed. The value must be a configured `id`. A shared bearer is a gate, not a unique user id. Per-user attribution (one client certificate per person, or this header from a gateway that already checked the person) is the mode that fits the expectations in the repository README. The package is designed to support that attribution.

A `POST`, `PUT`, `PATCH`, or `DELETE` needs the header `X-Audit-Reason` when `require_reason_for_writes` is true. The reason is stored. The header itself is not copied into the stored header map.

The stdio side of `mcp2api` and `mcp2llm` has no `listen` object. The MCP host talks to the proxy on stdin. The proxy calls the HTTPS API. Save this as `stdio.json` if you want that shape. `body_mode` still applies to those calls.

```json proxy
{
  "audit": {
    "path": "./data/audit.jsonl",
    "body_mode": "hash_only",
    "fail_closed": true
  },
  "policy": {
    "allow": ["api__*", "llm__*"],
    "deny": [],
    "require_reason_for_writes": true
  },
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "retention": {
    "profile": "swiss_glp",
    "min_months": 6,
    "years_after_study": 10,
    "legal_hold": false
  },
  "upstreams": [
    {
      "name": "api",
      "transport": "https",
      "kind": "api",
      "url": "https://127.0.0.1:9443",
      "ca_file": "./ca.crt",
      "endpoints": [
        {"tool": "get_study", "method": "GET", "path": "/studies/{study}"}
      ]
    },
    {
      "name": "llm",
      "transport": "https",
      "kind": "llm",
      "url": "https://127.0.0.1:9443",
      "ca_file": "./ca.crt",
      "endpoints": [
        {"tool": "chat", "method": "POST", "path": "/v1/chat/completions"}
      ]
    }
  ]
}
```

## Verification

Step 9. Start a sample API on port 9443. It uses the certificate from step 4 and speaks TLS 1.3. Save this as `lab_server.py`.

```python
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/studies/"):
            study = self.path.split("?", 1)[0].rsplit("/", 1)[-1]
            body = json.dumps({"id": study}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt, *args):
        return None


class Server(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 9443), Handler)
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.load_cert_chain("server.crt", "server.key")

    def get_request(self):
        sock, address = super().get_request()
        try:
            return self.ssl_context.wrap_socket(sock, server_side=True), address
        except ssl.SSLError:
            sock.close()
            raise


Server().serve_forever()
```

Linux or macOS:

```bash
python3 lab_server.py
```

Windows:

```bash
py -3 lab_server.py
```

The window stays open and prints nothing. That is the sample API. Leave it running. A real upstream must be `https://`. Point `ca_file` at that server's certificate and change the URL. The proxy refuses an `http://` upstream.

Step 10. In a second window, start the proxy from `glp-hello-gateway`.

Linux or macOS:

```bash
mcp-glp-audit-proxy --config config.json
```

Windows:

```bash
py -3 -m mcp_glp_audit_proxy --config config.json
```

You should not see `refusing to start`. The process stays running. It is waiting for HTTPS calls. It does not read stdin in this config.

Step 11. Save this client as `call.py` and run it in a third window.

```python
import ssl
import urllib.request

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_verify_locations("ca.crt")
context.load_cert_chain("client.crt", "client.key")
request = urllib.request.Request("https://127.0.0.1:8443/v1/studies/S1")
with urllib.request.urlopen(request, context=context) as response:
    print(response.status)
    print(response.read().decode("utf-8"))
```

Linux or macOS:

```bash
python3 call.py
```

Windows:

```bash
py -3 call.py
```

You should see:

```text
200
{"id":"S1"}
```

Step 12. Stop the proxy with Ctrl+C. Verify the log.

Linux or macOS:

```bash
mcp-glp-audit-proxy-verify data/audit.jsonl --print-head
```

Windows:

```bash
py -3 -m mcp_glp_audit_proxy verify data/audit.jsonl --print-head
```

You should see one line:

```text
seq=<n> entry_hash=<64 hex>
```

Exit code 0 means the chain verified. Open `data/audit.jsonl`. The call row has `"flow":"api2api"`, `"transport":"https"`, `"schema_version":"1.2.0"`, and `http.body_sha256` set to 64 hex characters. With `hash_only`, `http.body` is null. The path is `/v1/studies/S1`. A query string, if you added one, is not in the file.

A `GET /v1/studies/hidden` row has `"status":"denied"` and a policy rule that starts with `deny:`.

## Pitfalls

- On Linux and macOS the bearer file must be mode 0600. Mode 0644 makes the process print `refusing to start` and exit 1. On Windows the NTFS ACL may grant access only to the current user, SYSTEM, and BUILTIN\Administrators. Another principal makes the process refuse to start and print `icacls bearer.token /inheritance:r /grant:r "%USERNAME%:R" SYSTEM:F Administrators:F`. The token is never written to the log. Do not put it in the config.
- A fingerprint that does not match the client certificate returns 401. The row principal id is `unauthenticated` and the role is `system`. A failed TLS handshake is not a row, because there was no HTTP request.
- `POST` without `X-Audit-Reason` returns 403 and is not forwarded. The row rule is `write:reason-missing`.
- A body larger than `max_body_bytes` returns 413. `http.body_sha256` is null. The upstream is not called.
- Streaming is not in this version. A write without `Content-Length`, or with `Transfer-Encoding`, is refused with 411 and logged. GET and HEAD with no body are unchanged.
- If the log cannot be written, the proxy returns 503 and does not return the upstream body. Later calls stay blocked until you restart the process. Follow the reconciliation note in the repository if the upstream may already have applied the write.
- `http_allow` empty denies every HTTPS route. It does not block stdio MCP tools. Add a route glob before you expect a call to pass.
- Plain HTTP to the listener does not return an HTTP status line. The socket speaks TLS 1.3 only.

If it does not work:

- `config check` exits 1: read the one error line. The usual causes are a short fingerprint, a route flow that does not match the upstream `kind`, or `api2mcp` with no `tool`.
- The client says the certificate is not trusted: `call.py` must load `ca.crt`, and the server certificate must list `127.0.0.1`.
- The client says the handshake failed: the client has to offer TLS 1.3 and, for `mtls`, the client certificate.
- The proxy prints `refusing to start` and the bearer file is the cause: on Linux or macOS set mode 0600. On Windows run the `icacls` command printed in the error (`icacls bearer.token /inheritance:r /grant:r "%USERNAME%:R" SYSTEM:F Administrators:F`). Put exactly one line in the file.
- You see 404 `no route for this request`: the method or the path does not match a `routes` entry. The path in the record is the concrete path. The route field is the template.
- You see 403 `allow:none`: add the method and path to `http_allow`, or remove a matching `http_deny` line.
