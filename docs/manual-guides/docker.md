# Docker and a Glama-style image

The proxy is a stdio process. The upstream is reached only through the proxy, including when the proxy runs in a container. The container has no published port. A host runs `docker run -i` and speaks JSON-RPC on stdin and stdout. The upstream runs only where the proxy config says, which should be inside this container or on an `https://` URL the container can reach. Do not publish the upstream's port on the host.

Glama's hosting docs build a Dockerfile (or a PyPI module) and wrap stdio for a Streamable HTTP gateway. Point that build at `docs/manual-guides/docker/Dockerfile`. The image answers `initialize` and `tools/list` with a discovery principal so a scanner can start it. That principal is not a lab user. A real host overrides `GLP_PRINCIPAL_*` and mounts its own config.

This VM had no Docker daemon when the guide was written. The entrypoint command and the discovery config are what the tests run. Build the image on a machine that has Docker before you publish it.

## Prerequisites

- Docker, on a machine that will build the image
- A checkout of this repository (the Dockerfile installs the local tree, so it does not need a PyPI release)
- For a real lab run, a config file and an upstream the container can execute or dial

## Install

From the repository root:

```bash
docker build -f docs/manual-guides/docker/Dockerfile -t mcp-glp-audit-proxy:local .
```

The Dockerfile is:

```dockerfile
# Stdio image for mcp-glp-audit-proxy.
# Build from the repository root:
#   docker build -f docs/manual-guides/docker/Dockerfile -t mcp-glp-audit-proxy:local .
# No port is published. A host attaches stdin. Glama can point at this file
# and wrap stdio. The baked principal is for discovery only.

FROM python:3.12-slim

RUN useradd --create-home --uid 10001 proxy
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY docs/manual-guides/docker/discovery.config.json /app/discovery.config.json

RUN pip install --no-cache-dir . \
    && chown -R proxy:proxy /app

USER proxy

ENV GLP_CONFIG=/app/discovery.config.json \
    GLP_PRINCIPAL_ID=discovery \
    GLP_PRINCIPAL_NAME=Discovery \
    GLP_PRINCIPAL_ROLE=qa

ENTRYPOINT ["mcp-glp-audit-proxy"]
CMD ["--config", "/app/discovery.config.json"]
```

Discovery config baked into the image (`docs/manual-guides/docker/discovery.config.json`):

```json proxy
{
  "principal": {
    "id": "discovery",
    "name": "Discovery",
    "role": "qa"
  },
  "policy": {
    "allow": [],
    "deny": [],
    "write_tools": [],
    "require_approval_for_writes": true,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "/tmp/mcp-glp-audit-proxy-discovery.jsonl",
    "fail_closed": true,
    "checkpoint_every": 100
  },
  "require_ntp": false,
  "export_dir": "/tmp/mcp-glp-audit-proxy-discovery-exports",
  "licence_path": null,
  "plugins": {
    "storage": "jsonl",
    "signer": "unsigned",
    "reporters": ["json", "text"],
    "auth": "env"
  },
  "upstreams": []
}
```

`role` `qa` and an empty `upstreams` list let `tools/list` return the local QA tools without dialing a network. `require_ntp` is false because a slim image often has no `timedatectl`.

## Minimal config

Host side, for a discovery run. `-i` keeps stdin open. There is no `-p`.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "mcp-glp-audit-proxy:local"]
    }
  }
}
```

The image's `ENV` supplies the discovery principal. `--rm` is a Docker flag, not a proxy flag.

## Hardened config

Mount the lab config read-only, mount a data directory read-write, and override identity. Do not rely on the discovery principal. The lab config's upstream `command` must exist in the image, or its `url` must be an `https://` address the container can reach. A command that only exists on the laptop will not be visible inside the container.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "--network",
        "lab-internal",
        "-v",
        "/srv/glp/config.json:/config/config.json:ro",
        "-v",
        "/srv/glp/operator-1:/data",
        "-e",
        "GLP_PRINCIPAL_ID=operator-1",
        "-e",
        "GLP_PRINCIPAL_NAME=Ada Analyst",
        "-e",
        "GLP_PRINCIPAL_ROLE=operator",
        "-e",
        "GLP_AUDIT_PATH=/data/audit.jsonl",
        "mcp-glp-audit-proxy:local",
        "--config",
        "/config/config.json"
      ]
    }
  }
}
```

`--network lab-internal` is a Docker network you create so the container can reach the LIMS and the host's other processes cannot. Omit a published port. The proxy flag in that argument list is `--config`. The `-e` names are the environment variables in the index.

Glama's form can set the same environment variables on the deployment and can override CMD. Set `GLP_PRINCIPAL_*` there for a real user. Leave the image without a baked upstream token.

## Verification

Without Docker, the same entrypoint is:

```bash
GLP_PRINCIPAL_ID=discovery GLP_PRINCIPAL_NAME=Discovery GLP_PRINCIPAL_ROLE=qa mcp-glp-audit-proxy --config docs/manual-guides/docker/discovery.config.json
```

Pipe one initialize line, as in [generic-stdio.md](generic-stdio.md). With Docker:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"check","version":"0"}}}' | docker run -i --rm mcp-glp-audit-proxy:local
```

`result.serverInfo.name` is `mcp-glp-audit-proxy`. Then verify the log on the mounted data directory:

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --print-head
```

## Hello world

Audit two calls and one denied call through this host. Copy `examples/config.json` from a checkout and leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. Part 11 signatures are not part of this hello. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install the package the host will launch.

```bash
python -m pip install mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied config with the absolute path of the checkout. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

Edit the copied config before you mount it. Inside the container the upstream command is `python`, the args are `["/examples/hello_upstream.py"]`, and `cwd` is `/examples`. A host path in `REPLACE_WITH_ABSOLUTE_PATH` does not exist in the container. Build the image from this repository first (`docker build -t mcp-glp-audit-proxy:local .`). The image has no published port.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v",
        "REPLACE_WITH_ABSOLUTE_PATH/examples:/examples:ro",
        "-v",
        "REPLACE_WITH_ABSOLUTE_PATH/examples/config.json:/config/config.json:ro",
        "-v",
        "REPLACE_WITH_ABSOLUTE_PATH/examples/data:/data",
        "-e",
        "GLP_PRINCIPAL_ID=operator-1",
        "-e",
        "GLP_PRINCIPAL_NAME=Ada Analyst",
        "-e",
        "GLP_PRINCIPAL_ROLE=operator",
        "-e",
        "GLP_AUDIT_PATH=/data/audit.jsonl",
        "mcp-glp-audit-proxy:local",
        "--config",
        "/config/config.json"
      ]
    }
  }
}
```

The notes file is written in the upstream `cwd`. Mount that directory read-write if you need `hello-notes.txt` on the host. The log mount `/data` is the read-write one.

4. The next `docker run -i` is a new process. Restart the host that holds this entry so it launches that run.

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

- `docker run` without `-i` closes stdin and the proxy exits.
- Publishing `-p` does nothing useful. Nothing in the process listens.
- The discovery role `qa` cannot call upstream tools. A lab session must set role `operator` and mount a config that names the upstream.
- Building from a context other than the repository root breaks the `COPY` paths.
- An upstream installed only on the host is not inside the image. Install it in a derived image or call it over HTTPS from `upstreams`.
