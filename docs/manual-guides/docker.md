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

## Pitfalls

- `docker run` without `-i` closes stdin and the proxy exits.
- Publishing `-p` does nothing useful. Nothing in the process listens.
- The discovery role `qa` cannot call upstream tools. A lab session must set role `operator` and mount a config that names the upstream.
- Building from a context other than the repository root breaks the `COPY` paths.
- An upstream installed only on the host is not inside the image. Install it in a derived image or call it over HTTPS from `upstreams`.
