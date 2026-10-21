# Air-gapped install

Move wheels to the lab machine on media you control. The lab machine then installs with `--no-index` so pip does not contact a network. The proxy still does not phone home. A licence file, when you have one, is local JSON. See [plugins.md](plugins.md).

The upstream must already be on that machine, or reachable at an `https://` URL the machine is allowed to dial. Installing the proxy does not install the upstream, and it does not open a path around the proxy.

## Prerequisites

- A connected machine that can download wheels, with Python 3.11 or newer
- The lab machine, same Python minor version when you can arrange it, with no requirement to reach PyPI
- Media for the wheel directory
- `pip` on both machines

## Install

On the connected machine, from a checkout that contains `requirements.lock`:

```bash
python -m pip download -r requirements.lock -d ./wheels
python -m pip wheel --no-deps -w ./wheels .
```

`requirements.lock` is a hashed lock produced by `pip-compile --generate-hashes`. Copy the `wheels` directory and the lock file to the lab machine. On the lab machine, from the directory that holds the lock:

```bash
python -m pip install --no-index --find-links ./wheels --require-hashes -r requirements.lock
python -m pip install --no-index --find-links ./wheels --no-deps mcp-glp-audit-proxy
```

The first command installs the locked dependencies, including `mcp` and `rfc8785`. The second installs the proxy wheel without resolving new packages.

If the project is already on PyPI from a machine that is allowed to download it, the connected machine can instead run:

```bash
python -m pip download mcp-glp-audit-proxy -d ./wheels
```

That downloads the distribution and its dependencies. The lab install is still `--no-index --find-links ./wheels mcp-glp-audit-proxy`. Prefer the lock file when you need the hashes recorded in this repository.

Confirm:

```bash
mcp-glp-audit-proxy --help
```

## Minimal config

Same file as a networked install. No flag changes because the machine is offline.

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
    "write_tools": ["excel__write_*"],
    "require_approval_for_writes": false,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "./data/audit.jsonl",
    "fail_closed": true
  },
  "require_ntp": false,
  "upstreams": [
    {
      "name": "excel",
      "transport": "stdio",
      "protocol": "legacy",
      "command": "python",
      "args": ["-m", "your_excel_mcp_server"],
      "env": {}
    }
  ]
}
```

`require_ntp` false is deliberate. An air-gapped host often has no `timedatectl` result, and `require_ntp` true would refuse to start.

## Hardened config

Pin the plugins, keep the licence path on local disk, and keep writes behind approval. Copy the licence file on the same media. Nothing is fetched at startup to check it.

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
    "legal_hold": true,
    "study_completion": null
  },
  "policy": {
    "allow": ["excel__read_cell"],
    "deny": ["excel__drop_*"],
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
  "licence_path": "/srv/glp/licence.json",
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

`legal_hold` true is recorded on the startup entry. The JSONL backend still has no delete operation. The flag does not by itself move files to immutable storage.

A Community licence file that names no Pro features is optional. If `licence_path` points at a missing file, startup fails when the file is opened. Use null when you have no file. The licence object, when you use one, is in [plugins.md](plugins.md).

## Verification

```bash
mcp-glp-audit-proxy --help
mcp-glp-audit-proxy-verify --help
```

Both must run with the network disconnected. After a session, verify the local log:

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --print-head
```

Copy the `seq=` line to media that leaves the machine, the same way you would copy it to a ticket. See [anchoring-and-verification.md](anchoring-and-verification.md).

## Pitfalls

- `pip install mcp-glp-audit-proxy` on the lab machine will try the network. Use `--no-index`.
- A wheel built on a different operating system or Python version may not match. `mcp` and `rfc8785` publish portable wheels. Build the proxy wheel with the same major.minor Python when you can.
- `--require-hashes` fails if you hand-edit the lock. Do not strip hashes to make an install succeed.
- Offline does not mean the upstream may be started by the host. The host still only sees the proxy.
- `GLP_REQUIRE_NTP=true` on a host with no `timedatectl` refuses startup. The error is on stderr and the exit code is 1.
