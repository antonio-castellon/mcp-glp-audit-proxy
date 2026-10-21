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

## Hello world

Audit two calls and one denied call on the lab machine. The wheels do not contain `examples/`. Copy `examples/hello_upstream.py`, `examples/config.json`, and `examples/walkthrough.py` on the same media as the wheels. Leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install from the local wheel directory. This is the lab-machine command from the install section.

```bash
python -m pip install --no-index --find-links ./wheels --no-deps mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied `examples/config.json` with the absolute path of the copied `examples` directory's parent. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "mcp-glp-audit-proxy",
      "args": ["--config", "REPLACE_WITH_ABSOLUTE_PATH/examples/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator"
      }
    }
  }
}
```

On the lab machine you can also run `python examples/walkthrough.py` after `python -m pip install --no-index --find-links ./wheels -e .` from the copied checkout. A wheel-only install has no `examples/` until you copy that directory.

4. Restart the host on the lab machine so it launches the proxy from the offline install.

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

- `pip install mcp-glp-audit-proxy` on the lab machine will try the network. Use `--no-index`.
- A wheel built on a different operating system or Python version may not match. `mcp` and `rfc8785` publish portable wheels. Build the proxy wheel with the same major.minor Python when you can.
- `--require-hashes` fails if you hand-edit the lock. Do not strip hashes to make an install succeed.
- Offline does not mean the upstream may be started by the host. The host still only sees the proxy.
- `GLP_REQUIRE_NTP=true` on a host with no `timedatectl` refuses startup. The error is on stderr and the exit code is 1.
