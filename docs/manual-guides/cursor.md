# Cursor

Cursor reads MCP servers from `mcp.json` and merges the project file with the user file. The repository root `mcp.json` in this project is only a sample. Cursor does not load that path. Use the paths in the Cursor MCP docs:

- Project: `.cursor/mcp.json`
- User, all projects: `~/.cursor/mcp.json`

If the same server name is in both, the project entry wins. The Cursor CLI uses the same files.

The host entry is the proxy. The upstream is not a second server. It is `upstreams` inside the proxy config. See [generic-stdio.md](generic-stdio.md).

## Prerequisites

- Cursor, or the `agent` CLI
- Python 3.11 or newer
- `mcp-glp-audit-proxy` on PATH, or an absolute path to the script

## Install

```bash
python -m pip install mcp-glp-audit-proxy
```

Restart Cursor after saving `mcp.json`. In the product, Customize, then MCPs, shows the server.

## Minimal config

`.cursor/mcp.json`. The Cursor field table marks `type` as required for a stdio server. The short examples on the same page omit it. This sample includes it.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "type": "stdio",
      "command": "mcp-glp-audit-proxy",
      "args": ["--config", "/srv/glp/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator"
      }
    }
  }
}
```

## Hardened config

Absolute command, `envFile` kept out of git, and a dedicated log. `envFile` is a Cursor stdio field. It is not a proxy flag. Do not commit the file it names.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "type": "stdio",
      "command": "/opt/lab/venv/bin/mcp-glp-audit-proxy",
      "args": ["--config", "/srv/glp/config.json"],
      "envFile": "/srv/glp/operator-1.env",
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator",
        "GLP_AUDIT_PATH": "/srv/glp/operator-1/audit.jsonl"
      }
    }
  }
}
```

`operator-1.env` holds only variables you accept the proxy process seeing. It is not passed to the upstream. Upstream credentials stay in the proxy config's `upstreams[].env`.

Do not add a `url` entry for the lab server. This edition of the proxy is not an HTTP MCP endpoint, and a direct URL would skip the audit log.

The root `mcp.json` sample in the repository is the same `mcpServers` shape, with placeholder paths. Keep using `.cursor/mcp.json` for a real workspace.

## Verification

Restart Cursor, open Customize, MCPs, and confirm `glp-audit` is enabled. Then:

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --print-head
```

The Cursor CLI login command `agent mcp login` is for a remote server that asks you to sign in. This proxy has no such login. Do not point that command at a lab upstream.

## Hello world

Audit two calls and one denied call through this host. Copy `examples/config.json` from a checkout and leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. Part 11 signatures are not part of this hello. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install the package the host will launch.

```bash
python -m pip install mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied config with the absolute path of the checkout. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

`.cursor/mcp.json` (or `~/.cursor/mcp.json` for every project):

```json client
{
  "mcpServers": {
    "glp-audit": {
      "type": "stdio",
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

4. Restart Cursor. Customize, then MCPs, should list `glp-audit`.

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

- A workspace committed `.cursor/mcp.json` shares the command with the team. Keep identity in `env` or `envFile`, not in a shared default role of `admin`.
- Interpolation such as `${env:NAME}` is Cursor's, documented on its MCP page. This proxy does not expand those strings.
- The proxy still has only `--config`. Anything else in `args` is rejected by its parser and the process exits 1.
- The upstream process must be started by the proxy, not by a second `mcpServers` entry.
