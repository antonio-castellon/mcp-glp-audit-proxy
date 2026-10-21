# Claude Desktop

Claude Desktop starts each MCP server as a local process. Point it at the proxy. Do not also add the upstream server. The upstream belongs in the proxy's `upstreams` list. The proxy file itself is the minimal or hardened file in [generic-stdio.md](generic-stdio.md).

## Prerequisites

- Claude Desktop from the publisher
- Python 3.11 or newer on the PATH Claude Desktop will use
- `mcp-glp-audit-proxy` installed for that same user
- A proxy `config.json` whose stdio `command` exists on this machine

The published MCP quickstart names these config files:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

That quickstart does not name a Linux path. On Linux, use Settings, Developer, Edit Config, and edit the file that action opens. If Edit Config on Windows opens a different path than `%APPDATA%\Claude`, edit that file. A February 2026 packaging bug briefly split the Windows path; the publisher marked it fixed. Trust the file the app opens.

## Install

```bash
python -m pip install mcp-glp-audit-proxy
mcp-glp-audit-proxy --help
```

On Windows, if `python` is the launcher stub:

```bash
py -3.12 -m pip install mcp-glp-audit-proxy
py -3.12 -m mcp_glp_audit_proxy --help
```

`--help` shows `--config` only.

## Minimal config

macOS or Linux JSON. The `env` block is required. A desktop app does not load your shell profile, and the child would not see `GLP_PRINCIPAL_*` from the profile anyway unless this block sets them.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "mcp-glp-audit-proxy",
      "args": ["--config", "/Users/ada/glp/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator"
      }
    }
  }
}
```

Windows uses the module and escaped backslashes:

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "py",
      "args": ["-3.12", "-m", "mcp_glp_audit_proxy", "--config", "C:\\Lab\\glp\\config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator"
      }
    }
  }
}
```

The proxy file at that `--config` path is a [generic-stdio.md](generic-stdio.md) config. Its `upstreams` command is the lab server. Claude's config does not list that server.

## Hardened config

Absolute paths, one person per `env` block, and the hardened proxy file (approval required, narrow allow list).

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "/Users/ada/glp/venv/bin/mcp-glp-audit-proxy",
      "args": ["--config", "/Users/ada/glp/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator",
        "GLP_AUDIT_PATH": "/Users/ada/glp/data/audit.jsonl"
      }
    }
  }
}
```

Do not add a second key such as `excel` or `lims` under `mcpServers`. That would call the upstream with no audit trail.

## Verification

Quit Claude Desktop completely and start it again. Developer settings should show `glp-audit` running. Then, outside the app, with the same config path:

```bash
mcp-glp-audit-proxy-verify /Users/ada/glp/data/audit.jsonl --print-head
```

A startup record in that file means this process wrote the log. If the server is missing from the app, the usual cause is a bad JSON file or a command that is not on the app's PATH. Run the same command in a terminal. Startup errors are printed to stderr and the process exits 1.

## Hello world

Audit two calls and one denied call through this host. Copy `examples/config.json` from a checkout and leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. Part 11 signatures are not part of this hello. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install the package the host will launch.

```bash
python -m pip install mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied config with the absolute path of the checkout. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

macOS or Linux, `claude_desktop_config.json` (on Linux, the file Settings, Developer, Edit Config opens):

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

Windows. Forward slashes work in this JSON. Quit the app completely after saving.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "command": "py",
      "args": ["-3.12", "-m", "mcp_glp_audit_proxy", "--config", "C:/Lab/glp/config.json"],
      "env": {
        "GLP_PRINCIPAL_ID": "operator-1",
        "GLP_PRINCIPAL_NAME": "Ada Analyst",
        "GLP_PRINCIPAL_ROLE": "operator"
      }
    }
  }
}
```

4. Quit Claude Desktop completely, then start it again. Closing the window is not enough.

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

- Editing the config does nothing until the app is fully quit, not only the window closed.
- `command` must be an executable, not a shell line. `args` is the argument list. There is no `shell` key in this product.
- Claude Desktop has no flag that talks to this proxy except the args you put in `args`. The only proxy flag is `--config`.
- The upstream must not be reachable as its own MCP server from this app.
