# Claude Code

Claude Code starts a stdio MCP server from `.mcp.json` (project scope, shared) or from `claude mcp add` (local or user scope). Register the proxy. Do not register the upstream. The upstream is only in the proxy config's `upstreams`.

Official scopes, from the Claude Code MCP docs:

| Scope | File | Who sees it |
|---|---|---|
| local (default) | `~/.claude.json`, under this project | Only you, this project |
| project | `.mcp.json` in the project root | Anyone who clones the project, after they approve it |
| user | `~/.claude.json`, top-level `mcpServers` | Only you, all projects |

On Windows, `~/.claude.json` is `%USERPROFILE%\.claude.json`. `CLAUDE_CONFIG_DIR`, when set, replaces the directory that holds `.claude.json`.

## Prerequisites

- Claude Code installed and `claude` on PATH
- Python 3.11 or newer
- A proxy `config.json` as in [generic-stdio.md](generic-stdio.md)

## Install

```bash
python -m pip install mcp-glp-audit-proxy
```

Add the server. Everything after `--` is the proxy command, not a Claude Code flag. `--config` is the proxy's flag.

```bash
claude mcp add --transport stdio --scope project glp-audit -- mcp-glp-audit-proxy --config /srv/glp/config.json
```

Identity has to be in the server environment. Put at least one other option between `--env` and the server name, as the Claude Code docs require, or the name is parsed as another `KEY=value` pair.

```bash
claude mcp add --env GLP_PRINCIPAL_ID=operator-1 --env GLP_PRINCIPAL_NAME="Ada Analyst" --env GLP_PRINCIPAL_ROLE=operator --transport stdio --scope user glp-audit -- mcp-glp-audit-proxy --config /srv/glp/config.json
```

Check the saved entry:

```bash
claude mcp list
```

## Minimal config

Project file `.mcp.json`. `type` `stdio` matches the local-server form in the Claude Code docs.

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

Absolute command, a per-person log, and no extra servers. Commit `.mcp.json` only if the paths work for every clone. Prefer user scope when the path is personal.

```json client
{
  "mcpServers": {
    "glp-audit": {
      "type": "stdio",
      "command": "/opt/lab/venv/bin/mcp-glp-audit-proxy",
      "args": ["--config", "/srv/glp/config.json"],
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

The hardened proxy file (approval on, narrow allow list) is in [generic-stdio.md](generic-stdio.md). Do not add the LIMS or Excel server to this file.

Claude Code sets `CLAUDE_PROJECT_DIR` on the spawned server. This proxy does not read that variable. Paths in `--config` and in `config.json` should be absolute so they do not depend on the working directory.

## Verification

```bash
claude mcp list
```

A connected `glp-audit` entry means the process started. Then:

```bash
mcp-glp-audit-proxy-verify /srv/glp/operator-1/audit.jsonl --print-head
```

Inside a session, `/mcp` manages servers that are already added. That slash command is Claude Code's, not a proxy flag.

## Hello world

Audit two calls and one denied call through this host. Copy `examples/config.json` from a checkout and leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. Part 11 signatures are not part of this hello. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install the package the host will launch.

```bash
python -m pip install mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied config with the absolute path of the checkout. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

Project `.mcp.json`:

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

4. Start a new Claude Code session so it reloads `.mcp.json`.

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

- Flags before `--` belong to `claude mcp add` (`--env`, `--transport`, `--scope`). Flags after `--` belong to the proxy, and the only one is `--config`.
- A project `.mcp.json` is shared. Do not put a personal access token in it. Upstream credentials belong in the proxy's `upstreams[].env` or `headers`, outside git.
- Approving a project MCP server still must not approve a direct path to the upstream.
- `claude mcp list` showing a failure is usually a missing command or a config the proxy rejected on stderr.
