# Windows lab PC

Community 0.3.2 reads stdin and writes stdout. It does not open a socket. A Windows service is the wrong process model: a service has no MCP client attached to its stdin, so the process exits at end of file, and there is no port for the host to connect to. Do not register one with `sc.exe` or a third-party service wrapper.

The lab PC should install Python and the package for the person who sits at the machine. The MCP host (Claude Desktop, Cursor, VS Code) starts the proxy when a session needs it. That is the supported shape.

## Prerequisites

- Windows 10 or 11 on the lab PC
- Python 3.11, 3.12, or 3.13, installed for the lab user (the `py` launcher is the usual selector)
- An MCP host that can start a stdio process
- The upstream installed on this same PC, or an `https://` URL the PC can reach, named only in the proxy config

## Install

In a command prompt for the lab user:

```bash
py -3.12 -m pip install mcp-glp-audit-proxy
py -3.12 -m mcp_glp_audit_proxy --help
```

`--help` prints `--config` and nothing else. Create `C:\Lab\glp\` and put `config.json` there. The log directory can be `C:\Lab\glp\data`. The store creates the log with mode `0600` on platforms that honour that mode. On Windows, restrict the directory ACL to the lab user and to the QA account that must read the file. Do not grant Modify to Everyone.

## Minimal config

Proxy file `C:\Lab\glp\config.json`. Paths in JSON use escaped backslashes. This sample uses forward slashes, which Python accepts on Windows.

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
    "path": "C:/Lab/glp/data/audit.jsonl",
    "fail_closed": true,
    "checkpoint_every": 100
  },
  "export_dir": "C:/Lab/glp/data/exports",
  "upstreams": [
    {
      "name": "excel",
      "transport": "stdio",
      "protocol": "auto",
      "command": "py",
      "args": ["-3.12", "-m", "your_excel_mcp_server"],
      "env": {}
    }
  ]
}
```

Claude Desktop entry (`%APPDATA%\Claude\claude_desktop_config.json`, or the file Edit Config opens):

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

## Hardened config

Approval required, absolute upstream command, no extra MCP servers. Turn on `GLP_REQUIRE_NTP` only when Windows time service is actually synced. This edition's NTP probe runs `timedatectl`, which is not a Windows command. On Windows the probe records `ntp_synchronized` as null and `require_ntp` true refuses startup. Leave `require_ntp` false on a Windows lab PC and sync the clock with the site's time service. Record that in your SOP. The probe does not invent a sync.

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
    "legal_hold": false,
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
    "path": "C:/Lab/glp/data/audit.jsonl",
    "fail_closed": true,
    "checkpoint_every": 50
  },
  "approval_ttl_seconds": 900,
  "require_ntp": false,
  "export_dir": "C:/Lab/glp/data/exports",
  "licence_path": null,
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
      "command": "C:/Lab/venv/Scripts/python.exe",
      "args": ["-m", "your_excel_mcp_server"],
      "cwd": "C:/Lab",
      "timeout": 30,
      "env": {
        "EXCEL_WORKBOOK_DIR": "C:/Lab/workbooks"
      }
    }
  ]
}
```

If the PC must start the MCP host at logon, use Task Scheduler to start that host for the lab user. Do not schedule `mcp-glp-audit-proxy` by itself. With no client on stdin it exits.

## Verification

The verify tool is the console script `mcp-glp-audit-proxy-verify`. It is not a `python -m` module. The server module is `mcp_glp_audit_proxy`. The Scripts directory (`%LocalAppData%\Programs\Python\Python312\Scripts`, or the venv `Scripts` folder) must be on PATH.

```bash
mcp-glp-audit-proxy-verify C:\Lab\glp\data\audit.jsonl --print-head
```

Exit 0 and stderr `chain ok` means the file verified.

## Hello world

Audit two calls and one denied call through this host. Copy `examples/config.json` from a checkout and leave `require_approval_for_writes` false. The exposed tools are `lab__hello` and `lab__save_note`. Part 11 signatures are not part of this hello. The five-minute terminal run is [QUICKSTART.md](QUICKSTART.md).

1. Install the package the host will launch.

```bash
python -m pip install mcp-glp-audit-proxy
```

2. Replace every `REPLACE_WITH_ABSOLUTE_PATH` in the copied config with the absolute path of the checkout. `audit.path` stays `./data/audit.jsonl`.

3. Point the host at that file.

Use the py launcher. Forward slashes are accepted in this JSON.

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

Copy `examples/config.json` to `C:/Lab/glp/config.json` and replace the placeholder with the Windows path of the checkout, using forward slashes. Do not register a Windows service.

4. Quit the desktop app completely, then start it again.

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

- `sc create` does not give you an MCP server. There is no port, and stdin EOF ends the process.
- `require_ntp` true cannot succeed on Windows with this probe. It looks for `timedatectl`.
- The Microsoft Store Python alias sometimes points `python` at a stub that does not run pip. `py -3.12` avoids that stub.
- A config path in JSON must escape backslashes (`C:\\Lab\\...`) or use forward slashes.
- The upstream must not be a second entry in `claude_desktop_config.json`.
