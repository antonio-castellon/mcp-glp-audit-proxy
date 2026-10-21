# Windows lab PC

Community 0.1.0 reads stdin and writes stdout. It does not open a socket. A Windows service is the wrong process model: a service has no MCP client attached to its stdin, so the process exits at end of file, and there is no port for the host to connect to. Do not register one with `sc.exe` or a third-party service wrapper.

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

## Pitfalls

- `sc create` does not give you an MCP server. There is no port, and stdin EOF ends the process.
- `require_ntp` true cannot succeed on Windows with this probe. It looks for `timedatectl`.
- The Microsoft Store Python alias sometimes points `python` at a stub that does not run pip. `py -3.12` avoids that stub.
- A config path in JSON must escape backslashes (`C:\\Lab\\...`) or use forward slashes.
- The upstream must not be a second entry in `claude_desktop_config.json`.
