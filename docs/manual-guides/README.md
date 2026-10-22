# Manual guides

Usage and configuration for the Community edition of mcp-glp-audit-proxy (v0.3.2). The package is designed to support GLP / 21 CFR Part 11 / EU GMP Annex 11 workflows. Your own SOPs, reviews, and the systems around the proxy still decide whether a deployment meets those rules.

Every sample below was taken from the command line and the config loader in this repository. The proxy accepts no flags that are not listed here.

## The upstream is reached only through the proxy

The host must start `mcp-glp-audit-proxy` and must not also register the upstream MCP server. Excel, an ELN, a LIMS, a database, or an instrument server is named only in the proxy's `upstreams` list. The proxy is the process that spawns that command or dials that URL.

If the host can call the upstream directly, calls never reach the audit log. Do not publish the upstream on a port the host can open. Do not add it as a second MCP server next to the proxy.

```
host (editor, desktop app, or Python agent)
        |  stdio JSON-RPC only
        v
mcp-glp-audit-proxy          <-- the only MCP server the host configures
        |  stdio child, or HTTPS (TLS 1.3)
        v
upstream MCP server          <-- not configured in the host
```

There is no HTTP listener in this edition. The proxy reads newline-delimited JSON-RPC on stdin and writes it on stdout. Logs from the process go to stderr.

## What the process accepts

Console script and module, same server:

```bash
mcp-glp-audit-proxy --config /absolute/path/config.json
python -m mcp_glp_audit_proxy --config /absolute/path/config.json
```

The server parser has one option, `--config`. The default is the `GLP_CONFIG` environment variable, then `config.json` in the working directory. `mcp-glp-audit-proxy oq-report` is not a server flag. It is the OQ runner, and it is documented with `mcp-glp-audit-proxy-oq` in the repository README. These guides do not use it to audit a lab session.

Environment variables the loader reads:

| Variable | Effect |
|---|---|
| `GLP_CONFIG` | Config path when `--config` is omitted |
| `GLP_PRINCIPAL_ID` | Replaces `principal.id` when the variable is non-empty |
| `GLP_PRINCIPAL_NAME` | Replaces `principal.name` when non-empty |
| `GLP_PRINCIPAL_ROLE` | Replaces `principal.role` when non-empty. One of `operator`, `approver`, `qa`, `admin` |
| `GLP_AUDIT_PATH` | Replaces `audit.path` when non-empty |
| `GLP_FAIL_CLOSED` | Replaces `audit.fail_closed`. True: `1`, `true`, `yes`, `on`. False: `0`, `false`, `no`, `off` |
| `GLP_LICENCE_PATH` | Replaces `licence_path` when non-empty |
| `GLP_REQUIRE_NTP` | Replaces `require_ntp`, same true and false words as `GLP_FAIL_CLOSED` |

An empty variable is ignored. A GUI host often does not see your shell profile. Set `GLP_PRINCIPAL_*` in the host's `env` block for that server. The MCP Python SDK does not copy arbitrary parent variables into a stdio child. It passes a small allow-list (`HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM`, `USER` on POSIX; a Windows set that includes `PATH` and `USERPROFILE`) plus the `env` object you supply. Identity has to be in that object.

Roles, from `policy.py`: only `operator` may call an upstream tool. `qa` may call `glp_verify_chain`, `glp_search_audit`, and `glp_export_audit`. `approver` may do that and call `glp_approve`. `admin` may do the QA calls and call `glp_update_policy`. `admin` cannot call upstream tools.

## config.json

A JSON object. Unknown `policy` keys and unknown `plugins` keys refuse startup. The fields the loader reads:

| Field | Notes |
|---|---|
| `principal.id`, `principal.name`, `principal.role` | Required after environment overrides. Role is one of the four names above |
| `retention.profile` | `swiss_glp` (default) or `minimum` |
| `retention.min_months` | Default 6. Values under 6 are refused |
| `retention.years_after_study` | Default 10. The `swiss_glp` profile refuses a value under 10 |
| `retention.legal_hold` | Boolean, default false. The JSONL store still has no delete |
| `retention.study_completion` | String or null |
| `policy.allow` | List of globs on the exposed name `server__tool`. Empty denies every upstream tool. Deny wins |
| `policy.deny` | List of globs |
| `policy.write_tools` | Globs that count as writes |
| `policy.require_approval_for_writes` | Default false |
| `policy.require_reason_for_writes` | Default true |
| `audit.path` | Default `./data/audit.jsonl`, relative to the config file. Overridden by `GLP_AUDIT_PATH` |
| `audit.fail_closed` | Default true |
| `audit.checkpoint_every` | Default 100. A missing or zero value is stored as 100, because the loader treats 0 as unset |
| `approval_ttl_seconds` | Default 3600. A missing or zero value is stored as 3600 |
| `require_ntp` | Default false. When true, startup refuses unless `timedatectl` reports `NTPSynchronized=yes` |
| `export_dir` | Default `<audit directory>/exports`. `glp_export_audit` cannot write outside it |
| `client_id` | Printable token, or null. Required when a licence is signed. It is part of the licence fingerprint. It is not a machine id |
| `licence_path` | Local licence file, or null. LM1 text (RSA-2048 PSS) or LM2 text (Ed25519). Overridden by `GLP_LICENCE_PATH` |
| `plugins.storage` | Default `jsonl`. A name, or `{"name", "options"}`. `options` is passed to the factory and is not written to the audit log |
| `plugins.signer` | Default `unsigned`. Same shape as `plugins.storage` |
| `plugins.reporters` | Default `["json", "text"]`. A non-empty list, or `{"names", "options"}`. `options` maps each reporter name to an object. No duplicates |
| `plugins.auth` | Default `env`. Same shape as `plugins.storage` |
| `upstreams` | List. See below |

Plugin names match `^[a-z][a-z0-9_]{0,40}$`. Selecting a name that is unknown or not licensed refuses startup. There is no fallback. See [plugins.md](plugins.md).

Each upstream object:

| Field | Notes |
|---|---|
| `name` | Short token, no `__`. The exposed tool is `name__tool` |
| `transport` | `stdio` (default) or `https` |
| `protocol` | `auto` (default), `legacy`, or `modern` |
| `command`, `args`, `env`, `cwd` | stdio. `command` is required for stdio. `env` is merged onto the SDK allow-list. It is the only place for that upstream's own credentials |
| `url`, `headers` | https. `url` must be `https://`. TLS 1.3 only. `headers` are that backend's own credentials. The host's token is never copied here |
| `timeout` | Positive number. Applied to stdio. Omitted stdio uses 60 seconds. Community 0.3.2 does not pass this field into the HTTPS client, which uses 30 seconds |

`protocol` `auto` tries `server/discover` and falls back to `initialize` at protocol `2025-11-25`. `legacy` skips discovery. `modern` requires discovery.

The log file and the sidecar `<log>.head` are set to mode `0600` on open. A change to an existing file is logged as a warning. A log directory created by the store is mode `0700`. `init` writes the config as mode `0600`.

## Verify CLI

`mcp-glp-audit-proxy-verify` and `python -m mcp_glp_audit_proxy verify` call the same checker. Neither name loads `config.json`. Exit 0 means the chain verified. Exit 1 means it did not, and `--json-export` is skipped. Without `--pubkey` the command does not load plugins. With `--pubkey`, pass `--licence` and `--client-id`, or set `GLP_LICENCE_PATH` and `GLP_CLIENT_ID`.

```bash
mcp-glp-audit-proxy-verify data/audit.jsonl --print-head
mcp-glp-audit-proxy-verify data/audit.jsonl --json-export data/exports/audit.json
mcp-glp-audit-proxy-verify data/audit.jsonl --tool excel__write_cell --status ok
```

Flags: `--json-export`, `--record-class`, `--tool`, `--status`, `--principal`, `--method`, `--server`, `--since`, `--until`, `--print-head`, `--expect-head`, `--expect-head-file`, `--pubkey`, `--licence`, `--client-id`. Filters change what is printed. They do not change the integrity check. `--print-head` prints `seq=<n> entry_hash=<64 hex>` on stdout. Copy that line off the machine. `--expect-head <seq>:<entry_hash>` and `--expect-head-file` fail when the chain tip differs. `--pubkey` passes the file bytes to the licensed signer plugin. Unsigned checkpoints do not satisfy that check. See [anchoring-and-verification.md](anchoring-and-verification.md).

## Local tools

| Tool | Arguments |
|---|---|
| `glp_verify_chain` | none |
| `glp_search_audit` | `record_class`, `tool`, `principal_id`, `status`, `method`, `server`, `since`, `until` |
| `glp_export_audit` | those filters, plus `path` and `format` (`json` or `text` in Community) |
| `glp_approve` | `approval_id`, `meaning` (`approved`, `reviewed`, or `rejected`) |
| `glp_update_policy` | `reason` required, plus any of `allow`, `deny`, `write_tools`, `require_approval_for_writes`, `require_reason_for_writes`, `audit_enabled` |

`audit_enabled: false` is denied. A write reason is `_meta["io.github.antonio-castellon/reason"]` or the argument `_glp_reason` (removed before the upstream call and before the approval hash). The approval id on a later write is `_meta["io.github.antonio-castellon/approvalId"]`.

A message larger than 1048576 bytes (1 MiB) with no newline ends the session. The bytes are not forwarded.

## Guides

| Guide | Use it for |
|---|---|
| [QUICKSTART.md](QUICKSTART.md) | Five-minute terminal audit: hello, the log, verify, a tamper, a denied call |
| [claude-desktop.md](claude-desktop.md) | Claude Desktop on macOS, Windows, and Linux |
| [claude-code.md](claude-code.md) | Claude Code, including `.mcp.json` |
| [cursor.md](cursor.md) | Cursor editor and Cursor CLI |
| [vscode-copilot.md](vscode-copilot.md) | VS Code and GitHub Copilot agent mode |
| [windsurf-cline-continue.md](windsurf-cline-continue.md) | Windsurf, Cline, and Continue |
| [generic-stdio.md](generic-stdio.md) | Any stdio MCP host, plus the proxy file itself |
| [python-sdk.md](python-sdk.md) | Official MCP Python SDK |
| [langchain-langgraph.md](langchain-langgraph.md) | LangChain `MCPAdapter` and LangGraph tools |
| [openai-agents.md](openai-agents.md) | OpenAI Agents SDK `MCPServerStdio` |
| [docker.md](docker.md) | Container image, including a Glama-style stdio build |
| [windows-lab-pc.md](windows-lab-pc.md) | A Windows lab PC, and why a Windows service is the wrong shape |
| [multi-user.md](multi-user.md) | Shared workstation, one identity and one log per process |
| [air-gapped.md](air-gapped.md) | Wheel install with no network on the lab machine |
| [anchoring-and-verification.md](anchoring-and-verification.md) | `--print-head`, the sidecar, off-host copy, reconciliation |
| [approval-workflow.md](approval-workflow.md) | `glp_approve`, roles, separation of duties |
| [plugins.md](plugins.md) | Storage, signer, reporter, auth, and the licence file |
| [troubleshooting.md](troubleshooting.md) | Fail-closed latch, the 1 MiB cap, denied calls |
| [hello_world/README.md](hello_world/README.md) | Which hello-world page covers each transport |
| [hello_world/stdio-to-proxy-to-stdio.md](hello_world/stdio-to-proxy-to-stdio.md) | PyPI install, init, one allowed call, one blocked call, a stdio target |
| [hello_world/stdio-to-proxy-to-https.md](hello_world/stdio-to-proxy-to-https.md) | The same walkthrough with an HTTPS (TLS 1.3) target |

[QUICKSTART.md](QUICKSTART.md) is the terminal audit from a checkout. [hello_world/README.md](hello_world/README.md) is the coverage matrix for a PyPI install. Each walkthrough, and each other guide except QUICKSTART.md and that matrix, has prerequisites, install, a minimal config, a hardened config, a verification step, and pitfalls. The host guides also have a hello world that uses `examples/config.json` with the approval gate off.
