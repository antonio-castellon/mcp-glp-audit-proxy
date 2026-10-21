mcp-name: io.github.antonio-castellon/mcp-glp-audit-proxy

# mcp-glp-audit-proxy

Local MCP proxy that sits between an MCP host and your MCP servers and writes a tamper-evident audit trail. Community edition, v0.1.0.

It is designed to support GLP, ALCOA+, 21 CFR Part 11 and EU GMP Annex 11 traceability. Data stays on the customer's infrastructure. This package is the open core. Signed checkpoints, WORM storage, Part 11 electronic signatures, PDF/CSV reports, the IQ/OQ pack and SSO/OAuth are Pro features and are not in this repository.

```
host (Claude, Cursor, Grok, self-hosted LLM)
        |  stdio JSON-RPC
        v
mcp-glp-audit-proxy
  policy (allow / deny, reason, human approval)
  audit  (append-only JSONL, RFC 8785, SHA-256 chain)
        |  stdio or HTTPS (TLS 1.3)
        v
upstream MCP servers (Excel, ELN, LIMS, databases, instruments)
```

## Install

Requires Python 3.11 or newer.

```bash
pip install mcp-glp-audit-proxy
```

From a checkout:

```bash
pip install -e ".[dev]"
```

The `mcp` dependency is pinned to `>=2.2.0,<3`. That floor is outside GHSA-84m7-p3x7-pcfv (affected ranges are `mcp >=1.8.0,<1.30.0` and `>=2.0.0,<2.2.0`). The process refuses to start on an older SDK.

## Run

```bash
export GLP_PRINCIPAL_ID=operator-1
export GLP_PRINCIPAL_NAME="Ada Analyst"
export GLP_PRINCIPAL_ROLE=operator
mcp-glp-audit-proxy --config config.json
```

Stdio identity comes from the environment. There is no HTTP listener in 0.1.0. A Cursor snippet is in `mcp.json`. A full config is in `config.example.json`.

`plugins.storage`, `plugins.signer`, `plugins.reporters` and `plugins.auth` select entry points. The defaults are `jsonl`, `unsigned`, `json` plus `text`, and `env`. `env` returns the principal from `GLP_PRINCIPAL_*` or the config file. It is not an identity provider. An unknown plugin, or a plugin that is not licensed or not installed, refuses to start. The proxy does not fall back to another backend. See `docs/PLUGINS.md`.

Verify a chain and write a searchable JSON export (the export is skipped when the chain does not verify):

```bash
mcp-glp-audit-proxy-verify data/audit.jsonl --json-export exports/audit.json
mcp-glp-audit-proxy-verify data/audit.jsonl --tool excel__write_cell --status ok
mcp-glp-audit-proxy-verify data/audit.jsonl --print-head
```

`--print-head` prints `seq` and `entry_hash`. Copy that line into a ticket, an email or a LIMS record. The sidecar `data/audit.jsonl.head` makes a cut of whole trailing lines fail verification. Someone who can edit both the log and the sidecar can move them together; the external copy is the control. Signed checkpoints and WORM storage are Pro.

## What is recorded

Every mediated call, including denials and failures, is one JSON object on an append-only JSONL file. Each line is RFC 8785 canonical JSON. `entry_hash` is the SHA-256 of that object with `entry_hash` removed. `prev_hash` is the previous entry (64 zero digits for the first). `hash_algo` and `canonicalization` are stored on the entry. The open schema is `schema/audit-record.schema.json`. Cross-language vectors are in `schema/jcs-test-vectors.json`.

Fields include who (`principal` id, name, role), which tool, inputs, outputs, UTC timestamp plus `utc_offset`, protocol version, optional session id, record class (`gxp_data`, `access`, `technical`, `config`), reason for writes, and the previous hash.

The GxP trail is that file. The Python `logging` logger `mcp_glp_audit_proxy.technical` writes method, status and record class to stderr. It is not the record. Arguments are not written there.

## Policy

- Allow list and deny list use shell-style globs on the exposed tool name (`excel__write_cell`). Deny wins. An empty allow list denies every upstream tool.
- Roles are `operator`, `approver`, `qa` and `admin`. Only `operator` may call upstream tools. `qa` is read-only on the trail (`glp_verify_chain`, `glp_search_audit`, `glp_export_audit`). `approver` may record an approval and read the trail. `admin` may change policy and read the trail, and cannot call upstream tools.
- Auditing cannot be switched off. `glp_update_policy` with `audit_enabled: false` is denied and logged.
- Write tools (names matching `write_tools`) require a reason by default. The reason is `_meta["io.github.antonio-castellon/reason"]` or the argument `_glp_reason` (stripped before the upstream call).
- Optional human approval holds the write until a different person in the `approver` role records meaning `approved`. `reviewed` is stored with status `reviewed` and does not authorise the write. A log written before schema 1.1.0 may show that decision as status `approved` with meaning `reviewed`; those lines still verify and still do not authorise the write. `rejected` rejects it. An approval is single-use, bound to the SHA-256 of the canonical `{tool, arguments}`, and expires (default 3600 seconds). A successful write that presents a matching approval records it as consumed even if `require_approval_for_writes` was turned off before that call. A failed upstream call does not consume it. The record label is `approval`. It is not an electronic signature.
- Fail closed is the default. The store is checked before a call is forwarded. If the append after a successful upstream call fails, the upstream payload is not returned to the host. Denied and failed calls are still logged. If the upstream may already have applied a write, follow `docs/RECONCILIATION_SOP.md`.

## Protocol

The proxy speaks both handshake-era MCP revisions (`2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, with `initialize`) and spec `2026-07-28` (`server/discover`, no initialize, no session). A session id is recorded only when that revision has one. Upstream protocol `auto` tries `server/discover` and falls back to `initialize` at `2025-11-25`.

Exposed tool names are `server__tool`. Resource URIs are prefixed `server:`. Credential-bearing `_meta` keys are stripped, their names are logged, and their values are neither stored nor forwarded. Upstream stdio receives a safe environment allow-list from the MCP SDK, plus the env block in the config.

## Regulatory coverage

mcp-glp-audit-proxy is designed to support the audit-trail requirements below. Meeting them still depends on your validated use, SOPs and reviews. The clause-by-clause matrix is `docs/COVERAGE.md`. The norms and the verification log are `docs/STANDARDS.md`.

| Framework | What the proxy helps with | Edition |
|---|---|---|
| OECD GLP No. 17 (3.4) / Swiss GLPV Annex 2 | Always-on, append-only audit trail; who/what/when/why; admin-only settings; QA read-only role; 10-year Swiss retention profile | Community core; WORM retention and PDF reports in Pro |
| FDA 21 CFR Part 11 | Computer-generated, time-stamped, hash-chained audit trail (11.10(e)); tamper detection; complete copies; authority checks. Part 11 approval e-signatures (11.50, 11.70, 11.200) are Pro only: the Community `approval` is not an electronic signature | Community core; e-signatures (Pro only), reports, signing, SSO in Pro |
| EU GMP Annex 11 (2011; 2025 draft) | Audit trail of changes with reason; role, time zone; locked audit trail; searchable complete export; access log | Community core; review tooling and inactivity logout in Pro |
| MHRA / PIC/S PI 041-1 / WHO TRS 1033 | ALCOA+ data integrity, segregation of duties, metadata with each record, true-copy exports | Community core; signed manifests and validation pack in Pro |
| ISPE GAMP 5 / FDA CSA | Supplier documentation, proposed Cat. 4 configured components, machine-readable test evidence | Pro (validation pack) |
| EU AI Act Art. 12, 19, 26(6) | Automatic event logging, minimum 6-month retention | Community |
| Crypto and time (RFC 8785, SHA-256, Ed25519/ECDSA, RFC 3161, eIDAS/ZertES, TLS 1.3) | Canonical hashing and encrypted transport | Hash chain and TLS in Community; signing and timestamps in Pro |
| MCP authorization, OWASP LLM/Agentic | No token passthrough, tool allowlist/denylist, approval before write tools, OAuth 2.1 | Allowlist and no-passthrough in Community; OAuth/SSO in Pro |
| ISO/IEC 42001, NIST AI RMF | Event-log evidence for AI governance and monitoring | Community (supporting evidence only) |

Default retention is the Swiss GLP profile: 10 years after study completion, with a floor of 6 months. The `minimum` profile may use a shorter year count but cannot go under 6 months. A legal-hold flag refuses disposal. The JSONL backend has no delete. Retention-period WORM enforcement is a Pro backend.

## Community and Pro

This repository is the Community edition. Pro is available as a licensed / paid service - contact [antonio@castellon.ch](mailto:antonio@castellon.ch).

Pro adds SQL and S3 WORM backends, Ed25519 and ECDSA signing, RFC 3161 timestamps, Part 11 e-signatures, PDF and CSV auditor reports, an IQ/OQ validation pack, and SSO. It also includes the GLP Lab Data Pack for [mcp-advanced-excel](https://github.com/antonio-castellon/mcp-advanced-excel), unlocked by the same offline licence key. The free mcp-advanced-excel server reads and writes lab spreadsheets. The Data Pack adds what a GLP lab needs on top: provenance hashes that tie every result back to its source file, instrument templates for common lab exports, advanced LOD/LOQ calculations and molar unit conversions, batch processing of many files in one run, and Ed25519 signed output.

| Capability | Community (this repo) | Pro (licensed service) |
|---|---|---|
| Proxy core, both protocol eras | yes | plugs in, does not fork |
| Append-only JSONL hash chain | yes | |
| PostgreSQL / MSSQL append-only | | yes |
| S3 Object Lock | | yes |
| Verify CLI and searchable JSON export | yes | |
| Plain-text verify listing | yes | |
| PDF / CSV auditor reports | | yes |
| Audit-trail review tooling (flags, reviewer sign-off) | search, filter, export | yes |
| DE / FR / EN report templates | | later |
| Old/new value capture for write tools | planned | change highlighting in reports |
| Tool allowlist / denylist | yes | |
| Local roles (operator, approver, qa, admin) | yes | |
| Human approval before writes | yes (label: approval) | |
| Part 11 electronic signatures | | yes |
| Ed25519 / ECDSA signed checkpoints | unsigned checkpoints only | yes |
| RFC 3161 timestamps | | yes |
| IQ/OQ validation pack | | yes |
| SSO / OAuth | | yes |
| Syslog (RFC 5424) / SIEM export | | yes |
| Key management (KMS/HSM), field-level encryption and redaction | | yes |
| FIPS 140-3 mode | | on request |
| Merkle log with inclusion / consistency proofs | | later |
| OpenTelemetry spans (technical telemetry, not the audit record) | planned | |
| GLP Lab Data Pack for mcp-advanced-excel (provenance hashes, instrument templates, advanced LOD/LOQ and molar units, batch processing, Ed25519 signed output) | | yes |
| TLS 1.3 to remote upstreams, no token passthrough | yes | |
| Offline licence file, no phone-home | yes | reads the same file |

Plugin entry points, the `AuditStore` / `Signer` / `Reporter` contracts, and the licence file are described in `docs/PLUGINS.md`.

## Local tools

| Tool | Who | What |
|---|---|---|
| `glp_verify_chain` | qa, approver, admin | Check chain integrity. Still returns the report if the chain is broken. |
| `glp_search_audit` | qa, approver, admin | Filter entries. The audit of the search stores the filter and the count, not a second copy of every row. |
| `glp_export_audit` | qa, approver, admin | JSON electronic export with a hash manifest. A filtered export is marked `complete: false`. A broken chain is not exported. |
| `glp_approve` | approver | Record meaning `approved`, `reviewed` or `rejected`. |
| `glp_update_policy` | admin | Append a config event. Policy is replayed from the log. |

## Manuals

Host setup for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Cline, Continue, a generic stdio client, the MCP Python SDK, LangChain, the OpenAI Agents SDK, Docker, a lab PC, a shared workstation, and an offline install is in [`docs/manual-guides/`](docs/manual-guides/README.md). The upstream MCP server must be reachable only through this proxy. The same pages cover anchoring, approval, plugin selection, and the fail-closed latch.

## Safety

Read `SAFETY.md`. Short version: fail closed, no token passthrough, secrets are stripped from `_meta`, stdio children do not inherit the parent environment, an approval is not an electronic signature, and the JSONL file is tamper-evident, not a WORM store.

## Development

```bash
pip install -e ".[dev]"
python -m pytest -q
```

The OQ-style report runner needs a source checkout (`tests/` and `docs/verification/rtm.yaml`). A PyPI install does not include that tree. Two command names call the same runner. Neither is deprecated: `mcp-glp-audit-proxy-oq` is the installed console script, and `mcp-glp-audit-proxy oq-report` is the module subcommand. From a clone:

```bash
mcp-glp-audit-proxy-oq --repo-root .
mcp-glp-audit-proxy oq-report --repo-root .
```

If the checkout is missing, the command exits 2 and does not start pytest.

CI runs the same suite on Python 3.11, 3.12 and 3.13 (`.github/workflows/ci.yml`).

## MCP registry

`server.json` names this server `io.github.antonio-castellon/mcp-glp-audit-proxy` for the official MCP Registry. The marker on the first line of this file is the registry check.

## Licence

MIT. Copyright (c) 2026 Antonio Castellon / Castellon.CH. See `LICENSE`.
