mcp-name: io.github.antonio-castellon/mcp-glp-audit-proxy

<p>
  <a href="https://github.com/antonio-castellon/mcp-glp-audit-proxy/releases/latest"><img src="https://img.shields.io/github/v/release/antonio-castellon/mcp-glp-audit-proxy?label=version" alt="latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB" alt="Python 3.11, 3.12, and 3.13">
  <img src="https://img.shields.io/badge/MCP-proxy-1e4652" alt="MCP proxy">
</p>

<picture>
  <source srcset="https://raw.githubusercontent.com/antonio-castellon/mcp-glp-audit-proxy/main/docs/images/banner.svg" type="image/svg+xml">
  <img src="https://raw.githubusercontent.com/antonio-castellon/mcp-glp-audit-proxy/main/docs/images/banner.png" width="1280" height="320" alt="mcp-glp-audit-proxy. Tamper-evident audit trail for MCP tool calls - Community edition.">
</picture>

# mcp-glp-audit-proxy

GxP Gateway Audit (package mcp-glp-audit-proxy) audits MCP and HTTP(S) APIs, gateways, and LLM endpoints. Community edition, v0.4.0. The package name, the command names, and the MCP Registry id stay `mcp-glp-audit-proxy`. Changes since 0.2.0 are in `CHANGELOG.md`.

The listener and every remote URL are HTTPS with TLS 1.3. Plain HTTP is refused. With no `listen` object the process is still the stdio MCP proxy between a host and its MCP servers.

It is designed to support GLP / 21 CFR Part 11 / EU GMP Annex 11 workflows. Data stays on the customer's infrastructure. This package is the open core. Signed checkpoints, WORM storage, PDF/CSV reports, the IQ/OQ pack and SSO/OAuth are Pro features and are not in this repository. Personal Part 11 e-signatures are out of scope. Community is tamper-evident via the hash chain. It is not signed. Signing is Pro.

<picture>
  <source srcset="https://raw.githubusercontent.com/antonio-castellon/mcp-glp-audit-proxy/main/docs/images/flow.svg" type="image/svg+xml">
  <img src="https://raw.githubusercontent.com/antonio-castellon/mcp-glp-audit-proxy/main/docs/images/flow.png" width="1280" height="576" alt="Flow from the client / agent, host (Claude, Cursor, Grok, self-hosted LLM), over stdio JSON-RPC into mcp-glp-audit-proxy. Inside the proxy: policy (allow / deny, reason, human approval), approval, and the audit writer, audit (append-only JSONL, RFC 8785, SHA-256 chain). The proxy then reaches upstream MCP servers (Excel, ELN, LIMS, databases, instruments) over stdio or HTTPS (TLS 1.3). The audit writer records the JSONL log and the .head sidecar. The off-host anchor keeps the external copy (ticket, email, or LIMS record).">
</picture>

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

Stdio identity comes from the environment (`GLP_PRINCIPAL_ID`, `GLP_PRINCIPAL_NAME`, `GLP_PRINCIPAL_ROLE`). When the config has no `listen` object, the process reads newline-delimited JSON-RPC on stdin and writes it on stdout, and it does not open a socket. When `listen` is set, the same command serves HTTPS and does not read stdio. A Cursor snippet is in `mcp.json`. A full config is in `config.example.json`. The config reference is [`docs/manual-guides/README.md`](docs/manual-guides/README.md).

`plugins.storage`, `plugins.signer`, `plugins.reporters` and `plugins.auth` select entry points. The defaults are `jsonl`, `unsigned`, `json` plus `text`, and `env`. `env` returns the principal from `GLP_PRINCIPAL_*` or the config file. It is not an identity provider. An unknown plugin, or a plugin whose declared licence feature is not enabled, refuses to start. The factory is not called. The proxy does not fall back to another backend. See `docs/PLUGINS.md`.

Verify a chain and write a searchable JSON export (the export is skipped when the chain does not verify):

```bash
mcp-glp-audit-proxy-verify data/audit.jsonl --json-export exports/audit.json
mcp-glp-audit-proxy-verify data/audit.jsonl --tool excel__write_cell --status ok
mcp-glp-audit-proxy-verify data/audit.jsonl --print-head
```

`--print-head` prints `seq=<n> entry_hash=<64 hex>`. Copy that line into a ticket, an email or a LIMS record. Check it later with `--expect-head <seq>:<entry_hash>` or `--expect-head-file` (the file may hold that same line). The command exits 1 when the chain tip differs. The sidecar `data/audit.jsonl.head` makes a cut of whole trailing lines fail verification. Someone who can edit both the log and the sidecar can move them together; the external copy is the control. Community is tamper-evident via the hash chain. It is not signed. Signing is Pro. `--pubkey` passes a pinned public key file to the licensed signer plugin. With no licensed signer the check fails. Pass `--licence` and `--client-id`, or set `GLP_LICENCE_PATH` and `GLP_CLIENT_ID`, to load that signer. With no licence path, no licence file is read. A missing or invalid licence exits 2. Unsigned checkpoints stay the default and are not treated as signed. The log and the `.head` sidecar are mode 0600 on open. A log directory created by the store is mode 0700.

## Configure

`init` asks for the audit log path, the tool allow list, the principal (id, name, role), and the retention profile and legal hold. It writes a JSON config the same loader as startup accepts, with mode 0600. Prompts and the file are ASCII. The wizard does not open a network connection. If the destination already exists, it is left unchanged unless you answer yes to the overwrite question.

```bash
mcp-glp-audit-proxy init
mcp-glp-audit-proxy init /srv/glp/config.json
```

The default path is `GLP_CONFIG` when that variable is set, otherwise `config.json`. That is the same file the proxy reads.

`config check` loads a config and prints a plain-language error when it does not load. The process exits 0 when the file loads and 1 when it does not. It uses the same loader as startup, including the `GLP_*` overrides. The default path matches `init`.

```bash
mcp-glp-audit-proxy config check
mcp-glp-audit-proxy config check config.json
```

A licensed plugin can add questions and a validation step through the `mcp_glp_audit_proxy.wizard` entry point. An unlicensed plugin is not called and adds nothing. See `docs/PLUGINS.md`.

A licence file is local. There is no network call. LM1 is three lines: `LM1`, base64 of the body, and base64 of an RSA-2048 PSS signature over those raw bytes. LM2 is three lines: `LM2`, base64 of the body, and base64 of a 64-byte Ed25519 signature over those raw bytes, and the body must be compact sorted JSON. LM1, and LM2 with no `features` list, enable the features declared by the installed licensed plugins. An LM2 file that lists `features` enables only the listed names. Any other file is rejected. The production public keys are in `release_trust.json` and are loaded by `trusted_keys()` in `mcp_glp_audit_proxy.trust`. The fingerprint is not a machine id. Details are in `docs/PLUGINS.md`.

## What is recorded

Every mediated call, including denials and failures, is one JSON object on an append-only JSONL file. Each line is RFC 8785 canonical JSON. `entry_hash` is the SHA-256 of that object with `entry_hash` removed. `prev_hash` is the previous entry (64 zero digits for the first). `hash_algo` and `canonicalization` are stored on the entry. The open schema is `schema/audit-record.schema.json`. Cross-language vectors are in `schema/jcs-test-vectors.json`.

Fields include who (`principal` id, name, role), which tool, inputs, outputs, UTC timestamp plus `utc_offset`, protocol version, optional session id, record class (`gxp_data`, `access`, `technical`, `config`), reason for writes, and the previous hash.

Schema 1.3.0 stores `transport` (`stdio` or `https`), `channel` (`mcp` or `https`), `flow` (`mcp2mcp`, `mcp2api`, `api2mcp`, `api2api`, `mcp2llm`, `api2llm`, or null on local records), `http`, `arguments_sha256`, and `result_sha256`. The `http` object holds the method, the route template, the path with the query string removed, the kept headers, the names of stripped credential headers, the body SHA-256, `body_mode`, the stored body, the status, `latency_ms`, and `kind` (`api`, `llm`, or `mcp`). The query string is forwarded and is not stored. 1.0.0 and 1.1.0 lines omit the later keys. 1.2.0 lines omit the two SHA-256 fields. Older lines stay valid in the same chain.

The GxP trail is that file. The Python `logging` logger `mcp_glp_audit_proxy.technical` writes method, status and record class to stderr. It is not the record. Arguments are not written there.

## Policy

- Allow list and deny list use shell-style globs on the exposed tool name (`excel__write_cell`). Deny wins. An empty allow list denies every upstream tool.
- Roles are `operator`, `approver`, `qa` and `admin`. Only `operator` may call upstream tools. `qa` is read-only on the trail (`glp_verify_chain`, `glp_search_audit`, `glp_export_audit`). `approver` may record an approval and read the trail. `admin` may change policy and read the trail, and cannot call upstream tools.
- Auditing cannot be switched off. `glp_update_policy` with `audit_enabled: false` is denied and logged.
- Write tools (names matching `write_tools`) require a reason by default. The reason is `_meta["io.github.antonio-castellon/reason"]` or the argument `_glp_reason` (stripped before the upstream call).
- Optional human approval holds the write until a different person in the `approver` role records meaning `approved`. `reviewed` is stored with status `reviewed` and does not authorise the write. A log written before schema 1.1.0 may show that decision as status `approved` with meaning `reviewed`; those lines still verify and still do not authorise the write. `rejected` rejects it. An approval is single-use, bound to the SHA-256 of the canonical `{tool, arguments}`, and expires (default 3600 seconds). A successful write that presents a matching approval records it as consumed even if `require_approval_for_writes` was turned off before that call. A failed upstream call does not consume it. The record label is `approval`. It is not an electronic signature.
- HTTP routes use a second pair of lists, `http_allow` and `http_deny`. Each entry is `METHOD /path` with a shell-style glob on the path (`GET /v1/studies/*`). Deny wins. An empty `http_allow` denies every HTTPS route. It does not deny MCP tool calls. Only `operator` may call an HTTPS route.
- `audit.body_mode` is `hash_only` (the default for a new config), `redacted`, or `full`. Which value to use is the customer's and QA's decision. body_mode applies to HTTPS bodies and to MCP tool-call arguments and results. The SHA-256 of the raw request body is always recorded, and the SHA-256 of MCP tool arguments and results is recorded the same way. `hash_only` stores no body bytes and no MCP payload. `redacted` stores JSON with the paths in `audit.redact_paths` replaced by `***` (a non-JSON body stores no plaintext). `full` stores the parsed JSON, or the UTF-8 text, of the request inside the hash-chained record, and `full` also stores the response text as `response_body` next to `response_sha256`. The log file is mode 0600. Binary that is not UTF-8 is hashed and not stored as the request body. The response body is returned to the client in every mode. A write request without Content-Length, or with Transfer-Encoding, is refused with 411 and logged. In hash_only and redacted modes the trail proves that a payload existed and was unaltered, but does not show its content; the content record must be kept by the target system (OECD No. 17 para 80).
- The default body limit is 1048576 bytes. `audit.max_body_bytes` may be raised up to 8388608. A larger body is refused with status 413, is not forwarded, and is recorded with `body_sha256` null. Streaming is not part of 0.4.0. GET and HEAD with no `Content-Length` have an empty body. A write without `Content-Length`, or with `Transfer-Encoding`, is refused with 411 and logged.
- HTTPS writes (`POST`, `PUT`, `PATCH`, `DELETE`) require the header `X-Audit-Reason` when `require_reason_for_writes` is true. Optional approval reuses the same engine. The bound hash is the canonical `{tool, arguments}` where `tool` is `http:METHOD /route-template` and `arguments` are `body_sha256` plus the concrete path. The approver calls `glp_approve` or `POST /_glp/approve`. `reviewed` and `rejected` do not authorise the write.
- Fail closed is the default. The store is checked before a call is forwarded. If the append after a successful upstream call fails, the upstream payload is not returned to the host. Denied and failed calls are still logged. If the upstream may already have applied a write, follow `docs/RECONCILIATION_SOP.md`.

## Protocol

The proxy speaks both handshake-era MCP revisions (`2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, with `initialize`) and spec `2026-07-28` (`server/discover`, no initialize, no session). A session id is recorded only when that revision has one. Upstream protocol `auto` tries `server/discover` and falls back to `initialize` at `2025-11-25`.

Exposed tool names are `server__tool`. Resource URIs are prefixed `server:`. Credential-bearing `_meta` keys are stripped, their names are logged, and their values are neither stored nor forwarded. Upstream stdio receives a safe environment allow-list from the MCP SDK, plus the env block in the config.

## Regulatory coverage

mcp-glp-audit-proxy is designed to support the audit-trail requirements below. Meeting them still depends on your SOPs and reviews. The clause-by-clause matrix is `docs/COVERAGE.md`. The norms and the verification log are `docs/STANDARDS.md`.

HTTPS identity is one of three modes. `mtls` maps the SHA-256 fingerprint of the client certificate to a principal. `bearer` reads one static token from a private file and compares it without writing the token to a log or to the record. On Linux and macOS that file must be mode 0600. On Windows, startup reads the NTFS ACL and allows access only for the current user, SYSTEM, and BUILTIN\Administrators. If Everyone, Users, Authenticated Users, or any other principal has access, startup refuses and prints `icacls <file> /inheritance:r /grant:r "%USERNAME%:R" SYSTEM:F Administrators:F`. `mtls_and_bearer` requires both. There is no unauthenticated mode and no plaintext listener. A shared bearer is a gate. It is not a unique user id. FDA data-integrity questions and answers (2018): "When login credentials are shared, a unique individual cannot be identified through the login." WHO TRS 1033 11.9: shared logins or generic user access should not be used. An optional `end_user_header` is accepted only after that gate, and only when the header value is a configured user id.

The package is designed to support 21 CFR 11.10(d) "Limiting system access to authorized individuals." and EU GMP Annex 11 (2011) sections 12.1 and 12.4. 12.1: "Physical and/or logical controls should be in place to restrict access to computerised system to authorised persons." 12.4: "Management systems for data and for documents should be designed to record the identity of operators entering, changing, confirming or deleting data including date and time." 21 CFR 11.300 covers controls for identification codes and passwords used in electronic signatures; electronic signatures are out of scope, so 11.300 is out of scope, like 11.100(a). The mode that fits those expectations is per-user attribution: one client certificate per person, or the end-user header from an authenticated gateway. A shared bearer plus a client-supplied header is only as strong as the gateway that checked the person.

| Framework | What the proxy helps with | Edition |
|---|---|---|
| OECD GLP No. 17 (3.4) / Swiss GLPV Annex 2 | Always-on, append-only audit trail; who/what/when/why; admin-only settings; QA read-only role; 10-year Swiss retention profile | Community core; WORM retention and PDF reports in Pro |
| FDA 21 CFR Part 11 | Computer-generated, time-stamped, hash-chained audit trail (11.10(e)); tamper detection; complete copies; authority checks. Community is tamper-evident via the hash chain. It is not signed. Signing is Pro. Personal Part 11 e-signatures are out of scope. An approval is not an electronic signature | Community core; reports, checkpoint signing, and SSO in Pro |
| EU GMP Annex 11 (2011; 2025 draft) | Audit trail of changes with reason; role, time zone; audit trail that cannot be switched off and is tamper-evident (hash chain); searchable export via glp_search_audit / glp_export_audit; access log | Community core; review tooling and inactivity logout in Pro |
| MHRA / PIC/S PI 041-1 / WHO TRS 1033 | ALCOA+ data integrity, segregation of duties, metadata with each record, true-copy exports | Community core; signed manifests and validation pack in Pro |
| ISPE GAMP 5 / FDA CSA | Supplier documentation, proposed Cat. 4 configured components, machine-readable test evidence | Pro (validation pack) |
| EU AI Act Art. 12, 19, 26(6) | Designed to support Art. 12, 19 and 26(6) where the customer's AI system is high-risk: the proxy can supply automatically generated logs that a provider or deployer may keep. It does not by itself make an AI system meet Art. 12. A 6-month default retention floor is applied; the AI Act minimum applies unless Union or national law, in particular data-protection law, provides otherwise. High-risk use is the customer's classification. See http://data.europa.eu/eli/reg/2024/1689/oj | Community |
| Crypto and time (RFC 8785, SHA-256, Ed25519/ECDSA, RFC 3161, eIDAS/ZertES, TLS 1.3) | Canonical hashing and encrypted transport | Hash chain and TLS in Community; signing and timestamps in Pro |
| MCP authorization, OWASP LLM/Agentic | No token passthrough, tool allowlist/denylist, approval before write tools, OAuth 2.1 | Allowlist and no-passthrough in Community; OAuth/SSO in Pro |
| ISO/IEC 42001, NIST AI RMF | Event-log evidence for AI governance and monitoring | Community (supporting evidence only) |

Default retention is the Swiss GLP profile: 10 years after study completion, with a floor of 6 months. The `minimum` profile may use a shorter year count but cannot go under 6 months. A legal-hold flag refuses disposal. The JSONL backend has no delete. Retention-period WORM enforcement is a Pro backend.


## Limitations

The proxy complements the target system's audit trail and does not replace it. It records gateway activity and is designed to support audit-trail review (search and export). It records no old and new values.

Turning require_reason_for_writes off removes the reason capture (OECD No. 1 8.3.5, Annex 11 sec. 9, 21 CFR 58.130(e)); the change is itself logged.

Community JSONL is tamper-evident, not tamper-proof: a host administrator can delete the file; detection relies on verify plus external anchoring or backup (WHO TRS 1033 11.15/11.16, OECD No. 22 6.14).

Use add-on audit trails as a justified, documented, time-bound measure where a system cannot keep its own (WHO TRS 1033 11.12, OECD No. 22 6.13). For GxP use, set require_ntp to true.

Records are append-only and hash-chained. A missing or edited record stops the proxy (GxP fail-closed) with a critical alert. Community has no in-place erasure or crypto-shredding. Erasure (GDPR Art. 17) is a customer procedure: close the segment, handle the archived copy, start a new segment. Before choosing body_mode full, weigh erasure requests against legal retention duties (Art. 17(3)(b), (c), (d)). To keep erasable content out of the chain, use hash_only or redacted.

Community does not encrypt the log at rest. The file is owner-only (0600, or an owner-only ACL on Windows). Use disk or volume encryption, especially with body_mode full.

body_mode is global, not per route. full stores request and response bodies (which can include health data) for the whole retention period (10 years or more under the Swiss GLP profile).

Retention profiles set minimums; the proxy never deletes records. Disposal after the retention period is a customer procedure.

A fail-closed stop interrupts the AI tool traffic. Include it in your contingency plan.

Failed-authentication lockout is off unless listen.auth_failure_limit is set. regulatory-report shows that line as not configured and names OECD No. 25 para 14 and Annex 11 draft 2025 11.7 (draft, not in force), so QA can decide whether to enable it. There is no lockout by default.

Configuration changes, including identities and roles, are recorded on the next audit/startup (config_changed). They are visible only at restart. Give --change-reason or GLP_CHANGE_REASON when require_reason_for_writes is on; if it is missing the process still starts and the record stores a null reason.

Every audit record holds personal data in every body_mode: principal id and name, role, client certificate fingerprint, end-user id when end_user_header is used, the request path (it can contain ids), the kept request headers (for example user-agent), and timestamps. hash_only is not anonymisation: an unsalted SHA-256 of a short or guessable body can be matched by guessing. The customer is the controller and decides the lawful basis, the body_mode, the redact_paths and the retention. See [Personal data in audit records](SAFETY.md#personal-data-in-audit-records).

## Validation in a GLP facility

In a GLP test facility the proxy transfers and stores GLP-relevant records, so it is itself a computerised system that the test facility validates (AGIT V4.0 category C: complex systems requiring validation). The open OQ runner, the requirements traceability matrix, the regulatory configuration report and the CHANGELOG are inputs to that validation; they are not the validation.

Audit-trail review (AGIT 11.2): use glp_search_audit, glp_export_audit and verify in your review SOP. Archiving the closed package is described in [docs/ARCHIVING.md](docs/ARCHIVING.md).

## System requirements

Python 3.11, 3.12, and 3.13, as tested in CI. CI tests Linux. The same source is written to run on macOS and Windows. Keep the host clock synchronised (NTP) and protect it from unauthorised change. For GxP use, set require_ntp to true.

Disk: a hash_only record is on the order of 1 KB. redacted and full grow with the payload. Plan for that size times the calls you keep, and for growth of about 1,000 times one record per 1,000 calls. The log and its head file must be on the same backed-up volume. Restoring one without the other makes startup refuse until you close the segment.

## Regulatory configuration report

`mcp-glp-audit-proxy regulatory-report --config config.json` reads the configuration only and prints, by group, whether that configuration supports each mapped clause. It does not start the service, open the log, or use the network. `--format md` or `json`, `--out FILE`, `--profile swiss_glp`, and `--applies glp,part11,ai_high_risk,gdpr_bodies`. `--fail-on-gap` exits 1 when a checked row is not supported. The customer's QA makes the final assessment. The map is `src/mcp_glp_audit_proxy/data/regulatory_map.json`, which is also checked against `docs/COVERAGE.md`.

`archive-manifest` writes an index of the log, the head sidecar, segment files, and an alert file when one exists. `verify --manifest` checks a later copy. `archive-transfer` and `verify --manifest --received-by` record custody of that package. See [docs/ARCHIVING.md](docs/ARCHIVING.md). Day-to-day operation, backups, and the independent head check are in [docs/OPERATIONS.md](docs/OPERATIONS.md).

`review <audit_file> --out FILE` writes a review-by-exception report (`--format json`, `md`, or `csv`). The CSV is one row per record in the period. The report does not copy bodies.

Offline `verify`, `verify --json-export`, `archive-manifest`, `regulatory-report`, and `review` never append to the live audit log. Each output carries a `run` block. `--run-log FILE` appends the same block to a separate hash-chained log. Check that log with `verify-run-log`. An export made through the running gateway (`glp_export_audit`) is still a record in the live trail.


## Community and Pro

This repository is the Community edition. Pro is available as a licensed / paid service - contact [antonio@castellon.ch](mailto:antonio@castellon.ch).

Pro adds SQL and S3 WORM backends, Ed25519 and ECDSA signing, RFC 3161 timestamps, PDF and CSV auditor reports, an IQ/OQ validation pack, and SSO. It also includes the GLP Lab Data Pack for [mcp-advanced-excel](https://github.com/antonio-castellon/mcp-advanced-excel), unlocked by the same offline licence key. The free mcp-advanced-excel server reads and writes lab spreadsheets. The Data Pack adds what a GLP lab needs on top: provenance hashes that tie every result back to its source file, instrument templates for common lab exports, advanced LOD/LOQ calculations and molar unit conversions, batch processing of many files in one run, and Ed25519 signed output.

A mark means that edition includes the capability. Pro includes every Community capability. A note is added only where the mark alone would hide a limit. A Community cell that lacks the capability is a plain `:x:`. Nothing in this table links to a Pro source tree.

| Capability | Community (this repo) | Pro (licensed service) |
|---|---|---|
| Proxy core, both protocol eras | :white_check_mark: | :white_check_mark: plugs in, does not fork |
| Append-only JSONL hash chain | :white_check_mark: | :white_check_mark: plus SQL/S3 |
| PostgreSQL / MSSQL append-only | :x: | :white_check_mark: |
| S3 Object Lock | :x: | :white_check_mark: |
| Verify CLI and searchable JSON export | :white_check_mark: | :white_check_mark: |
| Plain-text verify listing | :white_check_mark: | :white_check_mark: |
| PDF / CSV auditor reports | :x: | :white_check_mark: |
| Audit-trail review tooling (flags, reviewer sign-off) | :x: | :white_check_mark: |
| DE / FR / EN report templates | :x: | :white_check_mark: |
| Old/new value capture for write tools | :x: | :white_check_mark: |
| Tool allowlist / denylist | :white_check_mark: | :white_check_mark: |
| HTTP method and route policy | :white_check_mark: | :white_check_mark: |
| HTTPS listener (TLS 1.3, no plaintext) | :white_check_mark: | :white_check_mark: |
| mTLS client-certificate identity | :white_check_mark: | :white_check_mark: |
| Static bearer token from a private file (0600, or an NTFS ACL on Windows) | :white_check_mark: | :white_check_mark: |
| Request body SHA-256, optional redacted or full body (full also stores the response text) | :white_check_mark: | :white_check_mark: |
| Gateway flows across MCP, HTTPS APIs, and LLM APIs | :white_check_mark: | :white_check_mark: |
| OIDC for the HTTPS listener | :x: | :white_check_mark: |
| Local roles (operator, approver, qa, admin) | :white_check_mark: | :white_check_mark: |
| Human approval before writes | :white_check_mark: | :white_check_mark: |
| Ed25519 / ECDSA signed checkpoints | :x: | :white_check_mark: |
| RFC 3161 timestamps | :x: | :white_check_mark: |
| IQ/OQ validation pack | :x: | :white_check_mark: |
| SSO / OAuth | :x: | :white_check_mark: |
| Syslog (RFC 5424) / SIEM export | :x: | :white_check_mark: |
| Key management (KMS/HSM), field-level encryption and redaction | :x: | :white_check_mark: |
| FIPS 140-3 mode | :x: | :x: on request |
| Merkle log with inclusion / consistency proofs | :x: | :white_check_mark: |
| OpenTelemetry spans (technical telemetry, not the audit record) | :x: | :white_check_mark: |
| GLP Lab Data Pack for mcp-advanced-excel (provenance hashes, instrument templates, advanced LOD/LOQ and molar units, batch processing, Ed25519 signed output) | :x: | :white_check_mark: |
| TLS 1.3 to remote upstreams, no token passthrough | :white_check_mark: | :white_check_mark: |
| Offline licence file, no phone-home | :white_check_mark: | :white_check_mark: reads the same file |
| Config wizard and config check | :white_check_mark: | :white_check_mark: |

Checked against this repository on 2026-10-25. Community marks match the code: JSONL store, `verify` CLI, JSON and text reporters, `glp_search_audit` / `glp_export_audit`, allow and deny lists, HTTP method and route policy, the four local roles, `glp_approve` stored as `approval`, unsigned checkpoints, TLS 1.3 in `tlsutil.py` and on the HTTPS listener, mTLS and the static bearer file, `body_mode`, the offline licence loader (LM1 and LM2), and `init` / `config check`. OIDC for the HTTPS listener is not in this tree. Pro marks follow the edition column in `docs/COVERAGE.md`. A plugin outside this tree declares `licence_feature`. Community enables that feature when the licence fingerprint matches this install's `client_id` and licensed plugins. The licence shapes are described under Configure. The fingerprint is not a machine id. PostgreSQL, MSSQL, S3 Object Lock, PDF/CSV, Ed25519/ECDSA, RFC 3161, the IQ/OQ pack, and SSO/OAuth are not implemented in this tree. Personal Part 11 e-signatures are out of scope for both editions. Syslog, KMS/HSM, and review flags/sign-off are Pro in `docs/COVERAGE.md` and are not in this tree. DE/FR/EN templates, the Merkle log, old/new value capture, and OpenTelemetry spans are marked for Pro. FIPS 140-3 mode is on request. The open OQ runner (`mcp-glp-audit-proxy-oq`) is not the IQ/OQ validation pack.

Plugin entry points, the `AuditStore` / `Signer` / `Reporter` contracts, and the licence file are described in `docs/PLUGINS.md`.

## Roadmap

Shipped Community items are in the sections above and in `CHANGELOG.md`. There is no separate roadmap file.

## Local tools

| Tool | Who | What |
|---|---|---|
| `glp_verify_chain` | qa, approver, admin | Check chain integrity. Still returns the report if the chain is broken. |
| `glp_search_audit` | qa, approver, admin | Filter entries. The audit of the search stores the filter and the count, not a second copy of every row. |
| `glp_export_audit` | qa, approver, admin | JSON electronic export with a hash manifest. A filtered export is marked `complete: false`. A broken chain is not exported. |
| `glp_approve` | approver | Record meaning `approved`, `reviewed` or `rejected`. |
| `glp_update_policy` | admin | Append a config event. Policy is replayed from the log. |

## Manuals

Start with the five-minute terminal audit in [`docs/manual-guides/QUICKSTART.md`](docs/manual-guides/QUICKSTART.md). Host setup for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Cline, Continue, a generic stdio client, the MCP Python SDK, LangChain, the OpenAI Agents SDK, Docker, a lab PC, a shared workstation, and an offline install is in [`docs/manual-guides/`](docs/manual-guides/README.md). The upstream MCP server must be reachable only through this proxy. The same pages cover anchoring, approval, plugin selection, and the fail-closed latch.

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

How to contribute is in `CONTRIBUTING.md`. The conduct note is `CODE_OF_CONDUCT.md`. Vulnerability reports go through `SECURITY.md`, not an open issue.
