# Changelog

## 0.4.0 - 2026-10-25

The commercial name is GxP Gateway Audit. The package name, the command names, the entry-point groups, and the MCP Registry id stay `mcp-glp-audit-proxy`.

Requirements affected: COV-SHUTDOWN, COV-MCP-BODY, COV-INTEGRITY, COV-SEGMENT, COV-REGULATORY, COV-ARCHIVE, COV-MIXED-SCHEMA, COV-STARTUP, COV-REVIEW, COV-RUNLOG, COV-AUTH-LIMIT, COV-TRANSFER, COV-CHANGE.
Effect on existing records: records already in a log are not rewritten and still verify. New records stay on schema 1.3.0. Offline verify, export, archive-manifest, regulatory-report, and review do not append to the live log.

### Behaviour change

- `audit.body_mode` now also applies to MCP tool-call arguments and results. With the default `hash_only` these are no longer stored in plaintext, only their SHA-256. Set `audit.body_mode` to `full` (or `redacted` with `redact_paths`) to keep storing them. Re-run the OQ after upgrading.
- `audit/startup` now records body_mode, listen, identities, the principal, and a SHA-256 of the effective configuration with secret values replaced. `config_changed` lists what differs from the previous startup. Pass `--change-reason` or `GLP_CHANGE_REASON` when a reason is required. A missing reason does not refuse startup. Re-run the OQ after upgrading.
- `review` writes a review-by-exception report and a CSV copy of the selected records. It does not copy bodies. Re-run the OQ after upgrading.
- Offline verify, JSON export, archive-manifest, regulatory-report, and review write a `run` block on their output and, with `--run-log`, a separate hash-chained run log. They do not append to the live audit log. Check the run log with `verify-run-log`. Re-run the OQ after upgrading.
- `listen.auth_failure_limit` can block an HTTPS client after repeated failed authentication. It is off unless configured. regulatory-report shows it as not configured. Re-run the OQ after upgrading.
- `archive-transfer` records custody of a manifest. `verify --manifest --received-by` adds a receipt only when the package matches. Re-run the OQ after upgrading.
- `mcp-glp-audit-proxy-oq --requirement` runs the tests mapped to the named RTM ids plus the chain smoke test. Re-run the OQ after upgrading.
- A POST, PUT, PATCH, or DELETE without `Content-Length`, or with `Transfer-Encoding`, is refused with 411 and logged. It is not forwarded. Re-run the OQ after upgrading.
- The process writes one `audit/shutdown` record on stdin EOF, on SIGTERM or SIGINT, and when the HTTPS server stops. `verify` reports a gap warning when a startup has no later shutdown. Old logs that have no shutdown records report the same warning. The hash chain still exits 0. Re-run the OQ after upgrading.
- A broken hash chain or head sidecar refuses startup and, at runtime, stops the process with exit code 3. A critical alert is written beside the log. This does not depend on `fail_closed`. Disk and permission errors keep the previous fail-closed latch. Re-run the OQ after upgrading.
- `regulatory-report` reads the config only and prints a configuration report. It does not start the service. Re-run the OQ after upgrading.
- `archive-manifest` and `verify --manifest` index and re-check a copied package. `segment close` requires a reason, a ticket, and `--approved-by`. Re-run the OQ after upgrading.

- New records use schema 1.3.0. Each line adds `arguments_sha256` and `result_sha256`. Schema 1.2.0 added `transport`, `channel`, `flow`, and `http`. A 1.0.0, 1.1.0, or 1.2.0 line in the same file still verifies. The verifier accepts all four.
- The process audits MCP and HTTPS calls. With no `listen` object it stays a stdio MCP proxy. With `listen` it serves HTTPS, TLS 1.3 only, and does not open a plaintext port. The client keeps its request and changes the base URL.
- Six flows: `mcp2mcp`, `mcp2api`, `api2mcp`, `api2api`, `mcp2llm`, `api2llm`. An LLM upstream is an HTTPS API whose records use kind `llm`.
- `audit.body_mode` is `hash_only` (the default), `redacted`, or `full`. Which value to use is the customer's and QA's decision. The SHA-256 of the raw body is always stored. `full` stores the request body and the response text inside the hash-chained record. The log file stays mode 0600. A body over the limit is not forwarded and the hash is null.
- HTTPS identity is `mtls`, `bearer`, or `mtls_and_bearer`. The bearer is one line in a private file and is compared without being logged. POSIX requires mode 0600. Windows requires an NTFS ACL limited to the current user, SYSTEM, and BUILTIN\Administrators, and prints `icacls <file> /inheritance:r /grant:r "%USERNAME%:R" SYSTEM:F Administrators:F` when another principal has access. There is no unauthenticated mode. OIDC and SSO stay a Pro plugin point.
- `policy.http_allow` and `policy.http_deny` match `METHOD /path`. Deny wins. An empty HTTP allow list denies every HTTPS route and does not change the MCP tool lists. `POST`, `PUT`, `PATCH`, and `DELETE` require `X-Audit-Reason` when reasons are required. An approval is bound to the method, the route template, the body hash, and the path.
- If the audit record cannot be written, the upstream body is not returned.

## 0.3.2 - 2026-10-22

- The JSON licence format is removed. LM2 supersedes it. A file that is not LM1 or LM2 text is rejected. With no licence file, Community features stay on.
- LM1 now verifies with the production RSA-2048 public key. LM2 still verifies with the production Ed25519 public key. Both keys are the only trust anchors in `release_trust.json`. `trusted_keys()` in `mcp_glp_audit_proxy.trust` loads that file. Pro should import `trusted_keys` instead of keeping a second copy. Test keys are not in the package.

## 0.3.1 - 2026-10-22

- On Windows, JSONL and the head sidecar stay LF. The JSONL lock uses the C runtime byte lock instead of `fcntl`. A timed pipe read uses `PeekNamedPipe` instead of `select`. A mode bit Windows cannot store does not fail the write. `verify --pubkey` takes `--licence` and `--client-id`, and also reads `GLP_LICENCE_PATH` and `GLP_CLIENT_ID`. With no licence path it still loads no licence. A missing or invalid licence exits 2.

## 0.3.0 - 2026-10-22

Community edition. The hash-chain format is unchanged. New records use schema 1.1.0. A line written as schema 1.0.0 still verifies. Personal Part 11 e-signatures are out of scope. Community is tamper-evident via the hash chain. It is not signed. Signing is Pro.

- `mcp-glp-audit-proxy init` writes the audit log path, allow list, principal, and retention profile with legal hold. It leaves an existing file unchanged unless you confirm the overwrite, and it writes that file as mode `0600`. `mcp-glp-audit-proxy config check` loads the same file, including `GLP_*` overrides, and exits 1 with a plain-language error when it does not load. Both are ASCII and do not use the network. `mcp_glp_audit_proxy.wizard` lets a licensed plugin add questions and validation. An unlicensed plugin is not called. (#16)
- `verify --expect-head <seq>:<entry_hash>` and `--expect-head-file` fail when the chain tip differs from an externally kept copy. The file may be a `--print-head` line. `--pubkey` passes that file to the one licensed signer plugin. Unsigned checkpoints stay the default and do not satisfy a pinned key. An existing log and `.head` are set to `0600` on open, with a warning when the mode changes. A log directory created by the store is `0700`. (#19)
- A licence file is one of three shapes, checked locally. JSON is Ed25519 over the RFC 8785 bytes. LM1 is three lines (`LM1`, base64 of the body, base64 of an RSA-2048 PSS signature over those raw bytes) and is not re-encoded. LM2 is three lines (`LM2`, base64 of the body, base64 of a 64-byte Ed25519 signature over those raw bytes); the body must also equal compact sorted JSON (`sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=False`). Any other text that starts with `LM` is rejected. LM1 has no `features` field. LM2 `features` is optional: when it is absent, a matching fingerprint enables the installed licensed plugins; when it is present, it is a non-empty sorted unique list of at most 64 names matching `^[a-z][a-z0-9._-]{0,47}$`, and only those features are enabled. The fingerprint for all three shapes is the lowercase SHA-256 hex of `[client_id, "mcp-glp-audit-proxy", sorted licensed entry-point names]`. There is no machine id. JSON `expires`, when set, is an RFC 3339 timestamp. LM1 and LM2 `expires` is an ISO date or null. `LICENCE_PUBLIC_KEY` and `LICENCE_RSA_PUBLIC_PEM` are test trust anchors. Replace both before issuing those customer licences. `LICENCE_LM2_PUBLIC_KEY` is the production Ed25519 public key. The private keys are not in this repository. (#14, #15, #20)
- Each plugin factory declares `licence_feature`. A feature outside the Community set is enabled only when the licence allows it and an installed factory declares it. No licence file still enables only Community features. `plugins.<group>.options` is passed to the factory. Community factories accept the object and ignore it. The options are not written to the audit log. A JSONL checkpoint `reason` names the active signer. The unsigned sentence is used only when the unsigned signer is used. (#13, #14)

## 0.2.0 - 2026-10-21

Community edition. The hash-chain format is unchanged. New records use schema 1.1.0. A line written as schema 1.0.0 still verifies.

- Plugin selection is wired from config. `plugins` chooses the storage, signer, reporter, and auth factories. The defaults stay `jsonl`, `unsigned`, `json` and `text`, and `env`. An unknown, unlicensed, or missing name refuses startup. Pro backends are not in this repository. (#7)
- The auth group keeps its contract. `IdentityProvider.resolve()` returns `id`, `name`, and `role`. The `env` factory returns the principal already loaded from `GLP_PRINCIPAL_*` or `config.json`. It is not an identity provider. `sso` and `oauth` stay reserved names. (#7)
- `glp_approve` with meaning `reviewed` is stored as status `reviewed` (schema 1.1.0) and does not authorise a write. A schema 1.0.0 line that stored that decision as status `approved` with meaning `reviewed` still verifies and still does not authorise the write. (#7)
- A matching approval is consumed when the write succeeds, including when `require_approval_for_writes` was turned off before that call. A failed upstream call does not consume it. (#7)
- The OQ runner requires a source checkout (`tests/` and `docs/verification/rtm.yaml`). A PyPI install exits 2 and does not start pytest. `mcp-glp-audit-proxy-oq` and `mcp-glp-audit-proxy oq-report` both stay. Neither is deprecated. (#7)
- `certifi` is pinned to `2026.10.19` in `requirements.lock`. (#7)
- The duplicate `Programming Language :: Python :: 3.13` classifier is removed. (#6)
- Host manuals are in `docs/manual-guides/`. The five-minute audit is `docs/manual-guides/QUICKSTART.md`, with `examples/hello_upstream.py` and a tamper check. The approval gate stays off in that example. (#8, #10)
- The README flow diagram, banner, and shields are in `docs/images/`. `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, and `SECURITY.md` are in the repository root. (#8, #9)
- The Community and Pro table uses `:white_check_mark:` and `:x:`. Pro includes every Community capability. (#10)
- The sample verification report under `docs/verification/sample/` was regenerated for this release. It replaces the report recorded at `c127000`.

## 0.1.0 - 2026-10-18

Initial Community release. Local stdio proxy, append-only JSONL hash chain, verify CLI, tool allow and deny lists, and the four local roles.
