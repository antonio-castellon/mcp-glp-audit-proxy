# Safety

This proxy is a control point in front of real systems. Treat a misconfiguration as a data-integrity event.

## Fail closed

`fail_closed` defaults to true and should stay true. The store is health-checked and the chain is verified before a call is forwarded. If the store is down, the call is not forwarded. If the upstream call succeeds and the append then fails, the host does not receive the upstream payload. Denied calls and failed calls are written to the same chain.

There is a residual case you must design for: the upstream server may already have applied a write before the append fails. The host is told the request was not completed. Reconcile that call from the upstream system's own records. Do not retry blindly. Follow `docs/RECONCILIATION_SOP.md`: detection, immediate actions, the attributed reconciliation entry, chain verification and restart.

Any failure to open, write or fsync the audit file, and any chain that no longer verifies, raises `AuditStoreError`. The process then latches into a blocked state: later calls are not forwarded until the process is restarted. A raw OS error does not skip that latch.

Plugin names in the config are entry points (`plugins.storage`, `plugins.signer`, `plugins.reporters`). Each factory declares `licence_feature`. Startup refuses an unknown name and a name whose feature is not enabled, and it does not call that factory. It does not silently keep the JSONL store or the unsigned signer when the config asked for something else. A signed licence is also bound to `client_id` and the installed licensed plugin names. A different set of plugins, or a different `client_id`, refuses the file. The binding is not a machine fingerprint.

Each fsynced line is followed by a sidecar file, `<audit-path>.head`. It stores the latest `seq` and `entry_hash` (temp file, fsync, atomic rename). The verify command fails when the log is shorter than that head or the hash does not match. A crash in the gap after the log fsync and before the head rename may leave the head one record behind. That one record must itself verify. Startup then advances the head. It is not treated as a broken trail. Any other disagreement refuses startup (`refusing to start`) and does not forward. A disagreement found on a later append latches the blocked state.

A person who can edit both the log and the sidecar can move them together. `mcp-glp-audit-proxy-verify --print-head` prints `seq` and `entry_hash` so an operator can copy that line into a ticket, an email or a LIMS record. That external copy is the control. Signed checkpoints and WORM storage are Pro.

A host or an upstream that never sends a newline is capped at 1 MiB. The proxy records a refusal with the byte count and the limit, not the body, and ends the session (exit 1). It does not scan for a later newline. An upstream that does this is closed, and the failure is logged without the body.

## The audit file is the record

`data/audit.jsonl` (or the path in config) is the GxP trail. stderr logs from `mcp_glp_audit_proxy.technical` are debug output. They record method, status and record class. They do not record arguments, and they are not the trail.

Do not log the JSONL file into a system that can rewrite lines. The Community backend detects edits, deletions and reordering. It does not prevent them. WORM retention (S3 Object Lock, append-only database tables) is a Pro backend.

## Identity

On stdio the principal is the environment: `GLP_PRINCIPAL_ID`, `GLP_PRINCIPAL_NAME`, `GLP_PRINCIPAL_ROLE`, or the same fields in `config.json` when those variables are unset. The `auth` plugin defaults to `env` and returns that principal. It does not contact an identity provider. `plugins.auth` set to another name refuses to start unless that entry point is installed and the signed licence includes the feature it declares. Those plugins are not in this repository. The host process must set the environment to the authenticated human. A shared service account for operators is a bad fit for attribution.

On the HTTPS listener the mode is `mtls`, `bearer`, or `mtls_and_bearer`. There is no unauthenticated mode and no plaintext listener. mTLS maps the SHA-256 fingerprint of the client certificate to a configured principal. The bearer is one line in a mode 0600 file. It is compared without being written to the log or to the record. A shared bearer is a gate, not a unique user id. `end_user_header` is trusted only after that gate, and only when the value is a configured id. Per-user attribution (one certificate per person, or an end-user header from an authenticated gateway) is the mode that fits the expectations described in the README. OIDC and SSO are not in this repository.

Roles are split on purpose. An operator cannot verify, search, export, approve or change policy. An approver, a QA reviewer and an admin cannot call upstream tools.

## Secrets

`_meta` keys that look like credentials (`authorization`, `token`, `access_token`, `api_key`, `api-key`, `password`, `secret`, `cookie`) are removed before storage and before the upstream call. The field names are stored in `stripped_credential_fields`. The values are not.

Tool arguments are stored in full. That is the original record. Do not put passwords or tokens in tool arguments.

`audit.body_mode` chooses what is stored next to the body SHA-256. The default is `hash_only`, which stores the hash and no body bytes. `redacted` stores a JSON copy with the configured paths replaced by `***`. `full` stores the plaintext inside the hash-chained record. The log file is mode 0600. Pick `hash_only` unless a procedure says the body itself has to be in the trail. Credential header values are not stored in any mode. Streaming is not part of 0.4.0. A request with no `Content-Length` is an empty body. A body over `max_body_bytes` (default 1 MiB, config ceiling 8 MiB) is not forwarded.

Upstream stdio processes receive the MCP SDK environment allow-list (`HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM`, `USER` on POSIX) plus the `env` object in that upstream's config. They do not inherit `GLP_*` or other parent secrets.

Remote upstreams must be `https`. The client context is TLS 1.3 only. Client tokens are not copied onto the upstream request. Upstream headers come only from that upstream's config.

## Approval is not an electronic signature

`require_approval_for_writes` asks a different person, in the approver role, to record meaning `approved` before a write is forwarded. The stored label is `approval`. It does not meet 21 CFR Part 11 signature rules (printed name plus meaning is recorded, but there is no two-factor re-authentication, no signature binding beyond the args hash, and no IdP). Personal Part 11 e-signatures are out of scope. Community is tamper-evident via the hash chain. It is not signed. Signing is Pro.

Meaning `reviewed` does not authorise the write. It is stored as status `reviewed` (schema 1.1.0). Older lines that stored it as status `approved` with meaning `reviewed` still verify, and the gate still refuses them. The requester cannot approve their own request. Each approval matches one canonical `{tool, arguments}` digest and is single-use. Consumption does not depend on `require_approval_for_writes` still being on: a successful write that presents a matching approval records `approval.status` `consumed`. A different call, or a failed upstream call, does not consume it. The failed call can be retried while the approval is still valid.

## Time

Timestamps are UTC with offset `+00:00`. Ordering is the monotonic `seq`, not the clock. `require_ntp` refuses startup when the local probe does not report a synchronised clock. Enabling it is the operator's choice; running NTP is the operator's job. The probe records `unknown` when it cannot tell. It does not invent a sync status.

## Retention

The default profile is Swiss GLP: 10 years after study completion, and never under 6 months. Set `study_completion` when you know it. `legal_hold: true` makes disposal raise. The JSONL store has no delete method either way.

## Audit cannot be disabled

`glp_update_policy` rejects `audit_enabled: false` and logs the attempt. Policy changes themselves are config-class entries and are replayed when the process handles the next call.
