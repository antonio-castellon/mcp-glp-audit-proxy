# Safety

This proxy is a control point in front of real systems. Treat a misconfiguration as a data-integrity event.

## Fail closed

`fail_closed` defaults to true and should stay true. The store is health-checked and the chain is verified before a call is forwarded. If the store is down, the call is not forwarded. If the upstream call succeeds and the append then fails, the host does not receive the upstream payload. Denied calls and failed calls are written to the same chain.

There is a residual case you must design for: the upstream server may already have applied a write before the append fails. The host is told the request was not completed. Reconcile that call from the upstream system's own records. Do not retry blindly. Follow `docs/RECONCILIATION_SOP.md`: detection, immediate actions, the attributed reconciliation entry, chain verification and restart.

## The audit file is the record

`data/audit.jsonl` (or the path in config) is the GxP trail. stderr logs from `mcp_glp_audit_proxy.technical` are debug output. They record method, status and record class. They do not record arguments, and they are not the trail.

Do not log the JSONL file into a system that can rewrite lines. The Community backend detects edits, deletions and reordering. It does not prevent them. WORM retention (S3 Object Lock, append-only database tables) is a Pro backend.

## Identity

On stdio the principal is the environment: `GLP_PRINCIPAL_ID`, `GLP_PRINCIPAL_NAME`, `GLP_PRINCIPAL_ROLE`. The host process must set those to the authenticated human. A shared service account for operators is a bad fit for attribution.

Roles are split on purpose. An operator cannot verify, search, export, approve or change policy. An approver, a QA reviewer and an admin cannot call upstream tools.

## Secrets

`_meta` keys that look like credentials (`authorization`, `token`, `access_token`, `api_key`, `api-key`, `password`, `secret`, `cookie`) are removed before storage and before the upstream call. The field names are stored in `stripped_credential_fields`. The values are not.

Tool arguments are stored in full. That is the original record. Do not put passwords or tokens in tool arguments.

Upstream stdio processes receive the MCP SDK environment allow-list (`HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM`, `USER` on POSIX) plus the `env` object in that upstream's config. They do not inherit `GLP_*` or other parent secrets.

Remote upstreams must be `https`. The client context is TLS 1.3 only. Client tokens are not copied onto the upstream request. Upstream headers come only from that upstream's config.

## Approval is not an electronic signature

`require_approval_for_writes` asks a different person, in the approver role, to record meaning `approved` before a write is forwarded. The stored label is `approval`. It does not meet 21 CFR Part 11 signature rules (printed name plus meaning is recorded, but there is no two-factor re-authentication, no signature binding beyond the args hash, and no IdP). Part 11 electronic signatures are a Pro plugin.

Meaning `reviewed` does not authorise the write. The requester cannot approve their own request. Each approval matches one canonical `{tool, arguments}` digest and is single-use.

## Time

Timestamps are UTC with offset `+00:00`. Ordering is the monotonic `seq`, not the clock. `require_ntp` refuses startup when the local probe does not report a synchronised clock. Enabling it is the operator's choice; running NTP is the operator's job. The probe records `unknown` when it cannot tell. It does not invent a sync status.

## Retention

The default profile is Swiss GLP: 10 years after study completion, and never under 6 months. Set `study_completion` when you know it. `legal_hold: true` makes disposal raise. The JSONL store has no delete method either way.

## Audit cannot be disabled

`glp_update_policy` rejects `audit_enabled: false` and logs the attempt. Policy changes themselves are config-class entries and are replayed when the process handles the next call.
