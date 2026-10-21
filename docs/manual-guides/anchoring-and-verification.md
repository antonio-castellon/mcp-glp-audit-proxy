# Log anchoring and verification

The Community store appends RFC 8785 JSON lines. Each line carries `prev_hash` and `entry_hash` (SHA-256). After every fsynced line the store writes `<audit-path>.head` with `seq` and `entry_hash`, via a temp file in the same directory, an fsync, and an atomic rename. The log and the head are set to mode `0600` on open. A change to an existing file is logged as a warning. A log directory created by the store is mode `0700`.

Someone who can edit both the log and the sidecar can move them together. The control on this machine is an external copy of the tip, checked with `--expect-head` or `--expect-head-file`. Community is tamper-evident via the hash chain. It is not signed. Signing is Pro.

The upstream must still be reached only through the proxy. Verification reads a file. It does not replace that rule.

## Prerequisites

- A log produced by the proxy (`audit.path` or `GLP_AUDIT_PATH`)
- `mcp-glp-audit-proxy-verify` on PATH
- A place outside this machine for the tip line: a ticket, an email, or a LIMS record

## Install

```bash
python -m pip install mcp-glp-audit-proxy
mcp-glp-audit-proxy-verify --help
```

The verify flags are `--json-export`, `--record-class`, `--tool`, `--status`, `--principal`, `--method`, `--server`, `--since`, `--until`, `--print-head`, `--expect-head`, `--expect-head-file`, and `--pubkey`. There is no `--config` on this command. Without `--pubkey` it does not load plugins. `--pubkey` passes the file bytes to the licensed signer plugin. Unsigned checkpoints do not satisfy that check. The JSON export's signer field stays `unsigned` unless a licensed signer produced the checkpoint.

## Minimal config

No extra proxy config is required to verify. This is a complete proxy file that turns checkpoints on every 100 entries (the default) so the log you verify is the one the rest of the guides use.

```json proxy
{
  "principal": {
    "id": "qa-1",
    "name": "Quinn QA",
    "role": "qa"
  },
  "policy": {
    "allow": [],
    "deny": [],
    "write_tools": [],
    "require_approval_for_writes": true,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "/srv/glp/qa-1/audit.jsonl",
    "fail_closed": true,
    "checkpoint_every": 100
  },
  "export_dir": "/srv/glp/qa-1/exports",
  "upstreams": []
}
```

QA can call `glp_verify_chain` through the proxy. That tool returns the report even when the chain is broken. The CLI exits 1 in that case and does not write an export.

```bash
mcp-glp-audit-proxy-verify /srv/glp/qa-1/audit.jsonl --print-head
```

Stdout, when the chain is intact and the log is non-empty:

```
seq=1 entry_hash=<64 lowercase hex>
```

Stderr contains `chain ok entries=<n> shown=<n> head=<hash> seq=<n>`. Copy the stdout line off the machine. Do not only copy `<audit>.head`. That file sits next to the log.

## Hardened config

Checkpoints more often, a dedicated export directory, and a filtered export that is still a full-chain verify.

```json proxy
{
  "principal": {
    "id": "qa-1",
    "name": "Quinn QA",
    "role": "qa"
  },
  "retention": {
    "profile": "swiss_glp",
    "min_months": 6,
    "years_after_study": 10,
    "legal_hold": true,
    "study_completion": null
  },
  "policy": {
    "allow": [],
    "deny": [],
    "write_tools": [],
    "require_approval_for_writes": true,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "/srv/glp/qa-1/audit.jsonl",
    "fail_closed": true,
    "checkpoint_every": 50
  },
  "require_ntp": false,
  "export_dir": "/srv/glp/qa-1/exports",
  "licence_path": null,
  "plugins": {
    "storage": "jsonl",
    "signer": "unsigned",
    "reporters": ["json", "text"],
    "auth": "env"
  },
  "upstreams": []
}
```

```bash
mcp-glp-audit-proxy-verify /srv/glp/qa-1/audit.jsonl --json-export /srv/glp/qa-1/exports/audit.json --print-head
mcp-glp-audit-proxy-verify /srv/glp/qa-1/audit.jsonl --expect-head-file /srv/glp/qa-1/expected-head.txt
mcp-glp-audit-proxy-verify /srv/glp/qa-1/audit.jsonl --record-class gxp_data --since 2026-01-01T00:00:00Z
```

`--since` and `--until` filter printed lines. They are not a retention setting. A filtered JSON export is marked incomplete in the document (`complete: false` in the export the proxy tool writes). The CLI export is the filtered set plus the full chain used for the manifest. Read `docs/RECONCILIATION_SOP.md` before you treat a gap as a restored record.

Inside a QA session the same check is the tool `glp_verify_chain` with no arguments.

## Verification

Compare today's stdout line with the line you stored outside the machine, or pass that line to `--expect-head-file`.

- Exit 0 and `chain ok`: the file matches its hashes. If stderr also says `head lags by 1 verified record`, the last record verifies and startup will advance the sidecar. That is the crash window between the log fsync and the head rename. Restart, run the command again, and the lag note should be gone. Do not hand-edit the sidecar.
- Exit 1 and `chain invalid`: stop. Do not export. Follow `docs/RECONCILIATION_SOP.md`. A missing head, a short log, or a hash mismatch is in this group.
- A cut of whole trailing lines that also rewrites `.head` is not detected on this machine unless `--expect-head` or `--expect-head-file` names the earlier tip. The off-host `seq=` line is what detects it.

## Pitfalls

- `checkpoint_every` 0 is stored as 100. It does not disable checkpoints.
- The CLI does not take `--config` or `GLP_AUDIT_PATH`. Pass the log path as the positional argument. `--pubkey` is the only flag that loads a signer plugin.
- Editing a sealed line, then hoping verify will rewrite it, fails. Verify does not change entry bytes. It does set the log and the head to mode `0600` when it can, and it warns when an existing mode changes.
- Reconciliation when the upstream applied a write and the append failed is `docs/RECONCILIATION_SOP.md`. The host was shown a JSON-RPC error, code `-32000`, `data.reason` `fail_closed`, and the upstream payload was not returned.
- QA's empty `upstreams` is correct for a review station. An operator station still names the upstream only in its own proxy config.
