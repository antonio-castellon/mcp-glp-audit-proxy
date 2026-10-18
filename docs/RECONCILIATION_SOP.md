# SOP: Reconciling a write that the upstream applied but the audit log did not record

Scope: mcp-glp-audit-proxy Community edition, JSONL store. Use it when a write tool reached the
upstream server, the upstream may have applied it, and the audit append then failed (the residual
case in `SAFETY.md`, "Fail closed"). This is a template; adapt it into your own controlled SOP and
deviation process. Roles below are the proxy roles (`operator`, `approver`, `qa`, `admin`).

## 1. Detection

What the proxy does in this case (Community 0.1.0):

- The host gets a JSON-RPC error instead of the upstream result:
  code `-32000`, message `audit log unavailable; request was not completed`,
  `error.data.reason = "fail_closed"`, `error.data.detail` = the store error text
  (for example `audit store unavailable`). The upstream payload is never returned.
- On stderr, the technical logger writes one line just before every append attempt:
  `INFO mcp_glp_audit_proxy.technical audit append method=tools/call status=ok class=gxp_data`.
  If that line has no matching new line in the JSONL file, the append failed after the upstream call.
  This line has no tool name and no arguments by design.
- If the store raised `AuditStoreError`, the proxy enters a blocked state: every later request
  gets the same `fail_closed` error, except `glp_verify_chain`, and notifications are dropped.
  The block lasts until the process restarts.
- An OS error while opening, writing or fsyncing the audit file (disk full, I/O error, permission
  denied) is converted to `AuditStoreError` with detail `audit store write failed: ...`. That path
  sets the same blocked state. The proxy does not retry the store. A chain that no longer verifies
  (including a partial last line) also sets the blocked state.
- A partly written last line makes the chain invalid. The verify CLI then reports
  `file does not end with a newline` and `line N: not utf-8 json (...)`.

Alerting: Community has no built-in alerting. Forward the proxy's stderr to your log monitoring and
alert on `fail_closed`, `proxy handle failed` and `refusing to start`.

## 2. Immediate actions (operator, then admin)

1. Stop using the proxy. Do not retry the write; it may already be applied upstream.
2. Note what you know: time (UTC), your principal id, tool name, arguments, reason, and the error
   text the host showed.
3. Admin stops the proxy process (stop the MCP host or remove the server from it).
4. Admin copies, without editing: the JSONL file, the config file, and the proxy stderr log.
   Record the SHA-256 of each copy (`sha256sum`). Keep the copies with the deviation record.
5. Open a deviation in your quality system and tell QA.

## 3. Establish what happened upstream (operator + QA)

- Check the upstream system's own audit trail (ELN, LIMS, instrument, spreadsheet history) for the
  call: was the write applied, when, with which values?
- Possible outcomes: applied, not applied, or unknown. Only "applied" needs a reconciliation
  record in the chain. "Not applied" is documented in the deviation only; the operator repeats the
  write later through the proxy. "Unknown" stays open until the upstream owner confirms.

## 4. Root cause and repair (admin)

- Typical causes: disk full, file permissions, storage path missing or unmounted, file lock held
  by another process, a broken chain.
- Fix the cause. Do not edit, reorder or delete existing lines in the JSONL file.
- If the verify CLI reports only an incomplete last line (no newline, not JSON), that fragment was
  never a sealed entry. Remove it only with QA approval in the deviation, after step 2.4, and keep
  the original copy. Any other verify error is a data-integrity incident: stop and escalate to QA.

## 5. Verify the chain (QA or admin)

```bash
mcp-glp-audit-proxy-verify data/audit.jsonl
```

- Exit 0 and stderr `chain ok entries=N shown=N head=<hash>`: intact. Record N and the head hash.
- Exit 1 and stderr `chain invalid` plus one line per error: do not continue; see section 4.

## 6. Record the reconciliation entry (QA, with a second person)

Community has no electronic signature. Attribution and signature work like this:

1. Fill in the reconciliation form (template below). QA signs it and a second person (approver
   role or upstream system owner) countersigns, using your site's controlled signature process
   (wet ink or your validated e-signature system). Store it as a PDF and record its SHA-256.
2. With the proxy stopped and the chain verified, QA appends one attributed entry to the same
   chain with the Community library (adjust the values; the entry is hash-chained like any other):

<!-- reconciliation-snippet:start -->
```python
from pathlib import Path

from mcp_glp_audit_proxy.chain import verify_file
from mcp_glp_audit_proxy.records import build_event
from mcp_glp_audit_proxy.storage.jsonl import JsonlAuditStore

AUDIT_PATH = Path("data/audit.jsonl")  # the audit.path from the proxy config
RECONCILER = {"id": "qa-1", "name": "Quinn QA", "role": "qa"}
FORM_ID = "REC-2026-001"
FORM_SHA256 = "sha256-of-the-signed-form-pdf"

before = verify_file(AUDIT_PATH)
if not before.ok:
    raise SystemExit("chain invalid: " + "; ".join(before.errors))

event = build_event(
    method="audit/reconciliation",
    record_class="gxp_data",
    status="ok",
    server="excel",
    tool="excel__write_cell",
    principal=RECONCILER,
    client={"id": "manual-reconciliation", "name": FORM_ID},
    protocol_version=None,
    session_id=None,
    arguments={"cell": "B2", "value": 42},  # the original call, from section 3
    result={
        "form_id": FORM_ID,
        "form_sha256": FORM_SHA256,
        "original_principal_id": "operator-1",
        "original_time_utc": "2026-10-18T09:15:02Z",
        "upstream_evidence": "LIMS audit trail record 12345",
        "head_hash_before": before.head_hash,
    },
    policy_rule="manual-reconciliation",
    reason="Upstream applied the write; audit append failed. Reconciled per RECONCILIATION_SOP.",
)
sealed = JsonlAuditStore(AUDIT_PATH).append_event(event)
print("reconciliation entry seq", sealed["seq"], "hash", sealed["entry_hash"])
```
<!-- reconciliation-snippet:end -->

3. Write the printed `seq` and `entry_hash` on the form.
4. Run the verify CLI again; it must report `chain ok` with N+1 entries (N+2 if a checkpoint was
   due). List the entry with `mcp-glp-audit-proxy-verify data/audit.jsonl --method audit/reconciliation`.

The entry is attributable (principal, UTC time, reason, form hash) and tamper-evident. It is not a
21 CFR Part 11 electronic signature. With a Pro licence, the Part 11 e-signature plugin can sign the
reconciliation entry instead of the paper or external signature; this is optional.

## 7. Unblock (admin)

1. Restart the proxy (start the MCP host again). The blocked state only clears on restart.
2. On start the proxy verifies the chain. If the store is unavailable or the chain is invalid it
   prints `mcp-glp-audit-proxy: refusing to start: ...` and exits; go back to section 4.
3. A successful start appends an `audit/startup` entry (record class `config`). Run the verify CLI
   once more and record the new head hash on the form.
4. Tell the operator to resume. Repeat any write that was "not applied" (section 3) normally.
5. QA closes the deviation with the form, file hashes, and root cause.

## 8. Reconciliation record template

```
RECONCILIATION RECORD                              Form ID: REC-____-___
Deviation ref:            ______________
Proxy version / config:   ______________  Audit file path: ______________

Original call
  Operator (id, name):    ______________
  Time (UTC):             ______________
  Upstream server / tool: ______________ / ______________
  Arguments:              ______________
  Reason given:           ______________
  Host error shown:       audit log unavailable; request was not completed (fail_closed)

Upstream evidence
  System / record ref:    ______________
  Outcome:                [ ] applied   [ ] not applied   [ ] unknown
  Values applied:         ______________

Root cause and fix:       ______________

Chain verification
  Before: entries ____  head ______________  result [ ] chain ok
  Reconciliation entry:   seq ____  entry_hash ______________
  After:  entries ____  head ______________  result [ ] chain ok
  Copies kept (SHA-256):  audit file ________  config ________  stderr log ________

Signatures
  Reconciled by (QA):     name ______________  date ________  signature ________
  Second person:          name ______________  date ________  signature ________
```
