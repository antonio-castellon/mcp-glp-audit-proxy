# Requirements traceability matrix

This matrix is evidence that supports a customer's own records. It is designed to support GLP / 21 CFR Part 11 / EU GMP Annex 11 workflows. The machine-readable rows are in `rtm.yaml`.

How to read `scope`:

- `community`: this repository claims the control. CI fails unless every named test passed.
- `pro`: out of scope (Pro). Not tested here.
- `customer`: customer responsibility. Not tested here.
- `gap`: documented limit. Not claimed as a Community control.

OECD GLP Series No. 22 is the data-integrity advisory cited in `docs/STANDARDS.md`. Rows `GLP22-1` through `GLP22-3` map the attributes this proxy actually exercises. They do not quote paragraph numbers.

`GAP-TAIL` is a Community control: `<log>.head` is written after each fsynced record, and verify fails when the log is shorter or the hash does not match. A head that lags by one verified record is recovered on startup. Cutting the log and the sidecar together is still only caught by an external copy of `--print-head`. Signed checkpoints and WORM storage are Pro.

A host or upstream that never sends a newline is capped at 1 MiB. The session ends. The refusal is audited without the body (`VER-LIMITS`).

Regenerate the verification report with:

```bash
mcp-glp-audit-proxy oq-report --markdown docs/verification/sample/oq-report.md --json docs/verification/sample/oq-report.json
```

or `python -m mcp_glp_audit_proxy.verification`.
