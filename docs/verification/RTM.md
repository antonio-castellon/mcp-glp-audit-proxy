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

The OQ runner needs a source checkout. It runs pytest on `tests/` and reads `docs/verification/rtm.yaml`. A PyPI install does not include that tree. Pass `--repo-root` or run the command from a clone. If the checkout cannot be found, the command exits 2 and does not start pytest.

Regenerate the verification report from a clone with:

```bash
mcp-glp-audit-proxy oq-report --repo-root . --markdown docs/verification/sample/oq-report.md --json docs/verification/sample/oq-report.json
```

or `python -m mcp_glp_audit_proxy.verification`.
