# Operating the gateway

This page is guidance for the customer's own procedures. The product is designed to support those procedures. It does not assess the customer's system. See also [ARCHIVING.md](ARCHIVING.md).

## Backups

Back up the log, `<log>.head`, closed segments and their head files, alert files, the config (without token files), and a copy of the head pin from `verify --print-head`. Keep that copy on another host, another network, and behind another firewall. Verify every backup and every restore with `verify --manifest`. Keep a backup and restore-test log.

The log and its head file are restored together. An older copy makes startup refuse until the segment procedure is run.

## Independent check

The test facility keeps the head pin outside the gateway host and runs `verify --expect-head-file` on its own schedule. A report from the vendor or from the host does not replace that check.

## Administration

The person who administers the operating system or the gateway config should not be a person who generates or reviews the audited data. A shared bearer token is not a personal identity. Use mTLS or `end_user_header` when each person must be named.

There is no lockout by default. `listen.auth_failure_limit` is optional and off until the config sets `max_failures`, `window_seconds`, `block_seconds`, and `key` (`address`, `identity`, or `both`). `regulatory-report` shows that line as not configured and names OECD No. 25 para 14 and Annex 11 draft 2025 11.7 (draft, not in force). The customer's QA decides whether to enable it. The limit applies to the HTTPS listener only.

Configuration changes are visible only at restart. The next `audit/startup` records identities, roles, `body_mode`, and `config_changed`. Pass `--change-reason` or set `GLP_CHANGE_REASON` when a reason is required. The process still starts if the reason is missing, and the record stores a null reason.

## Archiving order

Copy the closed package, build the manifest (`archive-manifest`), write the transfer record (`archive-transfer`), and verify with a receipt (`verify --manifest --received-by --report-out`). Only then delete the source. Keep a second archive copy. Archive the verifier wheel and the source with their SHA-256 values. The manifest is not rewritten by the transfer or the check.

## Hosted service

Use this section only when a service provider runs the gateway. The agreement should name the roles, require test-facility management to release changes that affect validation, forbid subcontracting without authorisation, give QA and inspectors access, keep records for the retention period (at least 10 years for the Swiss GLP profile), notify the customer of a breach, and describe exit and readability of the records.

## Data-integrity risks

| Factor | Gateway control | Customer control |
| --- | --- | --- |
| Incomplete transfer | archive-manifest hashes and verify --manifest | Second copy, receipt, restore test |
| Generic login | per-person mTLS or end_user_header; a shared bearer is flagged by regulatory-report | One account per person |
| Unprotected system time | require_ntp when set | NTP, and protect the clock |
| Software version change | CHANGELOG names RTM ids; oq --requirement runs that subset; existing records are not rewritten | Impact assessment and the OQ |
| Cyber attack | hash chain, fail closed, optional authentication limit | Network control, backups, the external head pin |

## Where the chain lives

The hash chain is kept on the customer's system. It is not a distributed or independent ledger.

Exports through the running gateway (`glp_export_audit`) are recorded in the live audit trail. Offline `verify`, export, `archive-manifest`, `regulatory-report`, and `review` are recorded in the run log (`--run-log`), which is hash-chained and checked with `verify-run-log`. Those commands do not append to the live audit log.
