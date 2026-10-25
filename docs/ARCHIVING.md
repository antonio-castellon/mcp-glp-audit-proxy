# Archiving the audit package

The Community log is tamper-evident, not tamper-proof. An operating-system administrator can delete or truncate the file. Restricting administrators is a customer risk control. Detection uses `verify`, an external copy of the head, and backups. Backups, the independent head check, and administration are in [docs/OPERATIONS.md](OPERATIONS.md).

## Archive package

The package is every file listed by `archive-manifest`, plus the manifest itself:

- the log
- `<log>.head`
- each closed segment file and its head
- `<log>.alert.json` when an alert was written
- the manifest (`--format json` or `md`)
- the transfer record from `archive-transfer` (`manifest_sha256`, from, to, by, method, at)
- the receipt inside the `verify --manifest --report-out` file when `--received-by` is set and the package matches (`complete and unaltered`)
- the verifier version: the wheel you used, and the SHA-256 of the source tree or the wheel file
- the configuration in force, copied beside the package
- the run log of offline verify, export, manifest, and report commands, when you keep one

The manifest file is not rewritten by a later transfer or by verify. Its SHA-256 identifies the package.

`archive-manifest` reads the files and writes only `--out`. It refuses to write the manifest when verify fails. The archivist fills `archivist_received_by` and `archivist_received_at` on receipt.

Copy closed segments to archive storage controlled by the archivist. Keep that copy read-only, or on storage that refuses overwrite and delete. Do not leave the only copy on the gateway host.

## Backups and checks

Keep off-site backups of the archived package, including the manifest and the head files. The log and its head file must be backed up together and restored together. Restoring an older copy makes the head disagree, and the proxy refuses to start until the segment procedure is run.

Run `verify --manifest --report-out` after each backup restore test, after each migration, and at risk-based intervals. Keep the reports. The check reads the package. Put `--report-out` outside the archive directory so the check does not write into it.

## Migration

A file copy is verified with the manifest before and after. Compare record counts and SHA-256 values. Moving to another storage backend or another format is a migration the customer validates. Records are never rewritten. A mixed chain of older schema lines and later lines stays verifiable; do not rewrite the older lines.

## Disposal

Community has no disposal function. Disposal and erasure follow the customer SOP. `segment close` requires `--reason` and `--approved-by` (and `--ticket`). Closing a segment for erasure or disposal needs test facility management approval, and sponsor approval when the SOP says so. Both values are stored on `audit/segment_start` of the new segment.

Retention under the Swiss GLP profile is at least 10 years. The proxy never deletes records when that period ends.

## Prerequisites

The host clock is synchronised (NTP) and protected against unauthorised change. For GxP use, set `require_ntp` to true. The config file, `fail_closed`, and `body_mode` are changeable only by authorised staff. Audit recording stays on during GLP work. There is no runtime switch that turns it off.

## What the gateway records

The gateway records gateway activity and is designed to support audit-trail review (`glp_search_audit`, `glp_export_audit`, and `verify`). It complements the data audit trail of the target system and does not replace it. It records no old and new values. An audit trail differs from a log file: use the hash-chained record, not stderr.
