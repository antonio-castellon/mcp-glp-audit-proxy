# Quickstart

Five minutes, from a checkout, in a terminal. No desktop client. This walkthrough is an audit of two tool calls, a denied call, and a tamper check. The approval gate stays off. `examples/config.json` sets `require_approval_for_writes` to false and `require_reason_for_writes` to false.

The package on PyPI does not include `examples/`. Clone the repository.

## 1. Install

```bash
python -m pip install -e .
```

`--help` on the server shows `--config` only.

```bash
python -m mcp_glp_audit_proxy --help
```

## 2. Run the audit

`examples/walkthrough.py` copies `examples/config.json` into a temporary directory, points the upstream at `examples/hello_upstream.py`, and starts the proxy. It calls `lab__hello`, `lab__save_note`, and `lab__drop_all` (not on the allow list). It then runs verify, edits one log line, runs verify again, and restores the line.

```bash
python examples/walkthrough.py
```

Stable lines from a run on 2026-10-21 (timestamps and hashes change every run):

```text
HELLO Hello, Ada.
SAVE Saved: bench 1 is clean
DENIED denied by policy (allow:none)
NOTES bench 1 is clean
LOG_COUNT 5
```

`lab__hello` returns `Hello, Ada.` `lab__save_note` returns `Saved: bench 1 is clean` and appends that text to `hello-notes.txt` in the upstream working directory. `lab__drop_all` is not forwarded. The proxy returns `denied by policy (allow:none)` and still appends a log line with `status` `denied` and `result` null.

The script does not call `tools/list`, so the log has five lines: startup, initialize, `lab__hello`, `lab__save_note`, `lab__drop_all`. A desktop client also calls `tools/list`, so the hello line is not always line 3.

## 3. Read the log lines

Each line is one JSON object. On the `lab__hello` line the script prints:

- `principal`: who called. `id`, `name`, and `role` come from `GLP_PRINCIPAL_*` (here `operator-1`, `Ada Analyst`, `operator`).
- `timestamp`: when, as UTC in RFC 3339. It changes every run.
- `tool`: the exposed name, `lab__hello`. The upstream name `lab` plus the tool `hello`.
- `arguments`: the call arguments, `{"name":"Ada"}`. A normal line has no separate args hash. `entry_hash` covers the arguments.
- `result`: what the proxy returned, including the text `Hello, Ada.`
- `prev_hash`: the previous line's `entry_hash`. The first line uses 64 zeroes.
- `entry_hash`: the chain hash. SHA-256 of the RFC 8785 JSON of the line with `entry_hash` removed.

`lab__save_note` is the same shape with `arguments` `{"text":"bench 1 is clean"}`, `status` `ok`, and `record_class` `gxp_data` because `write_tools` lists it. `lab__drop_all` has `status` `denied`, `arguments` `{}`, and `result` null. Its `prev_hash` equals the save line's `entry_hash`.

## 4. Verify

The script runs both of these. Exit 0. Stderr for an intact five-line log:

```text
chain ok entries=5 shown=5 head=<64 hex> seq=5
```

`--print-head` adds one stdout line after the per-entry listing:

```text
seq=5 entry_hash=<64 hex>
```

That `entry_hash` equals the `head=` value. Copy it off the machine. The same checker is the console script `mcp-glp-audit-proxy-verify`. On your own log, replace the path:

```bash
python -m mcp_glp_audit_proxy verify REPLACE_WITH_ABSOLUTE_PATH/data/audit.jsonl
python -m mcp_glp_audit_proxy verify REPLACE_WITH_ABSOLUTE_PATH/data/audit.jsonl --print-head
```

`verify` prints one `format_entry` line per record on stdout: `seq`, `time`, `class`, `status`, `principal`, `role`, `method`, `tool`, `server`. The JSONL file is the full record.

## 5. Tamper, then restore

The script changes `Hello, Ada.` to `Hello, Ada!` in the hello line and runs verify again. Exit 1. Stderr:

```text
chain invalid
line 3: entry_hash mismatch
```

Line 3 is the hello line only because this script did not call `tools/list`. The mismatch is on the line you edited. It then writes the original bytes back. The next verify exits 0 and stderr contains `chain ok` again.

To do it by hand on a log you keep: copy the file, change one character inside one JSON line, run the verify command, read `chain invalid`, then put the original file back and run verify again.

## 6. If it does not work

- `python examples/walkthrough.py` must be run from a checkout that contains `examples/hello_upstream.py`. A PyPI install alone does not have that file.
- `examples/config.json` must still say `"require_approval_for_writes": false`. The script refuses to start otherwise.
- `REPLACE_WITH_ABSOLUTE_PATH` in a config you copied by hand must be replaced with the checkout path. The script does that for its temporary copy.
- The log for a hand-copied `examples/config.json` is `examples/data/audit.jsonl`, because `./data/audit.jsonl` is resolved next to the config file. `GLP_AUDIT_PATH` moves it.
- Role must be `operator` for `lab__hello` and `lab__save_note`. `qa`, `approver`, and `admin` cannot call upstream tools.
- stderr of a refused startup is the error. The process exits 1. There is no port to connect to.

## Optional: four-eyes gate for write tools

Skip this for the audit demo. It is not required to see the hash chain.

In a copy of the config, set both of these to true:

```json
"require_approval_for_writes": true,
"require_reason_for_writes": true
```

`lab__save_note` is a write because it is listed in `write_tools`. A write with no reason is denied as `write:reason-missing` before the approval gate. Pass the reason as the argument `_glp_reason` (removed before the upstream call) or as `_meta["io.github.antonio-castellon/reason"]`.

The operator process then receives an error result and the call is not forwarded. The text is:

```text
Approval required before this write. approval_id=<uuid> args_hash=<64 hex>. An approver must call glp_approve. This call was not forwarded. The record is an approval, not an electronic signature.
```

`args_hash` exists on that approval object. It is not a field of an ordinary `lab__hello` line.

The operator cannot approve their own write. Start a second process with the same `GLP_CONFIG` and `GLP_AUDIT_PATH`, and with `GLP_PRINCIPAL_ROLE=approver` (and a different id and name). That process may call `glp_approve` with `approval_id` and `meaning` `approved`. It cannot call `lab__save_note`. The success text is:

```text
Recorded an approval. This is not an electronic signature.
```

`meaning` `reviewed` is stored as `reviewed` and does not authorise the write. The text is `Recorded. This meaning does not authorise the write.` `meaning` `rejected` stores a rejection.

The approval id travels only in `_meta["io.github.antonio-castellon/approvalId"]` on the later write. It is not an argument. The later write has to repeat the same arguments, including `_glp_reason`, because `args_hash` is a hash of those arguments. A changed argument does not match the approval. Many chat clients cannot set `_meta`. This gate is for a client that can send that field, or for a small JSON-RPC script. It is not part of the hello world above. A run of this path returned the pending text above, then `Recorded an approval. This is not an electronic signature.`, then `Saved: bench 1 is clean`.

The stored label remains `approval`. Part 11 electronic signatures are not in this repository.
