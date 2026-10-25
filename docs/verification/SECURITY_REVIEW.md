# Security review

Date: 2026-10-18. This note records the review of Community edition 0.1.0. The package version is now 0.4.0. The findings below still apply. It is evidence that supports a customer's own records. It is designed to support GLP / 21 CFR Part 11 / EU GMP Annex 11 workflows.

## What CI runs

On Python 3.11, 3.12 and 3.13:

- `pip-audit -r requirements.lock` (hashed lock from `pip-compile --generate-hashes`)
- `bandit -r src -ll` (medium and high)
- `ruff check src --select S`

`requirements.lock` had no known vulnerabilities at the time of this review. The editable project itself is not on PyPI, so pip-audit skips that name.

## Findings

| Tool | Item | Disposition |
|---|---|---|
| bandit B310 / ruff S310 | `urlopen` in the HTTPS upstream | The URL is rejected unless the scheme is `https`, and the TLS context is 1.3 only. `nosec` / `noqa` mark that check. |
| bandit B314 / ruff S314 | XML parse of the JUnit file | Switched to `defusedxml`. The file is produced by the local test run. |
| bandit B603 / ruff S603 | `subprocess` for the configured upstream, `timedatectl`, `git`, and pytest | `shell` is not used. Upstream argv comes from the operator config, not from a tool argument. `timedatectl` and `git` are resolved with `shutil.which` to an absolute path. |
| bandit B404 (low) | `import subprocess` in `clockutil.py`, `upstream.py`, `verification/oq.py` | Accepted. Same calls as the row above. CI uses `-ll`, so this low notice does not fail the job. It stays visible in a full `bandit -r src` run. |
| ruff S607 | partial executable path | Resolved by `shutil.which` before the call. |

## Open risks

- A cut of whole trailing lines fails verification against `<log>.head`. Cutting the log and the sidecar together still verifies locally. Keep `--print-head` outside the machine. Signed checkpoints and WORM storage are Pro.
- JSONL is tamper-evident, not a WORM store. A person who can edit the file and the sidecar can change history if nobody kept a copy of the previous head.
- If an upstream write is applied and the append then fails, the host does not receive the result, but the upstream action may already have happened. Follow `docs/RECONCILIATION_SOP.md`.
- Stdio identity is the environment of the host process. The proxy does not run an identity provider.
- MCP tool arguments follow `audit.body_mode`. The default stores a SHA-256 and not the payload. Secrets must not be placed in arguments. `_meta` credential keys are stripped.
- The size limit is 1 MiB per JSON-RPC message, including a stream that never sends a newline. The session ends. The body is not stored.
- The bearer token file is private. POSIX requires mode 0600. Windows reads the NTFS DACL through the standard-library Win32 calls and refuses to start unless the only principals with access are the current user, SYSTEM, and BUILTIN\Administrators. The error prints the icacls command.
