# Changelog

## 0.3.0 - 2026-10-22

Community edition. The hash-chain format is unchanged. New records use schema 1.1.0. A line written as schema 1.0.0 still verifies. Personal Part 11 e-signatures are out of scope. Community is tamper-evident via the hash chain. It is not signed. Signing is Pro.

- `mcp-glp-audit-proxy init` writes the audit log path, allow list, principal, and retention profile with legal hold. It leaves an existing file unchanged unless you confirm the overwrite, and it writes that file as mode `0600`. `mcp-glp-audit-proxy config check` loads the same file, including `GLP_*` overrides, and exits 1 with a plain-language error when it does not load. Both are ASCII and do not use the network. `mcp_glp_audit_proxy.wizard` lets a licensed plugin add questions and validation. An unlicensed plugin is not called. (#16)
- `verify --expect-head <seq>:<entry_hash>` and `--expect-head-file` fail when the chain tip differs from an externally kept copy. The file may be a `--print-head` line. `--pubkey` passes that file to the one licensed signer plugin. Unsigned checkpoints stay the default and do not satisfy a pinned key. An existing log and `.head` are set to `0600` on open, with a warning when the mode changes. A log directory created by the store is `0700`. (#19)
- A licence file is one of three shapes, checked locally. JSON is Ed25519 over the RFC 8785 bytes. LM1 is three lines (`LM1`, base64 of the body, base64 of an RSA-2048 PSS signature over those raw bytes) and is not re-encoded. LM2 is three lines (`LM2`, base64 of the body, base64 of a 64-byte Ed25519 signature over those raw bytes); the body must also equal compact sorted JSON (`sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=False`). Any other text that starts with `LM` is rejected. LM1 has no `features` field. LM2 `features` is optional: when it is absent, a matching fingerprint enables the installed licensed plugins; when it is present, it is a non-empty sorted unique list of at most 64 names matching `^[a-z][a-z0-9._-]{0,47}$`, and only those features are enabled. The fingerprint for all three shapes is the lowercase SHA-256 hex of `[client_id, "mcp-glp-audit-proxy", sorted licensed entry-point names]`. There is no machine id. JSON `expires`, when set, is an RFC 3339 timestamp. LM1 and LM2 `expires` is an ISO date or null. `LICENCE_PUBLIC_KEY` and `LICENCE_RSA_PUBLIC_PEM` are test trust anchors. Replace both before issuing those customer licences. `LICENCE_LM2_PUBLIC_KEY` is the production Ed25519 public key. The private keys are not in this repository. (#14, #15, #20)
- Each plugin factory declares `licence_feature`. A feature outside the Community set is enabled only when the licence allows it and an installed factory declares it. No licence file still enables only Community features. `plugins.<group>.options` is passed to the factory. Community factories accept the object and ignore it. The options are not written to the audit log. A JSONL checkpoint `reason` names the active signer. The unsigned sentence is used only when the unsigned signer is used. (#13, #14)

## 0.2.0 - 2026-10-21

Community edition. The hash-chain format is unchanged. New records use schema 1.1.0. A line written as schema 1.0.0 still verifies.

- Plugin selection is wired from config. `plugins` chooses the storage, signer, reporter, and auth factories. The defaults stay `jsonl`, `unsigned`, `json` and `text`, and `env`. An unknown, unlicensed, or missing name refuses startup. Pro backends are not in this repository. (#7)
- The auth group keeps its contract. `IdentityProvider.resolve()` returns `id`, `name`, and `role`. The `env` factory returns the principal already loaded from `GLP_PRINCIPAL_*` or `config.json`. It is not an identity provider. `sso` and `oauth` stay reserved names. (#7)
- `glp_approve` with meaning `reviewed` is stored as status `reviewed` (schema 1.1.0) and does not authorise a write. A schema 1.0.0 line that stored that decision as status `approved` with meaning `reviewed` still verifies and still does not authorise the write. (#7)
- A matching approval is consumed when the write succeeds, including when `require_approval_for_writes` was turned off before that call. A failed upstream call does not consume it. (#7)
- The OQ runner requires a source checkout (`tests/` and `docs/verification/rtm.yaml`). A PyPI install exits 2 and does not start pytest. `mcp-glp-audit-proxy-oq` and `mcp-glp-audit-proxy oq-report` both stay. Neither is deprecated. (#7)
- `certifi` is pinned to `2026.10.19` in `requirements.lock`. (#7)
- The duplicate `Programming Language :: Python :: 3.13` classifier is removed. (#6)
- Host manuals are in `docs/manual-guides/`. The five-minute audit is `docs/manual-guides/QUICKSTART.md`, with `examples/hello_upstream.py` and a tamper check. The approval gate stays off in that example. (#8, #10)
- The README flow diagram, banner, and shields are in `docs/images/`. `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, and `SECURITY.md` are in the repository root. (#8, #9)
- The Community and Pro table uses `:white_check_mark:` and `:x:`. Pro includes every Community capability. (#10)
- The sample verification report under `docs/verification/sample/` was regenerated for this release. It replaces the report recorded at `c127000`.

## 0.1.0 - 2026-10-18

Initial Community release. Local stdio proxy, append-only JSONL hash chain, verify CLI, tool allow and deny lists, and the four local roles.
