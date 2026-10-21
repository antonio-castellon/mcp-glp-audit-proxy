# Changelog

## Unreleased

- `PRO_PLUGINS` and `PRO_FEATURES` are removed. Each plugin factory declares `licence_feature` (for example `storage.sql`). Community discovers installed entry points. A feature outside the Community set is enabled only when a signed licence lists it. An unlicensed plugin is not loaded. No licence file still enables only Community features.
- A licence file is either Ed25519 over RFC 8785 JSON, or LM1 text: `LM1`, base64 of the JSON body, and base64 of an RSA-2048 PSS signature (MGF1 with SHA-256, salt length equal to the digest) over the raw body bytes. Those bytes are UTF-8 from `json.dumps` with sorted keys and compact separators. The loader does not re-encode them. The LM1 object is `app`, `expires` (ISO date or null), `fingerprint`, `holder`, `issued`, `kind` (`trial`, `year`, or `perpetual`), `updates_until`, and `version`. It has no `features` field. `updates_until` and `version` are not checked yet. `LICENCE_PUBLIC_KEY` and `LICENCE_RSA_PUBLIC_PEM` are test trust anchors. Replace both before issuing customer licences. The private keys are not in this repository.
- Both formats are bound to a fingerprint: the lowercase SHA-256 hex of the RFC 8785 array `[client_id, "mcp-glp-audit-proxy", sorted licensed entry-point names]`. Startup computes it from config `client_id` and the installed plugins and refuses the file when it does not match. There is no machine fingerprint. An extra plugin requires a new licence. A matching LM1 fingerprint enables the `licence_feature` of those installed plugins. JSON `expires`, when set, is compared with the local clock after that check. LM1 uses `expires`: null does not expire, and a past ISO date does.
- `plugins.<group>.options` is passed to the plugin factory. Community factories accept the object and ignore it. The options are not written to the audit log.
- A JSONL checkpoint `reason` names the active signer. The unsigned sentence is used only when the unsigned signer is used.

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
