# Plugin configuration

`plugins` in `config.json` selects entry points. Community ships `storage` `jsonl`, `signer` `unsigned`, reporters `json` and `text`, and `auth` `env`. The factories are in `pyproject.toml`. Each factory declares `licence_feature` (for example `storage.sql`). This page does not describe how another backend stores or signs data. The contracts are in `docs/PLUGINS.md`.

Startup refuses an unknown name, a factory that does not declare `licence_feature`, and a declared feature the licence does not enable. The factory is not called in those cases. There is no silent fallback to `jsonl` or `unsigned`.

The upstream is still only in `upstreams`. A plugin does not add a second path from the host to the lab server.

`init` and `config check` read the entry-point group `mcp_glp_audit_proxy.wizard` the same way. Community does not register a factory in that group. A factory is called only when its `licence_feature` is enabled. Otherwise it adds no question and no check.

## Prerequisites

- `mcp-glp-audit-proxy` installed so the Community entry points are registered
- Optional: a local licence file. Community features stay on without one

## Install

```bash
python -m pip install mcp-glp-audit-proxy
```

An editable install from a checkout registers the same entry points. Reinstall after you change `pyproject.toml` so Python's metadata sees the factories.

## Minimal config

Defaults. You can omit `plugins` and get `jsonl`, `unsigned`, `json` plus `text`, and `env`. This file states them.

```json proxy
{
  "principal": {
    "id": "operator-1",
    "name": "Ada Analyst",
    "role": "operator"
  },
  "policy": {
    "allow": ["excel__read_*"],
    "deny": [],
    "write_tools": [],
    "require_approval_for_writes": false,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "./data/audit.jsonl",
    "fail_closed": true
  },
  "licence_path": null,
  "plugins": {
    "storage": "jsonl",
    "signer": "unsigned",
    "reporters": ["json", "text"],
    "auth": "env"
  },
  "upstreams": [
    {
      "name": "excel",
      "transport": "stdio",
      "protocol": "auto",
      "command": "python",
      "args": ["-m", "your_excel_mcp_server"],
      "env": {}
    }
  ]
}
```

`auth` `env` returns the principal `load_settings` already resolved from `GLP_PRINCIPAL_*` or `principal`. `resolve()` returns `id`, `name`, and `role`. It is not an identity provider.

## Hardened config

Same Community plugins, stated explicitly, licence file present, reporters limited to the ones you will export. `glp_export_audit` `format` must be one of the configured reporter names. Unknown `format` is a denied call (`reporter:unknown`), not a startup error. `json` is written as pretty JSON. `text` writes the reporter's bytes.

```json proxy
{
  "principal": {
    "id": "admin-1",
    "name": "Dan Admin",
    "role": "admin"
  },
  "policy": {
    "allow": [],
    "deny": [],
    "write_tools": [],
    "require_approval_for_writes": true,
    "require_reason_for_writes": true
  },
  "audit": {
    "path": "/srv/glp/admin-1/audit.jsonl",
    "fail_closed": true,
    "checkpoint_every": 50
  },
  "export_dir": "/srv/glp/admin-1/exports",
  "client_id": "lab-1",
  "licence_path": "/srv/glp/licence.json",
  "plugins": {
    "storage": "jsonl",
    "signer": "unsigned",
    "reporters": ["json", "text"],
    "auth": "env"
  },
  "upstreams": []
}
```

Licence file. Two shapes are accepted. JSON uses `format` `mcp-glp-audit-proxy-licence` and an Ed25519 signature over the RFC 8785 bytes with the `signature` field removed. `features` is a list of strings. An empty list leaves Community features on. A feature outside that set is enabled only when the signature verifies, the fingerprint matches, and an installed factory declares the same `licence_feature`. Otherwise the name is not loaded. A verified feature that no factory declares is printed on stderr as unavailable. JSON `expires`, when set, is an RFC 3339 timestamp with a time zone; a time that is not still in the future is rejected after the signature and the fingerprint.

LM1 is three text lines: `LM1`, base64 of the JSON body, and base64 of an RSA-2048 PSS signature over those raw body bytes (MGF1 with SHA-256, salt length equal to the digest). The body bytes are UTF-8 from `json.dumps` with `sort_keys=True`, `separators=(",", ":")`, and `ensure_ascii=False`. The loader checks that signature and does not re-encode the JSON. The object keys are `app`, `expires`, `fingerprint`, `holder`, `issued`, `kind`, `updates_until`, and `version`. There is no `features` field. `app` must be `mcp-glp-audit-proxy`. `kind` is `trial`, `year`, or `perpetual`. `expires` is an ISO date (`YYYY-MM-DD`) or null. Null does not expire. `updates_until` and `version` are kept and not checked yet. A matching fingerprint enables the `licence_feature` of each installed licensed plugin in that set.

The public keys are `LICENCE_PUBLIC_KEY` and `LICENCE_RSA_PUBLIC_PEM` in `mcp_glp_audit_proxy.licence`. Both are test keys. Replace them before issuing customer licences. The private keys are not in this repository.

The fingerprint is the lowercase SHA-256 hex of the RFC 8785 array `[client_id, "mcp-glp-audit-proxy", [sorted licensed entry-point names]]`. `client_id` comes from config. The names are installed entry points whose `licence_feature` is outside the Community set. Community names are not included. There is no machine fingerprint. Startup computes the digest and refuses the file when it does not match, so each new licensed plugin needs a new licence. A JSON file that lists only Community features, and has neither a signature nor a fingerprint, still loads.

A plugin value may be a name, or `{"name": "<plugin>", "options": {}}`. Reporters may be `{"names": ["json", "text"], "options": {}}`. `options` is `plugins.<group>.options` and is passed to that factory. Community factories ignore it. It is not written to the audit log.

```json licence
{
  "format": "mcp-glp-audit-proxy-licence",
  "features": []
}
```

`GLP_LICENCE_PATH` overrides `licence_path` when it is non-empty. The loader does not contact a network to read either path.

Admin can change the allow list at runtime with `glp_update_policy`. `reason` is required. `audit_enabled` false is denied and logged. Policy is replayed from the log on startup. That tool does not change `plugins`.

## Verification

Start the proxy and read stderr. A rejected plugin or a licence whose fingerprint does not match prints `mcp-glp-audit-proxy:` and exits 1. A verified licence that names a feature no installed factory declares prints `licence requested features with no plugin:` and still starts, as long as the fingerprint matches and `plugins` did not select that feature.

After a session, the startup audit entry records `arguments.plugins` with the auth, reporters, signer name, and storage that were selected. Search it:

```bash
mcp-glp-audit-proxy-verify /srv/glp/admin-1/audit.jsonl --method audit/startup
```

`glp_export_audit` with `"format": "text"` writes under `export_dir`. A `path` that escapes that directory is refused.

## Pitfalls

- `plugins.reporters` must be a non-empty list without duplicates. `[]` refuses startup.
- Names are lowercase. `JSONL` is not `jsonl`.
- The verify CLI ignores `plugins` and always reports signer `unsigned` on its export.
- Setting `plugins.signer` to a name that is not installed, or whose `licence_feature` is not enabled, refuses startup. Do not do that to turn signing on in this repository. The Community signer returns `signed: false`.
- `auth` values other than `env` are not implemented here. A missing or unlicensed selection fails closed. The factory is not called.
