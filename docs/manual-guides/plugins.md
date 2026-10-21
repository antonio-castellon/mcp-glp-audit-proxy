# Plugin configuration

`plugins` in `config.json` selects entry points. Community ships `storage` `jsonl`, `signer` `unsigned`, reporters `json` and `text`, and `auth` `env`. The factories are in `pyproject.toml`. Pro names exist only as reserved feature flags. This page does not describe how a Pro backend stores or signs data. The contracts are in `docs/PLUGINS.md`.

Startup refuses an unknown name, a name the licence does not enable, or a name that is not installed. The factory is not called in those cases. There is no silent fallback to `jsonl` or `unsigned`.

The upstream is still only in `upstreams`. A plugin does not add a second path from the host to the lab server.

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

Licence file. `format` must be `mcp-glp-audit-proxy-licence`. `features` is a list of strings. An empty list leaves Community features on. A Pro feature name is enabled only when this list contains it and the entry point is installed. Otherwise it is printed on stderr as unavailable, and selecting it under `plugins` refuses startup.

```json licence
{
  "format": "mcp-glp-audit-proxy-licence",
  "features": []
}
```

`GLP_LICENCE_PATH` overrides `licence_path` when it is non-empty. The loader does not contact a network to read either path.

Admin can change the allow list at runtime with `glp_update_policy`. `reason` is required. `audit_enabled` false is denied and logged. Policy is replayed from the log on startup. That tool does not change `plugins`.

## Verification

Start the proxy and read stderr. A rejected plugin prints `mcp-glp-audit-proxy:` and exits 1. A licence that names a feature with no installed entry point prints `licence requested features with no plugin:` and still starts, as long as `plugins` did not select that feature.

After a session, the startup audit entry records `arguments.plugins` with the auth, reporters, signer name, and storage that were selected. Search it:

```bash
mcp-glp-audit-proxy-verify /srv/glp/admin-1/audit.jsonl --method audit/startup
```

`glp_export_audit` with `"format": "text"` writes under `export_dir`. A `path` that escapes that directory is refused.

## Pitfalls

- `plugins.reporters` must be a non-empty list without duplicates. `[]` refuses startup.
- Names are lowercase. `JSONL` is not `jsonl`.
- The verify CLI ignores `plugins` and always reports signer `unsigned` on its export.
- Setting `plugins.signer` to a reserved Pro name without a licence and an installed entry point refuses startup. Do not do that to "turn signing on" in this repository. The Community signer returns `signed: false`.
- `auth` values other than `env` are reserved names. They are not implemented here. A missing or unlicensed selection fails closed.
