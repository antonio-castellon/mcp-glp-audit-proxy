# Plugin interfaces

Community ships one storage backend, one signer and two reporters. The licensed Pro edition registers more entry points in the same groups. It should not need to fork this repository. `build_proxy` loads the factories named in config. It does not hard-code `JsonlAuditStore` or `UnsignedSigner`.

Nothing in the feature loader opens a socket. A licence is a local JSON file.

## Entry point groups

Declared in `pyproject.toml`. Each value is a factory, not the class.

| Group | Community name | Factory | Returns |
|---|---|---|---|
| `mcp_glp_audit_proxy.storage` | `jsonl` | `jsonl_store(settings, signer, options=None)` | `JsonlAuditStore` |
| `mcp_glp_audit_proxy.signers` | `unsigned` | `unsigned_signer(settings, options=None)` | `UnsignedSigner` |
| `mcp_glp_audit_proxy.reporters` | `json`, `text` | `json_reporter(settings, options=None)`, `text_reporter(settings, options=None)` | `JsonReporter`, `TextReporter` |
| `mcp_glp_audit_proxy.auth` | `env` | `env_identity(settings, options=None)` | `EnvIdentity` |
| `mcp_glp_audit_proxy.licence` | (none) | zero-arg factory | object with `verify(raw)` |

Pro names reserved by `mcp_glp_audit_proxy.features.PRO_PLUGINS` (not implemented here):

| Feature flag | Group | Entry point name |
|---|---|---|
| `storage.postgres` | `mcp_glp_audit_proxy.storage` | `postgres` |
| `storage.mssql` | `mcp_glp_audit_proxy.storage` | `mssql` |
| `storage.s3_object_lock` | `mcp_glp_audit_proxy.storage` | `s3` |
| `signer.ed25519` | `mcp_glp_audit_proxy.signers` | `ed25519` |
| `signer.ecdsa` | `mcp_glp_audit_proxy.signers` | `ecdsa_p256` |
| `timestamp.rfc3161` | `mcp_glp_audit_proxy.signers` | `rfc3161` |
| `signature.part11` | `mcp_glp_audit_proxy.signers` | `part11` |
| `report.pdf` | `mcp_glp_audit_proxy.reporters` | `pdf` |
| `report.csv` | `mcp_glp_audit_proxy.reporters` | `csv` |
| `validation.iqoq` | `mcp_glp_audit_proxy.reporters` | `iqoq` |
| `auth.sso` | `mcp_glp_audit_proxy.auth` | `sso` |
| `auth.oauth` | `mcp_glp_audit_proxy.auth` | `oauth` |

The auth group stays reserved. Dropping `sso` and `oauth` would remove names `PRO_PLUGINS` already publishes. Community does not add an identity provider. `IdentityProvider` is the contract, and `env` is the default: it returns the principal `load_settings` already took from `GLP_PRINCIPAL_*` or `config.json`. `resolve()` returns `{"id", "name", "role"}`. A Pro plugin uses the same `(settings, options=)` factory signature and the same method. This repository does not implement `sso` or `oauth`.

`mcp_glp_audit_proxy.licence` is the signature verifier. This repository does not register one. `FeatureSet.load` uses `CommunityLicenceVerifier` until a package registers a factory in that group. One installed factory is used. If several are installed, the name `default` is required.

`load_group` in `mcp_glp_audit_proxy.plugins` returns `{name: loaded object}`. A missing group is an empty dict.

## Selection

Config (all keys optional):

```json
{
  "plugins": {
    "storage": "jsonl",
    "signer": "unsigned",
    "reporters": ["json", "text"],
    "auth": "env"
  }
}
```

A name may also be an object. `options` is `plugins.<group>.options`. Reporters use `names` plus a map of reporter name to options. Community factories accept `options` and ignore it. The object is not written to the audit log.

```json
{
  "plugins": {
    "storage": {"name": "jsonl", "options": {}},
    "signer": {"name": "unsigned", "options": {}},
    "reporters": {"names": ["json", "text"], "options": {"text": {}}},
    "auth": {"name": "env", "options": {}}
  }
}
```

Missing `plugins` uses the string defaults and passes an empty options object. `build_proxy` then:

1. Resolves the auth factory and calls it with `(settings, options=)`. The returned principal replaces `settings.principal` before anything is built. A role outside `operator`, `approver`, `qa` and `admin` refuses startup.
2. Resolves the signer factory and calls it with `(settings, options=)`.
3. Resolves the storage factory and calls it with `(settings, signer, options=)`.
4. Resolves each reporter factory and calls it with `(settings, options=)` for that reporter's object.

A Pro package uses the same signatures. This repository only maps names to feature flags and calls the factory. It does not contain a Pro backend.

Startup records the selected names on the `audit/startup` entry (`arguments.plugins`).

The process refuses to start (`ConfigurationError`, exit 1) when:

- the name is not a Community name and not one of the reserved Pro names (unknown)
- the name is a Pro feature and the licence does not enable it (not licensed)
- the licence names it but no entry point is installed (not installed)
- the factory is missing, not callable, raises, or returns an object that does not match the contract

An unknown entry point that happens to be installed is not called. There is no fallback to `jsonl` or `unsigned` when the config named something else.

`glp_export_audit` takes an optional `format` (default `json`). The name must be one of the configured reporters. `json` is still written as pretty JSON so a reviewer can search it. Any other reporter writes the bytes from `render()`. The verify CLI does not read `plugins` from config: it prints text with `format_entry` and, with `--json-export`, pretty JSON. Its manifest signer field stays `unsigned`.

## Contracts

Structural protocols live in `mcp_glp_audit_proxy.interfaces`.

`AuditStore`:

- `health() -> bool`
- `read_entries() -> list[dict]`
- `append_event(event: dict) -> dict` returns the sealed entry (with `seq`, `prev_hash`, `entry_hash`)

No `update` and no `delete`. The store assigns the chain fields. Callers pass the body built by `records.build_event`. A store that sees a broken chain raises `ChainIntegrityError` and does not append.

`Signer`:

- attribute `name: str`
- `sign(payload: bytes) -> dict`
- `verify(payload: bytes, signature: dict) -> bool`

The Community signer returns `{"algorithm": null, "signed": false, "value": null}`. `verify` is true only for that unsigned shape. A Pro signer returns a real signature object. Checkpoints store that object under `result.signature`. The checkpoint entry is then hashed into the chain like any other entry. The checkpoint `reason` is `unsigned checkpoint (Community); signing is a Pro plugin` only when the unsigned signer is used. Any other signer name is recorded as `checkpoint signed by <name>`.

`Reporter`:

- attribute `name: str`
- attribute `media_type: str`
- `render(document: dict) -> bytes`

`JsonReporter` renders RFC 8785 bytes. The verify CLI writes pretty JSON via `dumps_document` so a reviewer can search it; the manifest hashes are the chain hashes, not a hash of the pretty file.

## Licence file

```json
{
  "format": "mcp-glp-audit-proxy-licence",
  "features": ["storage.postgres", "signer.ed25519"]
}
```

Point config `licence_path` or `GLP_LICENCE_PATH` at that file. With no licence file, `FeatureSet.load` does not call a verifier and enables only Community features.

`expires` is optional. When present it is an RFC 3339 timestamp with a time zone. `FeatureSet.load` compares it with the local clock and raises `LicenceError` (`licence expired`) when the time is not still in the future. A missing zone or a value that is not a timestamp is rejected. This is not a clock check against a vendor.

`signature` is optional. When present it must be an object. `FeatureSet.load` delegates that object to the licence verifier (`validate_licence`). With no verifier installed, a signature is rejected (`licence signature cannot be verified`). A verifier that raises, or returns false, rejects the file. Features in a rejected file are not enabled.

```json
{
  "format": "mcp-glp-audit-proxy-licence",
  "features": ["storage.postgres", "signer.ed25519"],
  "expires": "2027-01-01T00:00:00+00:00",
  "signature": {"algorithm": "ed25519", "key_id": "example", "value": "<verifier-defined>"}
}
```

`FeatureSet.load`:

- always enables Community features (`storage.jsonl`, `signer.unsigned`, `report.json`, `report.text`, `verify`, `policy.allowlist`, `approval.local`, `rbac.local`, `auth.env`) when the file is accepted
- enables a Pro feature only when the licence lists it and the matching entry point is installed
- records anything else on `unavailable` and the server prints that list to stderr
- still refuses to start if config selects a feature that is not both licensed and installed

There is no network call and no grace period fetched from anywhere. If the plugin is not installed, the feature stays off. Selecting it in config is an error, not a silent skip. A file with neither `expires` nor `signature` still loads.
