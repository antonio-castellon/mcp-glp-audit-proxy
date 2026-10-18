# Plugin interfaces

Community ships one storage backend, one signer and two reporters. The private package `mcp-glp-audit-proxy-pro` registers more entry points in the same groups. It should not need to fork this repository.

Nothing in the feature loader opens a socket. A licence is a local JSON file.

## Entry point groups

Declared in `pyproject.toml`:

| Group | Community name | Object |
|---|---|---|
| `mcp_glp_audit_proxy.storage` | `jsonl` | `JsonlAuditStore` |
| `mcp_glp_audit_proxy.signers` | `unsigned` | `UnsignedSigner` |
| `mcp_glp_audit_proxy.reporters` | `json`, `text` | `JsonReporter`, `TextReporter` |

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

`load_group` in `mcp_glp_audit_proxy.plugins` returns `{name: loaded object}`. A missing group is an empty dict.

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

The Community signer returns `{"algorithm": null, "signed": false, "value": null}`. `verify` is true only for that unsigned shape. A Pro signer returns a real signature object. Checkpoints store that object under `result.signature`. The checkpoint entry is then hashed into the chain like any other entry. Community checkpoints are explicit about being unsigned.

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

Point config `licence_path` or `GLP_LICENCE_PATH` at that file. `FeatureSet.load`:

- always enables Community features (`storage.jsonl`, `signer.unsigned`, `report.json`, `report.text`, `verify`, `policy.allowlist`, `approval.local`, `rbac.local`)
- enables a Pro feature only when the licence lists it and the matching entry point is installed
- records anything else on `unavailable` and the server prints that list to stderr

There is no network call, no clock check against a vendor, and no grace period fetched from anywhere. If the plugin is not installed, the feature stays off.
