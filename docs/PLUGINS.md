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

Each factory declares `licence_feature`, a string such as `storage.sql`. Community reads that attribute from the installed entry points. There is no built-in list of Pro names in this repository, and this repository does not ship a Pro backend.

Community does not add an identity provider. `IdentityProvider` is the contract, and `env` is the default: it returns the principal `load_settings` already took from `GLP_PRINCIPAL_*` or `config.json`. `resolve()` returns `{"id", "name", "role"}`. Another auth plugin uses the same `(settings, options=)` factory signature and the same method, and it declares its own `licence_feature`. This repository does not implement one.

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

Another package uses the same signatures and sets `licence_feature` on its factory. This repository calls that factory only when the declared feature is enabled. It does not contain a Pro backend.

Startup records the selected names on the `audit/startup` entry (`arguments.plugins`).

The process refuses to start (`ConfigurationError`, exit 1) when:

- the name is not an installed entry point (`unknown plugin`)
- the factory does not declare `licence_feature`
- the declared feature is not enabled (`not licensed`); the factory is not called
- the factory is not callable, raises, or returns an object that does not match the contract

There is no fallback to `jsonl` or `unsigned` when the config named something else.

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

Point config `licence_path` or `GLP_LICENCE_PATH` at the file. `client_id` in the same config is the customer id used for the fingerprint below. With no licence file, `FeatureSet.load` enables only Community features and does not check a signature or a fingerprint.

A file is one of two shapes. Both are checked locally. There is no network call and no grace period fetched from a vendor.

### JSON, Ed25519

```json
{
  "format": "mcp-glp-audit-proxy-licence",
  "features": ["storage.jsonl", "report.json"]
}
```

`expires` is optional. When present it is an RFC 3339 timestamp with a time zone. `FeatureSet.load` compares it with the local clock and raises `LicenceError` (`licence expired`) when the time is not still in the future. A missing zone or a value that is not a timestamp is rejected. The check runs after the signature and the fingerprint, so `expires` is the signed value. This is not a clock check against a vendor.

Community features do not need a signature. Any other feature in `features`, a `fingerprint`, and any file that carries a `signature`, must verify as Ed25519 before a feature is enabled. A missing signature in that case raises `LicenceError` (`licence signature is required`). A bad signature raises `LicenceError` (`licence signature is invalid`). Features in a rejected file are not enabled.

The signature covers the RFC 8785 bytes of the licence object with the `signature` field removed. `algorithm` must be `ed25519`. `value` is standard base64 of the 64-byte signature. `key_id` sits inside `signature`, so it is not part of the signed bytes and it does not select a key. The trust anchor is the raw 32-byte public key `LICENCE_PUBLIC_KEY` in `mcp_glp_audit_proxy.licence` (`LICENCE_KEY_ID` is `mcp-glp-audit-proxy-licence`).

### LM1 text, RSA-2048 PSS

The file is three lines and it ends with a newline:

```text
LM1
<base64 of the JSON body>
<base64 of the RSA-PSS signature>
```

The body bytes are UTF-8 from `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. The signature is RSA 2048, PSS, MGF1 with SHA-256, salt length equal to the SHA-256 digest length, hash SHA-256, over those raw bytes. The loader verifies those bytes. It does not re-encode the JSON. The trust anchor is the PEM SubjectPublicKeyInfo `LICENCE_RSA_PUBLIC_PEM` in `mcp_glp_audit_proxy.licence`.

The object has these keys and no others. It has no `features` field.

| Key | Value |
|---|---|
| `app` | Must be `mcp-glp-audit-proxy` |
| `expires` | ISO date `YYYY-MM-DD`, or null. Null does not expire. A past date is `licence expired` |
| `fingerprint` | 64 lowercase hex characters. Same digest as the JSON shape |
| `holder` | Email address |
| `issued` | ISO date `YYYY-MM-DD` |
| `kind` | `trial`, `year`, or `perpetual`. The clock uses `expires`, not `kind` |
| `updates_until` | ISO date `YYYY-MM-DD`. Recorded and not checked yet |
| `version` | JSON number or string. Recorded and not checked yet |

```json
{
  "app": "mcp-glp-audit-proxy",
  "expires": "2027-01-01",
  "fingerprint": "<64 lowercase hex>",
  "holder": "qa@lab.example",
  "issued": "2026-01-01",
  "kind": "year",
  "updates_until": "2027-06-01",
  "version": 1
}
```

That object is the body before base64. The fingerprint above is a placeholder. It is not a signature this repository can verify.

When the fingerprint matches, LM1 enables the `licence_feature` of each installed licensed plugin in that set. It does not read a feature list from the file.

### Fingerprint

Both shapes use the same fingerprint. It is the lowercase SHA-256 hex of the RFC 8785 bytes of this JSON array:

```json
["<client_id>", "mcp-glp-audit-proxy", ["<sorted entry-point names>"]]
```

`client_id` is the config value. The app id is the fixed string `mcp-glp-audit-proxy`. The names are the installed entry-point names whose `licence_feature` is outside the Community set, sorted ascending. Community entry points (`jsonl`, `unsigned`, `json`, `text`, `env`) are not included. There is no machine id, hostname, or MAC address in the array.

Startup computes that digest from the config and from the entry points installed in this process. The licence `fingerprint` must be equal. A mismatch raises `LicenceError` (`licence fingerprint does not match`) and no feature from that file is enabled. The factory is not called. Adding or removing a licensed plugin changes the digest, so the previous licence is refused and a new one is required. A signed file also requires `client_id`. A file that lists only Community features, and has neither a signature nor a fingerprint, still loads without `client_id`.

`LICENCE_PUBLIC_KEY` and `LICENCE_RSA_PUBLIC_PEM` are test trust anchors. Replace both before issuing customer licences. The private keys are not in this repository.

`FeatureSet.load`:

- always enables Community features (`storage.jsonl`, `signer.unsigned`, `report.json`, `report.text`, `verify`, `policy.allowlist`, `approval.local`, `rbac.local`, `auth.env`) when the file is accepted
- for a JSON licence, enables any other listed feature only when the signature verifies, the fingerprint matches, and an installed factory declares that same `licence_feature`
- for an LM1 file, enables the `licence_feature` of each installed licensed plugin whose names produced the matching fingerprint
- records a JSON feature that no installed factory declares on `unavailable`, and the server prints that list to stderr
- refuses to start if config selects a plugin whose declared feature is not enabled; the factory is not called

Selecting a name that is not installed is an error, not a silent skip.
