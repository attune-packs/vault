# HashiCorp Vault Pack for Attune

A production-oriented Vault pack translated from StackStorm Exchange's
`stackstorm-vault` `v2.1.0` at
`d9176cbfcf3e3038796907a120ddfb1befbd64ef`. Source and current API verification
details are pinned in `SOURCE_METADATA.json`.

## Security Model

- Bootstrap credentials live only in a **pack-owned, encrypted Attune Key**.
- Runtime verifies both `owner_type=pack`, `owner_pack_ref=vault`, and encryption.
- Tokens, AppRole secret IDs, KV values, plaintext, and signing inputs are never
  logged or included in error messages.
- Secret-producing reads write directly to a pack-owned encrypted Attune Key.
- Vault mutations are attempted once. There are no Vault mutation retries.
- Redirects are disabled so Vault headers cannot be forwarded to another host.
- TLS verification defaults on. Plain HTTP or disabled verification requires an
  explicit opt-in in the encrypted profile.
- Actions expose fixed operations only. There is no arbitrary endpoint action,
  root-token generation, unseal/init operation, or general dynamic-secret path.

**Attune persists action inputs and outputs as execution records.** Secret
parameters are marked `secret`, but ciphertext, key names, policy bodies, policy
names, paths, list results, signatures, lease metadata, and all other returned
metadata may still be retained according to the Attune deployment's execution
retention and access controls. Review those controls before production use.

## Bootstrap

Create one encrypted profile key owned by this pack. Avoid placing the command
in shell history in production; use your platform's protected provisioning
mechanism or the Attune API over TLS.

Token profile:

```bash
attune key create -e \
  --owner-type pack --owner-pack-ref vault \
  --ref vault_credentials --name "Vault production credentials" \
  --value '{
    "url":"https://vault.example.com:8200",
    "namespace":"admin/team-a",
    "auth_method":"token",
    "token":"hvs.REDACTED",
    "verify":true,
    "ca_cert":"/etc/attune/vault/ca.pem",
    "client_cert":"/etc/attune/vault/client.pem",
    "client_key":"/etc/attune/vault/client-key.pem"
  }'
```

AppRole profile:

```json
{
  "url": "https://vault.example.com:8200",
  "namespace": "admin/team-a",
  "auth_method": "approle",
  "auth_mount": "approle-attune",
  "role_id": "ROLE-ID",
  "secret_id": "SECRET-ID",
  "verify": true
}
```

Supported profile fields:

| Field | Meaning |
|---|---|
| `url` | Vault origin only; URL paths, userinfo, query, and fragment are rejected |
| `namespace` | Optional Enterprise/HCP namespace sent only as `X-Vault-Namespace` |
| `auth_method` | `token` or `approle` |
| `token` | Bootstrap token for token auth |
| `role_id`, `secret_id`, `auth_mount` | AppRole bootstrap material and mount |
| `verify` | TLS verification, default `true` |
| `ca_cert` | Worker-local custom CA bundle path; takes precedence over `verify` |
| `client_cert`, `client_key` | Worker-local mTLS pair; both are required together |
| `allow_http` | Must be exactly `true` to permit HTTP |
| `insecure_skip_verify` | Must be exactly `true` alongside `verify:false` |

Namespace and mount paths are deliberately separate. Every mount/path action is
relative to the profile namespace. Do not prefix action mounts or paths with the
namespace; doing so can target a different location than intended.

## Actions

| Action | Behavior |
|---|---|
| `vault.health` | Root-namespace initialization, seal, standby, version, and HTTP status (`healthy` distinguishes cluster state from request success) |
| `vault.token_lookup_self` | Minimal current-token metadata; accessor omitted |
| `vault.token_renew_self` | Bounded requested increment |
| `vault.token_revoke_self` | Revoke bootstrap token and children |
| `vault.approle_login` | AppRole token/wrapping token directly to Attune Key |
| `vault.kv_read` | KV v1/v2 values directly to Attune Key |
| `vault.kv_write` | KV v1/v2 write, optional v2 CAS |
| `vault.kv_patch` | Native KV v2 merge patch with mandatory CAS |
| `vault.kv_delete` | Permanent v1 delete or soft v2 delete |
| `vault.kv_undelete` | Restore v2 versions |
| `vault.kv_destroy` | Permanently destroy selected v2 versions |
| `vault.kv_list` | List v1/v2 names; names are not ACL-filtered by Vault |
| `vault.kv_metadata` | v2 lifecycle metadata, excluding custom metadata |
| `vault.policy_list/read/write/delete` | ACL policy management |
| `vault.token_create` | Bounded non-root child token directly to Attune Key |
| `vault.transit_encrypt` | UTF-8 plaintext to Vault ciphertext |
| `vault.transit_decrypt` | Plaintext directly to Attune Key |
| `vault.transit_sign/verify` | Existing-key UTF-8 sign/verify operations |

KV v1 has no undelete, destroy, metadata, or concurrency-safe patch operation.
Those actions reject `kv_version=1`. KV v1 delete is permanent. KV v2 uses the
required `data/`, `metadata/`, `delete/`, `undelete/`, and `destroy/` API paths
through hvac 2.4.0 or the native PATCH call.

Transit actions support only existing, non-derived keys. Encrypt additionally
requires `update` on the exact encrypt path and rejects callers that also have
`create`, `sudo`, or `root` there, preventing Vault's implicit key creation.
This keeps key type, derivation, exportability, and rotation under separate
administrative control. Dynamic secret generation is omitted because a generic mount/path
contract would amount to unsafe arbitrary endpoint dispatch and secret schemas
vary by engine.

## Confirmations

Confirmation strings are case-sensitive and include the normalized target:

```text
REVOKE SELF
DELETE KV V1: secret/apps/payments
DESTROY KV VERSIONS: secret/apps/payments#2,4
WRITE POLICY: app-reader
DELETE POLICY: app-reader
CREATE TOKEN: app-reader,default
```

`vault.token_create` requires explicit policies, lowercases/sorts them for the
confirmation, rejects `root`, sets both `ttl` and `explicit_max_ttl`, and caps
them at 86,400 seconds. It cannot request orphan, periodic, custom-ID, or root
tokens. A token role is intentionally not accepted because role settings can
override caller-supplied TTL and policy bounds.

## Response Wrapping

`vault.approle_login` and `vault.token_create` accept `wrap_ttl_seconds` from 1
to 3,600. When set, only the single-use wrapping token is written to the output
Attune Key. The action does not unwrap it. Wrapping does not make Attune Key
access unimportant: anyone who obtains the wrapping token before use may unwrap
it, and the wrapping token expires independently of Attune retention.

## Compatibility

The implementation pins `hvac==2.4.0`, the current hvac release verified on
2026-08-15. It was reviewed against Vault's current v1 HTTP API and Vault
`v2.0.4`. The Vault HTTP API remains `/v1/` even for Vault 2.x. hvac 2.4.0's
AppRole login has no `wrap_ttl` argument, so the wrapped AppRole action uses its
documented adapter header support for that fixed endpoint. Native KV v2 PATCH is
used because hvac's `KvV2.patch()` performs a read/merge/CAS write.

## Development

Tests are deterministic and use fake clients; they require no Vault server or
Attune API.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-test.txt
.venv/bin/pytest -q
attune pack check /home/david/Codebase/attune-packs/vault
attune pack test /home/david/Codebase/attune-packs/vault
```

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.
