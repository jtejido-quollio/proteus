# Key Management & Rotation v0 (Phase 3)

This document defines enterprise key custody and rotation for Proteus.

## 1. Goals (v0-compatible)
- Preserve Ed25519 signatures, wire formats, and canonicalization rules.
- Keep verification fully offline and deterministic.
- Support per-tenant key rotation with ACTIVE → RETIRED transitions.

## 2. Key purposes
Proteus uses distinct key purposes:
- `signing`: manifest signatures
- `log`: STH signatures

Keys are tenant-scoped and environment-scoped.

## 3. Vault storage (KV v2)
Vault path format:

```
secret/data/proteus/{env}/tenants/{tenant_id}/keys/{purpose}/{kid}
```

Stored JSON fields:
- `alg` (must be `Ed25519`)
- `kid`
- `private_key_base64` (raw ed25519 private key bytes; 32-byte seed or 64-byte key)
- `public_key_base64` (raw ed25519 public key bytes)
- `status` (`ACTIVE` | `RETIRED` | `REVOKED`)
- `created_at` (RFC3339, optional)

Environment variables:
- `VAULT_ADDR`
- `VAULT_TOKEN`
- `PROTEUS_ENV` (dev/stage/prod)

## 4. Rotation semantics (two-phase)
Rotation is a two-step state change:
1) Create a new key with `status=ACTIVE`.
2) Mark the previous ACTIVE key as `RETIRED`.

`REVOKED` is reserved for compromise and is only set via admin revoke.

## 5. Rotation schedule
Rotation decisions are based on key age.
Default interval is controlled by:
- `KEY_ROTATION_DAYS` (default `90`)

No wall-clock values are used in verification or replay.

## 6. Admin rotation endpoint
Trigger rotation per tenant and purpose:

```
POST /v1/tenants/{tenant_id}/keys/{purpose}:rotate
```

Requires `X-Admin-Key` and returns the new `kid`.

## 7. Verification & compatibility
- Old receipts remain verifiable as long as keys are not revoked.
- `retired` keys are valid for verification.
- Revoked keys MUST produce `KEY_REVOKED` on verification.
