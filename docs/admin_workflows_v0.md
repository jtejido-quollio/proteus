# Admin Workflows v0 (Spec)

This document defines the minimal administrative workflows required to operate Phase 1.

## 1. Create Tenant
**Goal:** create an isolated tenant boundary.

Inputs:
- `name` (string, unique)

Outputs:
- `tenant_id` (uuid)

Operational notes:
- Tenant creation is audited (Phase 2+).
- Tenants own their signing keys and transparency log.

## 2. Register Tenant Signing Key
**Goal:** allow publishers to sign manifests and allow verifiers to validate them.

Inputs:
- `tenant_id`
- `kid` (string, unique per tenant)
- `alg` (ed25519)
- `public_key` (base64)

Outputs:
- key stored with `status=active`

Notes:
- In Phase 1, key registration can be admin-only.
- In Phase 3, key creation/rotation should occur via KMS/HSM.

## 3. Register Tenant Log Signing Key
**Goal:** allow verifiers to validate STH signatures.

Inputs:
- `tenant_id`
- `kid`
- `alg` (ed25519)
- `public_key` (base64)

Outputs:
- log key stored with `status=active`

Notes:
- For MVP you may reuse the tenant signing key material, but the API should treat them as distinct logical key sets.

## 4. Rotate Key
**Goal:** introduce a new active key and deprecate old keys.

Process:
1. Create new key as `active`
2. Mark old key as `retired`
3. Continue to allow verification with retired keys (historical signatures)

## 5. Revoke Key
**Goal:** invalidate a compromised key.

Inputs:
- `tenant_id`
- `kid`
- `revoked_at`
- `reason`

Effects:
- Key status becomes `revoked`
- `/verify` MUST return `KEY_REVOKED` for signatures using this `kid`
- Caches MUST be invalidated promptly

## 6. Minimal Endpoints (Phase 1)
These endpoints are required for Phase 1 operation:

- `POST /v1/tenants` (admin)
- `POST /v1/tenants/{tenant_id}/keys/signing` (admin)
- `POST /v1/tenants/{tenant_id}/keys/log` (admin)
- `POST /v1/tenants/{tenant_id}/keys/{kid}:revoke` (admin)
- `GET  /v1/tenants/{tenant_id}/keys/signing` (public/read)
- `GET  /v1/tenants/{tenant_id}/keys/log` (public/read)

AuthZ and RBAC are Phase 2+; Phase 1 can start with API-key guarded admin endpoints.
