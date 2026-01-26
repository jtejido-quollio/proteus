# Trust Anchors & Key Discovery v0

This document defines how consumers obtain keys required for verification.

## 1. Key types
- **Tenant signing keys**: verify manifest signatures (`signature.kid`)
- **Tenant log signing keys**: verify STH signatures

In v0, both keys may be represented by the same underlying key material per tenant, but the system MUST treat them as logically distinct.

## 2. Key discovery (v0)
The service MUST provide endpoints (Phase 1 implementation) for key discovery:

- `GET /v1/tenants/{tenant_id}/keys/signing`
- `GET /v1/tenants/{tenant_id}/keys/log`

Response includes:
- `kid`
- `alg` (ed25519)
- `public_key` (base64)
- `status` (active/retired/revoked)
- validity bounds (optional)

Consumers SHOULD cache keys for a bounded TTL (e.g., 15 minutes) and re-fetch on verification failures.

## 3. Rotation
- New keys are introduced as `active` while old keys move to `retired`.
- `retired` keys remain usable for verifying historical signatures until revoked or expired.
- Rotation events MUST be auditable (Phase 2+).

## 4. Revocation
- When a key is revoked, verification MUST fail with `KEY_REVOKED` for signatures using that `kid`.
- Receipts created before revocation remain verifiable as "historical inclusion," but signature trust is invalid at verification time (default behavior).
- Future enhancement: "verify-as-of-time" semantics (not in v0).

## 5. Distribution model (recommended)
For enterprise deployments:
- Keys may be provisioned out-of-band and pinned by consumers.
- Online discovery endpoints remain available for convenience but must support pinning policies.
