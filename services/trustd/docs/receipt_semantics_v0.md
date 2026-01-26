# Receipt Semantics v0 (Normative)

This document defines when a receipt is considered **portable** and what is returned by `/record`.

## 1. STH cadence (MVP)
For MVP, the system MUST operate in **STH-per-append** mode:

- Each successful `/v1/manifests:record` appends exactly one leaf.
- The system computes the new Merkle root and issues a new STH immediately.
- The returned receipt MUST include:
  - the STH that **includes** the new leaf
  - the inclusion proof for the leaf in that STH

This ensures receipts are portable and verifiable without waiting for batching.

## 2. Leaf index assignment
- `leaf_index` is assigned at append time and is monotonically increasing per tenant log.
- `leaf_index` MUST be returned in the `/record` response.

## 3. Record response requirements
`POST /v1/manifests:record` MUST return:
- `manifest_id`
- `leaf_hash`
- `leaf_index`
- `sth` (tree_size, root_hash, issued_at, signature)
- `inclusion_proof`

## 4. Duplicate records (idempotency)
If a client submits an envelope that produces a `leaf_hash` that already exists in the tenant log:
- The system SHOULD return `200 OK` with the previously assigned `leaf_index`, `sth`, and `inclusion_proof`
- The system MUST NOT append a second identical leaf for the same `(tenant_id, leaf_hash)`.

## 5. Verification receipts
`POST /v1/manifests:verify` MUST return:
- signature verdict
- key status + revocation checked time
- inclusion verdict
- STH + inclusion proof (unless explicitly requested otherwise; default is to include)

## 6. Replay inputs digest (optional helper)
For replay integrity, implementations MAY compute a deterministic `replay_inputs_digest`
over the **subset of fields consumed by policy/decision**. This is **not** a protocol requirement.

The digest is **not intended to attest to STH signature bytes**; it only binds deterministic
decision inputs. The full receipt remains the evidence bundle.

For v0, replay and policy evaluation are **time-independent**; no wall-clock inputs are allowed,
and `sth.issued_at` is excluded from the replay inputs digest.

Digest rules:
- Canonicalize the replay inputs payload using RFC 8785 (JCS).
- Compute `sha256` over the canonical bytes.
- Encode as lowercase hex.

See `docs/decision_replay_v0.md` for the normative replay inputs definition.

### Example (extended, additive)
Values are illustrative. Existing fields remain at the top level; optional sections may be present.

```json
{
  "signature_valid": true,
  "key_status": "active",
  "revocation_checked_at": "2025-01-01T00:00:00Z",
  "log_included": true,
  "subject_hash": {
    "alg": "sha256",
    "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "manifest_id": "manifest-123",
  "tenant_id": "tenant-123",
  "sth": {
    "tree_size": 4,
    "root_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "issued_at": "2025-01-01T00:00:00Z",
    "signature": "BASE64_STH_SIGNATURE"
  },
  "inclusion_proof": {
    "leaf_index": 2,
    "path": [
      "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    ],
    "sth_tree_size": 4,
    "sth_root_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "derivation": {
    "status": "not_evaluated"
  },
  "policy": {
    "engine": "opa",
    "decision": "allow",
    "bundle_id": "policy-2025-01-01"
  },
  "decision": {
    "score": 92,
    "action": "allow",
    "reasons": [
      "signature_valid",
      "log_proof_valid"
    ]
  },
  "replay": {
    "count": 1,
    "last_seen_at": "2025-01-01T00:00:00Z"
  }
}
```
