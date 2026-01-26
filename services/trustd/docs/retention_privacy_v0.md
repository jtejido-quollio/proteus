# Retention & Privacy v0

## 1. Default storage stance (v0)
- The system MUST store:
  - manifests (JSON)
  - signatures
  - transparency log leaves
  - STHs and proofs metadata
- The system MAY store artifact bytes, but in v0 it is acceptable to operate in **hash-only** mode.

## 2. Artifact bytes
If artifact bytes are stored:
- Store in object storage with tenant isolation.
- Allow deletion of artifact bytes while retaining:
  - subject hash
  - manifest
  - leaf + STH evidence

## 3. Retention
v0 recommends:
- manifests/log metadata retained for the contract duration
- artifact bytes retained per tenant policy (configurable later)

## 4. Tenant deletion
- Transparency evidence is append-only by design.
- If tenant deletion is required, the system should support:
  - deletion of artifact bytes
  - deletion/anonymization of PII fields in manifests (future)
  - retention of hashes/proofs as allowed by policy and law

A formal "right to be forgotten" policy is Phase 3+ work and must consider legal/audit obligations.
