# Phase 0 Specification (Trust Infrastructure v0)

## 1. Purpose
This document defines the Phase 0 specifications for a **Trust Infrastructure** system that provides **cryptographic proofs** of:
- **Origin** (who attested/signed)
- **Integrity** (what content, unchanged)
- **Transparency** (tamper-evident append-only log)
- **Revocation awareness** (key trust state)

Phase 0 produces stable contracts (manifest schema, canonicalization rules, storage/log model, and API contract) to unblock Phase 1 implementation.

## 2. Non-Goals (Phase 0 / Phase 1)
Out-of-scope for Phase 0 and Phase 1:
- Deepfake detection / AI manipulation classification as a primary signal
- Watermarking as a guarantee of origin
- Full device attestation (TEE) (optional future module)
- Legal PDF generation (JSON evidence bundles first)
- Cross-tenant/global transparency log (start with per-tenant logs)

## 3. Definitions
- **Artifact**: content object whose integrity and origin are to be proven.
- **Canonicalization**: deterministic transformation into canonical bytes for hashing/signing.
- **Artifact Hash**: digest of canonical bytes; stable identity.
- **Manifest**: structured statement about an artifact (and optionally derivation inputs).
- **Signed Manifest Envelope**: manifest plus signature metadata.
- **Transparency Log**: append-only sequence of leaves, producing periodic Signed Tree Heads (STH).
- **STH (Signed Tree Head)**: signed summary of the log state.
- **Inclusion Proof**: Merkle proof that a leaf is included in a tree.
- **Consistency Proof**: Merkle proof that one tree is append-only extension of another.
- **Tenant**: isolated customer boundary; each tenant has its own keyspace and log.

## 4. Trust Model
### 4.1 Guarantees
Given a verification receipt produced by the system:
1. The manifest was signed by the private key corresponding to a known **public key** (`kid`).
2. The `subject.hash` matches the canonical artifact bytes (if artifact is available).
3. The signed manifest was appended to a **tamper-evident** log (inclusion + consistency proofs).
4. Key revocation status is checked during verification.

### 4.2 Non-guarantees
- The artifact is truthful, not manipulated, or not AI-generated (unless upstream provides attestations).
- Signer is “good” beyond the trust placed in keys and tenant policy.

## 5. Artifact Identity and Canonicalization (v0)
### 5.1 Supported media types
- `text/plain; charset=utf-8`
- `application/json`

### 5.2 Hashing algorithm
- `sha256` (lowercase hex output)

### 5.3 Canonicalization rules
#### Text
- UTF-8 bytes
- Normalize CRLF → LF
- No trimming
- Canonical bytes = normalized bytes

#### JSON
- MUST follow RFC 8785 (JCS)
- Canonical bytes = RFC 8785 serialization (UTF-8)

### 5.4 Artifact hash
`artifact_hash = sha256(canonical_bytes)`

## 6. Manifest Schema (v0)
### 6.1 Schema identifier
`schema` identifies the manifest schema identifier, e.g. `trust.manifest.v0`.

### 6.2 Normative fields
Manifest MUST include:
- `schema`, `manifest_id`, `tenant_id`
- `subject.type` = `artifact`
- `subject.media_type`
- `subject.hash.alg` = `sha256`
- `subject.hash.value` (lowercase hex)
- `actor` (type, id)
- `tool` (name, version)
- `time.created_at`, `time.submitted_at` (RFC3339)

Optional/reserved:
- `subject.size_bytes`, `subject.uri`
- `inputs[]` (for derivation; reserved for Phase 2)
- `claims{}` (model_id, tags, etc.)

### 6.3 Signed payload
Signed payload MUST be canonical JSON bytes (RFC 8785) of the `manifest` object *only*.

### 6.4 Envelope
Envelope includes:
- `manifest`
- `signature{alg,kid,value}`
- optional `cert_chain[]`

## 7. Cryptography (v0)
- Default signature algorithm: **Ed25519**
- `kid` is unique per tenant
- Revocation registry: `(tenant_id,kid,revoked_at,reason)`
- Verification MUST check revocation state

## 8. Transparency Log (per-tenant, v0)
- Append-only log per tenant
- Leaf hash derived deterministically from envelope
- Merkle tree produces STH: `(tree_size, root_hash, issued_at, sth_signature)`
- Must support inclusion + consistency proofs

## 9. Storage Model
- Postgres holds metadata: tenants, keys, revocations, manifests/envelopes, leaves, STHs
- Evidence store (artifact bytes) optional in Phase 1; hash-only is acceptable

## 10. API Contract (v0)
- `POST /v1/manifests:record`
- `POST /v1/manifests:verify`
- `GET /v1/logs/{tenant_id}/sth/latest`
- `GET /v1/logs/{tenant_id}/inclusion/{leaf_hash}`
- `GET /v1/logs/{tenant_id}/consistency?from={a}&to={b}`

Receipts MUST include inclusion proof by default for portable verification.

## 11. Threat Model (summary)
- Forged manifests → signature verification
- Replay → idempotency (Phase 1)
- DB tampering → transparency proofs + portable receipts
- Key compromise → rotation + revocation
- Log rewrite → STH + consistency proofs

## 12. Phase 0 Exit Criteria
Complete when canonicalization + manifest + log model + API contract + storage model + threat model are documented.
