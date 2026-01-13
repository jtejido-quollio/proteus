# Phase 1 Acceptance Criteria v0 (Testable)

These acceptance criteria must be met to claim Phase 1 completion.

## A. Canonicalization
1. Text canonicalization converts CRLF to LF deterministically.
2. JSON canonicalization is RFC 8785 compliant (JCS).
3. `sha256(canonical_bytes)` matches reference test vectors.

## B. Ed25519
1. Given a manifest canonical payload and keypair, signatures verify correctly.
2. Modified payload fails verification.
3. Base64 encoding/decoding is correct and round-trips.

## C. Per-tenant transparency log
1. Append N leaves and produce STH per append:
   - tree_size increments by 1
   - STH signature verifies against tenant log public key
2. Inclusion proofs validate for random leaves.
3. Consistency proofs validate between checkpoints.
4. Duplicate record does not create a new leaf; returns the original receipt.

## D. Revocation
1. If `kid` is revoked, `/verify` returns `KEY_REVOKED`.
2. Revocation cache invalidation is correct (no stale "active" results).

## E. Portable receipts
1. A receipt containing STH + inclusion proof can be verified offline
   (with access to the relevant public keys).

## Suggested artifacts
- Provide JSON test vectors for:
  - canonicalized manifest bytes (hex)
  - leaf hash (hex)
  - STH payload + signature
  - inclusion proof paths
