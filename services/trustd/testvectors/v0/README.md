# Test Vectors v0

These test vectors are deterministic and intended to validate:
- RFC 8785-style canonicalization used for signing payloads (controlled JSON, no floats)
- Ed25519 signing/verification
- Leaf hashing (sha256 over JCS leaf object)
- Merkle root and inclusion/consistency proofs (RFC 6962 / CT-style, using node_hash = sha256(0x01||L||R))

Notes:
- These vectors intentionally avoid floats to bypass number-normalization variability.
- Merkle tree follows RFC 6962 tree hashing (split at largest power of two < n), with no odd-node duplication.
- See `docs/crypto_encoding_v0.md` for the canonical encoding and hashing rules.
