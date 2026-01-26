# Policy Input v0 (Normative)

This document defines the deterministic input schema for OPA policy evaluation.

## 1. Determinism rules
- Input MUST be fully deterministic.
- No timestamps unless provided by the envelope or receipt.
- No network, no DB, no randomness, no wall-clock time.

For v0, policy evaluation is **time-independent**. Policies MUST NOT depend on
`sth.issued_at` or any other wall-clock value.

## 2. JSON schema (conceptual)
```json
{
  "envelope": {
    "manifest": { "...": "..." },
    "signature": { "alg": "ed25519", "kid": "string", "value": "base64" },
    "cert_chain": ["optional"]
  },
  "verification": {
    "signature_valid": true,
    "key_status": "active|revoked|retired|unknown",
    "log_included": true,
    "artifact_hash_valid": true
  },
  "options": {
    "require_proof": false
  },
  "derivation": { "...": "..." }
}
```

Notes:
- `envelope.manifest` is the canonical manifest object.
- `verification.artifact_hash_valid` MUST be omitted if artifact bytes were not provided.
- `options` and `derivation` are optional.
