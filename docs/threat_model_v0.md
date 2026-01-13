# Threat Model v0 (Draft)

## Threats
1. Forged manifests → mitigated by signature verification
2. Replay of manifests → mitigated by idempotency (Phase 1), log inclusion uniqueness
3. Database tampering → mitigated by transparency log proofs and externalized receipts
4. Key compromise → mitigated by revocation + rotation
5. Log rewrite attempt → mitigated by signed tree heads and consistency proofs

## Open items (Phase 1 decisions)
- Idempotency key: use `leaf_hash` uniqueness per tenant
- Receipt portability: include STH + inclusion proof by default
