# Trust Infrastructure

This repository is a Phase 0 (spec-first) scaffold for a Trust Infrastructure:
**Authenticity, Provenance, and AI Forensics** via cryptographic proofs and a per-tenant transparency log.

## Stack
- Go
- Gin
- GORM
- Postgres

## What is included
- `/docs` Phase 0 specs (trust model, manifest schema, API contract, threat model)
- Clean Architecture layout: `domain` → `usecase` (ports) → `infra` (adapters)
- Postgres schema migration (`/migrations/0001_init.sql`)
- Minimal HTTP server with `/healthz`
- Phase 1 use-cases and HTTP handlers (compile-ready)

## Not included (by design)
- Actual signing / verification implementations
- Merkle tree log proofs and STH issuance
- AuthZ, rate limiting, and full API endpoints
- KMS/HSM integrations

## Run
### 1) Start Postgres (optional)
You can run the server without a database connection. If `POSTGRES_DSN` is not set, the server will start in "no-db" mode.

### 2) Run
```bash
go mod tidy
go run ./cmd/trustd
```

### Environment
- `HTTP_ADDR` (default `:8080`)
- `POSTGRES_DSN` (optional; if set, GORM will connect)
- `LOG_LEVEL` (default `info`)

## Next
Proceed with Phase 1 implementation:
- Implement canonicalization (text + RFC 8785 JCS for JSON)
- Implement Ed25519 signing/verification
- Implement per-tenant Merkle transparency log (leaves, STH, inclusion/consistency proofs)
- Implement record/verify/proof endpoints in `/internal/infra/http`

## Documentation
- Phase 0 spec (`docs/phase0_spec.md`)
- Crypto/encoding spec (`docs/crypto_encoding_v0.md`)
- Receipt semantics (`docs/receipt_semantics_v0.md`)
- Trust anchor model (`docs/trust_anchors_v0.md`)
- Error model (`docs/error_model_v0.md`)
- Retention & privacy stance (`docs/retention_privacy_v0.md`)
- Phase 1 acceptance criteria (`docs/phase1_acceptance_v0.md`)
- Operational envelope (`docs/ops_envelope_v0.md`)
