# PROTEUS

PROTEUS is a **standalone enterprise forensics platform** for proving
**what happened, when it happened, who/what produced it, and whether it was altered**.

It is designed for **post-incident proof**, disputes, audits, investigations, and regulatory scrutiny.

PROTEUS does not control execution.
PROTEUS does not enforce policy at runtime.
PROTEUS produces **cryptographic evidence** that survives adversarial review.

---

## What PROTEUS Solves

Modern systems — AI or otherwise — generate outputs that later become disputed:
- “Was this document altered?”
- “Did this model really produce this output?”
- “What inputs, tools, and versions were involved?”
- “Can a third party verify this without trusting our internal systems?”

Traditional logs are mutable.
Detection systems are probabilistic.
Dashboards are not evidence.

PROTEUS provides **forensics-grade proof**.

---

## Core Guarantees (Non-Negotiable)

- Deterministic verification (same inputs → same result)
- Tamper-evident recording (append-only, cryptographically verifiable)
- Portable, offline verification (no vendor dependency)
- Explicit key lifecycle and revocation
- Legal-grade chain of custody

---

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
