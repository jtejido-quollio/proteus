# Operational Envelope v0

## 1. Tenancy
- Logs are per-tenant for isolation.
- All queries are tenant-scoped.

## 2. Throughput targets (initial)
- `/record`: 50 RPS per tenant (initial)
- `/verify`: 200 RPS per tenant (initial)
These are guidance values to size caching and DB indices.

## 3. Latency SLO targets (initial)
- `/record` p95 < 250ms (STH-per-append; may require optimization later)
- `/verify` p95 < 100ms (cache-friendly)

## 4. Observability (Phase 1 minimum)
- request count, latency, error rates per endpoint
- key verification failures by code
- log append latency
- DB errors

## 5. Audit logging (Phase 2+)
- key creation/rotation/revocation events
- policy updates
- administrative access
