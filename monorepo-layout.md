# Monorepo layout (Phase 4B)

## Repository tree (recommended)

```text
proteus/
  apps/
    web/                         # React + TypeScript (Moderator Console)
      src/
        app/
        pages/
        components/
        api/                     # typed client, query keys, hooks
        features/
          cases/
          queues/
          holds/
          escalations/
          evidence/
          audit/
          policies/
        auth/
        ui/
      package.json
      tsconfig.json
      vite.config.ts
  services/
    gateway/                     # API Gateway (authn/z, tenancy, rate limits, request IDs)
    trustd/                      # Core Trustd API (record/verify, log, provenance)
    case-service/                # Cases, queues, SLA, assignments, human actions
    orchestrator/                # Temporal worker (not a domain service)
    evidence-service/            # Derivation graphs + immutable receipts lookup
    policy-service/              # Policy bundles, versions, approvals, audits
    export-service/              # Evidence pack generation, signing, retention
    notification-service/        # optional (Phase 4C)
  api/                           # versioned OpenAPI specs
  infra/
    compose/
    k8s/
    terraform/
  docs/
    adr/
    architecture/
    runbooks/
    compliance/
  schemas/
    evidence-pack/               # regulator export schemas (included in this bundle)
  examples/
    evidence-pack/               # schema examples (included in this bundle)
  scripts/
```

## What NOT to build (anti-bloat guardrails)
- No generic “analytics dashboard”. Only case-centric metrics (SLA, queue health).
- No “data lake UI”. Evidence is referenced/packaged, not explored like BI.
- No ML retraining loop. Feedback is policy thresholds/guidelines only, all audited.
- No free-form “notes everywhere”. Notes are human events with templates + required fields.
