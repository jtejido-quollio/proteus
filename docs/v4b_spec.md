# Phase 4B Case Management Spec (v0)

This document locks the Case Management domain model and hard constraints for Phase 4B.0.

## Scope
- Define canonical entities and invariants for case management and moderator workflows.
- Establish lifecycle state machine and required event types.
- Define idempotency rules, multi-tenant boundaries, and retention constraints.
- Provide OpenAPI v1 endpoint list (no implementation).

## Non-goals (avoid dashboard bloat)
- No detection, watermarking, or ML scoring logic in case workflows.
- No generic analytics dashboards beyond case-centric queue views.
- No free-form custom fields that bypass schema review.
- No deletion or mutation of evidence; redaction is an event, not a delete.
- No cross-tenant sharing of cases, evidence, or events.
- No custom workflow builder; workflows are fixed and audited.

## Canonical Definitions
### Case
A tenant-scoped review record created from a system trigger or human action.
Key fields: `case_id`, `tenant_id`, `source_type`, `source_ref`, `severity`, `queue_id`,
`owner`, `sla_state`, `status` (derived), `created_at`.

### Evidence
Immutable references that support a case decision.
Examples: artifact hashes, verification receipts, derivation graph snapshots, policy decisions.
Evidence is linked to cases and is never overwritten or deleted.

### Claim
A structured statement about evidence (human or system), recorded as an event payload.
Claims do not alter evidence; they add interpretation or context.

### Decision
The authoritative outcome for a case (allow, label, require_review, block).
Decisions are recorded as events and reference policy bundle hashes and rationale.

### Hold
A time-bound or indefinite pause that stops SLA timers.
Holds are recorded as events; active holds are derived state.

### Escalation
A routing action that moves a case to a higher queue or different reviewer group.
Escalations are recorded as events and capture from/to queue and reason.

### Queue
A work queue that defines routing and default SLA configuration.
Queues are per-tenant and are used for triage and assignment.

### SLA
Time expectations for a queue or case (warn and breach thresholds).
SLA timers are computed by the workflow service and logged as events.

### Assignment
The current reviewer or system agent responsible for a case.
Assignments are events; current assignment is derived state.

### AuditEvent
A system-wide append-only log entry (existing `audit_events`) that mirrors case actions
for compliance and traceability.

## Event Envelope (all case events)
Each case event must include:
`event_id`, `tenant_id`, `case_id`, `event_type`, `actor_type`, `actor_id`,
`request_id`, `created_at`, `payload`.

## Invariants
- `case_events` is append-only; no UPDATE or DELETE.
- Case status is derived from the latest relevant event.
- Evidence links are immutable once attached (redactions are separate events).
- Decisions are events, never direct state changes.
- All rows are tenant-scoped; no cross-tenant joins or references.
- Derived tables can be rebuilt from `case_events` for integrity checks.

## Lifecycle State Machine
```mermaid
stateDiagram-v2
  [*] --> QUEUED: case.created
  QUEUED --> ASSIGNED: case.assigned
  ASSIGNED --> IN_REVIEW: case.review_started
  IN_REVIEW --> ON_HOLD: case.hold_placed
  ON_HOLD --> IN_REVIEW: case.hold_released
  IN_REVIEW --> ESCALATED: case.escalated
  ESCALATED --> IN_REVIEW: case.deescalated
  IN_REVIEW --> RESOLVED: case.decided
  RESOLVED --> CLOSED: case.closed
  RESOLVED --> QUEUED: case.reopened
```
Notes:
- System can skip intermediate states (for example, create + assign).
- `case.decided` defines the authoritative decision and transitions to RESOLVED.
- `case.reopened` requires a reason and creates a new review cycle.

## Required Event Types
| event_type | actor | notes |
| --- | --- | --- |
| case.created | system/human | creates the case and initial queue |
| case.evidence_added | system/human | links immutable evidence reference |
| case.evidence_redacted | legal/system | records redaction without deleting link |
| case.comment_added | human | adds rationale or notes |
| case.assigned | human/system | assigns owner |
| case.unassigned | human/system | clears owner |
| case.review_started | human | starts active review |
| case.hold_placed | legal/human | pauses SLA timers |
| case.hold_released | legal/human | resumes SLA timers |
| case.escalated | human/system | routes to new queue |
| case.deescalated | human/system | returns to previous queue |
| case.decided | human | decision action + policy refs |
| case.reopened | human | reopens after new evidence |
| case.closed | system | final closure / retention state |
| case.sla.reminder | system | SLA reminder fired |
| case.sla.breached | system | SLA breach recorded |
| case.export_requested | human | export started |
| case.export_completed | system | export completed with hash |
| case.export_failed | system | export failure with error |

## Idempotency Rules
- Case creation requires an `idempotency_key` derived from
  `(tenant_id, source_type, source_ref)` or `(tenant_id, subject_hash)`.
- Duplicate create with the same `idempotency_key` returns the existing case.
- Event creation requires `request_id`; duplicates return existing event.
- Evidence linking is idempotent on `(tenant_id, case_id, evidence_type, evidence_ref)`.

## Multi-tenant Boundaries and Retention
- All entities include `tenant_id` and must be filtered by tenant in every query.
- Retention rules apply to derived views, not event or evidence logs.
- Evidence links are never deleted; redaction is an event with reason and actor.

## RBAC / Capability Matrix
| capability | moderator | supervisor | legal/compliance | auditor | system |
| --- | --- | --- | --- | --- | --- |
| view_case | yes | yes | yes | yes | yes |
| list_queue | yes | yes | yes | yes | yes |
| assign/unassign | yes | yes | no | no | yes |
| hold/unhold | no | yes | yes | no | yes |
| escalate/deescalate | no | yes | yes | no | yes |
| decide/resolve | yes | yes | yes | no | no |
| add_comment | yes | yes | yes | no | yes |
| export_evidence | no | yes | yes | yes | yes |

## OpenAPI v1 Endpoint List (Case API + Workflow API)
Case API:
- `POST /v1/cases` (idempotent create)
- `GET /v1/cases/{case_id}`
- `GET /v1/cases` (filters: tenant_id, status, queue_id, owner, severity, sla_state, time ranges)
- `GET /v1/cases/{case_id}/events`
- `POST /v1/cases/{case_id}/evidence`
- `POST /v1/cases/{case_id}/comments`
- `POST /v1/cases/{case_id}/assign`
- `POST /v1/cases/{case_id}/unassign`
- `POST /v1/cases/{case_id}/hold`
- `POST /v1/cases/{case_id}/unhold`
- `POST /v1/cases/{case_id}/escalate`
- `POST /v1/cases/{case_id}/deescalate`
- `POST /v1/cases/{case_id}/decide`
- `POST /v1/cases/{case_id}/reopen`
- `POST /v1/cases/{case_id}/exports`
- `GET /v1/exports/{export_id}`

Workflow API (Temporal wrapper):
- `POST /v1/workflows/cases/{case_id}:start`
- `POST /v1/workflows/cases/{case_id}:signal` (assign, hold, unhold, escalate, resolve)
- `GET /v1/workflows/cases/{case_id}`
- `POST /v1/workflows/cases/{case_id}:terminate`

## Threat Model (Phase 4B.0)
- Tamper: enforce append-only case_events and evidence links; optional event hash chain.
- Privilege escalation: strict RBAC checks on human actions and exports.
- Data leakage: tenant scoping on all queries; export access logged and audited.
- Export abuse: rate limits, capability checks, and append-only export events.

## ERD (Mermaid)
```mermaid
erDiagram
  tenants ||--o{ cases : owns
  tenants ||--o{ case_events : owns
  tenants ||--o{ case_evidence_links : owns
  tenants ||--o{ holds : owns
  tenants ||--o{ escalations : owns
  tenants ||--o{ assignments : owns
  tenants ||--o{ comments : owns
  tenants ||--o{ exports : owns
  tenants ||--o{ queues : owns
  tenants ||--o{ slas : owns

  slas ||--o{ queues : default
  queues ||--o{ cases : routes

  cases ||--o{ case_events : has
  cases ||--o{ case_evidence_links : has
  cases ||--o{ holds : has
  cases ||--o{ escalations : has
  cases ||--o{ assignments : has
  cases ||--o{ comments : has
  cases ||--o{ exports : has

  cases {
    UUID id PK
    UUID tenant_id FK
    TEXT status
    TEXT severity
    UUID queue_id FK
    UUID sla_id FK
    TIMESTAMPTZ created_at
  }
  case_events {
    UUID id PK
    UUID case_id FK
    TEXT event_type
    TIMESTAMPTZ created_at
  }
  case_evidence_links {
    UUID id PK
    UUID case_id FK
    TEXT evidence_type
    TEXT evidence_ref
  }
  holds {
    UUID id PK
    UUID case_id FK
    TEXT status
  }
  escalations {
    UUID id PK
    UUID case_id FK
    UUID to_queue_id FK
  }
  assignments {
    UUID id PK
    UUID case_id FK
    TEXT assignee_id
  }
  comments {
    UUID id PK
    UUID case_id FK
    TEXT body
  }
  exports {
    UUID id PK
    UUID case_id FK
    TEXT status
  }
  queues {
    UUID id PK
    UUID tenant_id FK
    TEXT name
  }
  slas {
    UUID id PK
    UUID tenant_id FK
    TEXT name
  }
```
