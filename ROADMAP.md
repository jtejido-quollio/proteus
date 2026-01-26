# Guiding Principles

Your competitive edge is: cryptographic proof + tamper-evident logs + legal-grade evidence bundles.
All "AI detection" (deepfake, watermark, stylometry) is optional and should be layered after the cryptographic core is solid.

## Build Order

1. Evidence Capture & Signing
2. Immutable Recording
3. Verification API Surface
4. Reporting / Evidence Bundles
5. Policy / Decisioning
6. Forensics (optional) + Case Mgmt + Feedback

## Phase 0 - Product Definition and Constraints (1-2 weeks)

### Outcomes
- Tight scope: "We prove authenticity," not "we detect deepfakes."
- Choose 1-2 first-class artifact types: text + JSON (LLM outputs, documents).
- Optional early: images (heavier).
- Build artifacts (SBOMs, model cards, pipelines) are a good wedge.

### Decisions to Lock
- Canonical artifact ID = sha256(canonical_bytes) (define canonicalization for each artifact type).
- Manifest format (your own JSON schema initially; map to standards later).
- Signature scheme: Ed25519 (simple, fast) + optional ECDSA for compatibility.
- Log model: append-only Merkle log with signed tree heads (RFC 6962 / CT-style Merkle tree, no odd-leaf duplication).
- Evidence store: object storage (S3-compatible) + metadata DB (Postgres).
- Tenancy: hard multi-tenant from day one (even if minimal).

### Definition of Done
- Written spec for artifact types, canonicalization, manifest schema, trust model, and threat model.

## Phase 1 - MVP (6-10 weeks): "Proof of Origin + Integrity + Verification"

This is the minimum product that is useful, sellable, and defensible.

### 1A. Evidence Capture & Signing (Capture package)
- **Build**
- SDK: library + CLI.
- `capture(artifact) -> artifact_hash`.
- `build_manifest(inputs, outputs, tool, actor, timestamp, metadata)`.
- `sign(manifest) -> signature`.
- Signer: per-tenant keypairs or org keypairs.
- Support key rotation metadata (kid, validity).
- KMS integration (lite).
- Start with software keys + encrypted at rest.
- Optional AWS KMS/GCP KMS later.
- **Deliverables**
- CLI + SDK in one language (recommend Go + one of: TS/Python wrapper depending on target users).
- Manifest JSON schema.
- Signing + verification utilities.
- **DoD**
- Given an artifact, you can produce a signed manifest deterministically and verify the signature on another machine.

### 1B. Immutable Recording & Stores (Stores package)
- **Build**
- Evidence store: store artifact bytes (optional early) OR store only hashes + external pointers.
- Store redacted copies later.
- Transparency log (Merkle): append leaf = sha256(JCS({ manifest, signature{alg,kid,value} })).
- Periodically generate Signed Tree Head (STH) signed by the log key.
- Provide inclusion proof + consistency proof APIs.
- Timestamp service: MVP internal timestamping (server time) + signed receipts.
- Later: RFC3161 TSA or anchored witness model.
- Revocation registry: per-tenant key revocation (kid + reason + time).
- Cache: store verification results keyed by (manifest hash, sth).
- **Deliverables**
- Postgres schema: tenants, keys, manifests, entries, tree_heads, revocations.
- Object storage bucket layout (optional).
- Merkle log service with basic APIs.
- **DoD**
- You can append signed manifests, receive an inclusion proof, and later prove the log hasn't been rewritten (consistency proof).

### 1C. Trust API Surface (API package) - minimal
- **Build**
- Verification gateway.
- POST /v1/manifests:record (submit signed manifest + optional artifact pointer).
- POST /v1/manifests:verify (returns pass/fail + proofs).
- GET /v1/logs/{tenant_id}/inclusion/{leaf_hash} and /v1/logs/{tenant_id}/consistency.
- AuthZ: API keys per tenant (JWT later).
- Rate limiting (basic).
- **Deliverables**
- API + OpenAPI spec.
- Minimal tenant onboarding (create tenant, issue API key).
- **DoD**
- Any consumer can verify: signature validity, revocation status, inclusion proof, consistency proof.

### 1D. Report Builder (MVP)
- **Build**
- Generate a "Verification Receipt" JSON with signature verdict, key chain details, revocation status, inclusion proof + STH, timestamp.
- Basic human-readable HTML/PDF later; JSON is enough for MVP.
- **DoD**
- A verification receipt that can be attached to compliance/audit workflows.

### MVP Exit Criteria (Seed-relevant)
- You can credibly state: "We provide tamper-evident proof that content came from X and was not modified."
- You can credibly state: "Verification does not require trusting our database - proofs are portable."
- You support key rotation and revocation.

## Phase 2 - Beta (6-8 weeks): "Derivation + Policy + Decisioning"

Now you go from "proof of origin" to "proof of process."

### 2A. Provenance Graph
**Build**
Introduce a read-optimized provenance graph derived exclusively from verified manifests.
* Nodes:
    * Artifact (by artifact_hash)
    * Manifest (by manifest_id)
* Edges:
    * USED (manifest → input artifact)
    * GENERATED (manifest → output artifact)
    * SIGNED_BY (manifest → signer)
    * ATTESTED_BY (optional, future)
    
**APIs**
* ```GET /v1/lineage/{artifact_hash}```
* ```GET /v1/derivation/{manifest_id}```

**DoD**
* You can reconstruct a chain:
    ```
    output artifact
    → generating manifest
        → input artifacts
        → upstream manifests
    ```
* Traversal is deterministic and order-stable

### 2B. Derivation Verifier (Structural Integrity)
**Build**
Implement a pure derivation verifier that validates graph integrity, not policy.

Validation checks:
* All referenced input artifacts exist
* Artifact hashes match recorded values
* Manifest ordering is monotonic (no time paradox)
* Tool identity and version are present
* Signers in the chain are not revoked

**Output**
A deterministic result object:
```
{
"complete": true,
"depth": 3,
"failures": [],
"severity": "none"
}
```

**Rules**
* No heuristics
* No scoring
* No policy decisions

**DoD**
* Same derivation input always yields the same result
* Failures are explicit and enumerable

### 2C. Policy Engine (Embedded, Deterministic)
**Build**
* Embed Open Policy Agent (OPA) as a library, used in a constrained mode.
* OPA is responsible only for policy evaluation, not final decisions.

**Policy Model**

Policies evaluate a pre-verified input object, for example:
```
{
  "signature": { "valid": true, "revoked": false },
  "log": { "included": true, "consistent": true },
  "derivation": { "complete": true, "depth": 3 },
  "artifact": { "type": "json" },
  "signer": { "tenant": "acme", "kid": "key-1" }
}
```

OPA outputs structured policy results:
```
{
  "allow": true,
  "violations": []
}
```
**Constraints**
* Policies are:
    * Side-effect free
    * Versioned and hashed
    * Evaluated with no external IO
* Policy bundle hash is recorded in receipts

**DoD**
* Policy evaluation is deterministic
* Given the same input + policy bundle hash, any verifier can recompute the result

### 2D. Decision Engine (Authoritative Outcomes)
**Build**

Implement a Decision Engine in native code (not OPA).

Responsibilities:
* Combine:
    * Cryptographic verification results (strong)
    * Derivation verifier output (strong)
    * Policy engine verdicts (authoritative)
* Produce:
    * Risk score (0–100)
    * Action:
        * allow
        * label
        * require_review
        * block

**Rules**
* Decision logic is:
    * Explicit
    * Versioned
    * Deterministic
* No ML
* No probabilistic behavior

**Example**
```go
if !policy.Allow {
  action = BLOCK
} else if !derivation.Complete {
  action = REQUIRE_REVIEW
} else {
  action = ALLOW
}
```
**DoD**
* Same inputs → same action
* Decision explanation is traceable and human-readable

### 2E. Decision-Aware Verification Receipt (Beta)
**Build**

Extend the Phase 1 receipt to include:
* Derivation summary
* Policy bundle hash
* Policy evaluation result
* Final decision + score

Example additions:
```json
{
  "policy": {
    "bundle_hash": "sha256:...",
    "allow": true,
    "violations": []
  },
  "decision": {
    "score": 92,
    "action": "allow"
  }
}
```
**DoD**
* Receipt can be verified offline
* Third party can replay:
    * Proof verification
    * Derivation validation
    * Policy evaluation
    * Decision mapping

### Beta Exit Criteria
You can credibly state:
* “We prove how content was produced, not just who signed it.”
* “Decisions are deterministic, explainable, and replayable.”
* “Policies are enforceable without trusting the service runtime.”

At this point, you are no longer just a receipt issuer —
you are a trust enforcement platform.

## Phase 3 - Seed-Grade Product (8-12 weeks): "Enterprise Readiness + Evidence Bundles"

This is where procurement starts taking you seriously.

### 3A. Evidence Bundles (legal-grade)
- **Build**
- Export bundle format: manifest(s), signatures, key certificates/metadata, inclusion proofs + STHs, revocation statements, derivation graph slice, verification receipt.
- Output formats: JSON bundle (MVP), PDF "chain of custody report" (later).
- **DoD**
- A third party can verify the entire bundle offline.

### 3B. Key Management upgrades
- **Build**
- Real KMS/HSM integration (AWS KMS or Hashi Vault).
- Key rotation automation.
- Revocation propagation + cache invalidation.
- **DoD**
- Key compromise response workflow is documented and tested.

### 3C. Multi-tenant ops + Observability
- **Build**
- Telemetry: request latency, proof generation time, failure reasons.
- Audit logs for policy changes.
- SLOs and dashboards.
- **DoD**
- You can operate this as a service, not a demo.

### 3D. Witness model (optional but strong)
- **Build**
- Third-party witness service that co-signs STHs.
- Or integrate with a public anchoring service (store STH hash externally).
- **DoD**
- Makes tampering accusations significantly harder ("not even the vendor can rewrite history").

## Phase 4 - Full Platform (Ongoing): "Forensics + Case Management + Feedback"

Only do this once the cryptographic core is adopted.

### 4A. Forensics & Detection (optional modules)
- Watermark detector (if you can access model signals).
- Deepfake analysis (integrate vendors first).
- Similarity/theft detection (fingerprints + NN search).
- Note: these are inherently probabilistic; they must be supplementary to cryptographic proof.

### 4B. Case Management + Moderator workflows
- Review queue for require_review.
- Hold orders, escalations, audit trails.
- Feedback loop to tune scoring/policies.

#### Phase 4B.0 — Hard Constraints + Domain Model Lock (1–2 weeks)
**Outcomes**

* Canonical definitions:
  * Case, Evidence, Claim, Decision, Hold, Escalation, Queue, SLA, Assignment, AuditEvent
* Append-only event schema (human + system)
* Idempotency rules (no duplicate cases from repeated require_review)
* Multi-tenant boundaries and retention constraints
* RBAC / capabilities matrix for moderator/legal/compliance

**Definition of Done**

* `docs/v4b_spec.md` contains:
  * state machine
  * event types
  * invariants (“no mutation of evidence”, “all decisions are events”)
* OpenAPI v1 for Case API + Workflow API
* DB ERD + migrations plan
* Threat model: tamper, privilege escalation, data leakage, export abuse

##### Codex prompts (Phase 4B.0)
**Prompt 4B0-A — Spec + state machine**

Create docs/v4b_spec.md defining Case Management domain: entities, invariants, lifecycle state machine, required event types, and idempotency rules. Include explicit non-goals to avoid dashboard bloat. Provide OpenAPI endpoint list (no implementation yet).

**Prompt 4B0-B — DB schema + migrations**

Create Postgres schema for Phase 4B: cases, case_events (append-only), case_evidence_links, holds, escalations, assignments, queues, slas, exports, comments. Include tenant_id on all rows, indexes for queue views, and immutable event log. Generate migrations (golang-migrate or goose) and document ERD in Mermaid.

#### Phase 4B.1 — Case Service (Domain + API + Storage) (3–5 weeks)
**Outcomes**
* Case CRUD (enterprise-safe: create, read, list, search)
* Evidence linking (artifacts, receipts, derivation graphs, policy decisions)
* Append-only event API (every action writes events)
* Query views for queues, SLA status, ownership
* Strong validation + error codes

**Definition of Done**
* Go services + repositories + migrations
* Deterministic integration tests (DB in compose)
* Pagination, filtering, stable sorting
* Consistent error envelope + codes

##### Codex prompts (Phase 4B.1)

**Prompt 4B1-A — Case domain + repositories**

Implement Go domain models and repositories for Phase 4B tables. Enforce invariants: events append-only; case status derived from latest events; evidence links immutable once attached (unless “redact” event). Add idempotency keys for case creation.

**Prompt 4B1-B — Case API (Gin)**

Implement Gin HTTP API for cases:
* POST /v1/cases (idempotent)
* GET /v1/cases/:id
* GET /v1/cases (filters: tenant_id, status, queue_id, owner, severity, sla_state, time ranges)
* POST /v1/cases/:id/evidence (attach links to artifacts/receipts/derivation/policy decisions)
* GET /v1/cases/:id/events
  * Use consistent error codes, request validation, and RBAC checks.

**Prompt 4B1-C — Queue views + indexing**

Add endpoints for reviewer queue views:
* GET /v1/queues/:queue_id/cases
  * Implement DB indexes and query plans for high-cardinality tenants. Ensure pagination uses stable cursor (created_at + id). Add tests.

#### Phase 4B.2 — Workflow Service (Temporal Wrapper) (4–6 weeks)
**Outcomes**
* Temporal workflow per case:
  * routing → assignment → SLA timers → escalations → resolution
  * holds pause timers
  * reminders + breach events
* Workflow APIs to start/signal/query
* Deterministic workflows (replay-safe)

**Definition of Done**
* Temporal worker in Go
* Workflows + activities tested (unit + integration)
* SLA breach produces events + escalations
* “Hold” pauses SLA; “Unhold” resumes

##### Codex prompts (Phase 4B.2)

**Prompt 4B2-A — Temporal scaffolding**

Add a Workflow Service in Go wrapping Temporal. Create worker process, task queue setup, workflow registration, and config. Provide docker-compose additions for Temporal (or document local temporalite). Add health checks.

**Prompt 4B2-B — CaseWorkflow state machine**

Implement CaseWorkflow(tenant_id, case_id):
* on start: compute SLA deadlines from queue config
* wait for signals: Assign, Hold, Unhold, Escalate, Resolve, CommentAdded
* timers: reminder timer(s), SLA breach timer
* on breach: emit case_event sla.breached and signal escalation path

Ensure determinism (workflow.Now, no external IO).

**Prompt 4B2-C — Activities + idempotency**

Implement activities:
* EmitCaseEventActivity (writes to Case Service)
* NotifyActivity (stub for email/slack)
* TicketingActivity (stub/Jira-like)

Guarantee idempotency with workflow IDs and request IDs. Add tests for retries and duplicate signals.

#### Phase 4B.3 — Moderator UX (React + TypeScript) (4–7 weeks)
**Outcomes**
* Case queue UI (triage)
* Case detail UI (evidence timeline + decisions)
* Assignment / escalation / hold / resolve actions
* Comments + rationale
* Audit timeline rendering (human + system)
* “Evidence bundle” viewer (linked artifacts, receipts, derivation graph summaries)

**Definition of Done**
* Role-based UI controls
* Fast queue browsing (virtualized list)

Fully typed API client

E2E tests for key flows

##### Codex prompts (Phase 4B.3)

**Prompt 4B3-A — React app skeleton**

Create React + TypeScript app structure for Phase 4B: routes for QueueView, CaseDetail, CaseCreate, Exports. Use a component library (your choice) and a typed API client. Include auth token injection and tenant scoping.

**Prompt 4B3-B — QueueView (triage)**

Implement QueueView:
* filters (status, severity, owner, SLA state)
* sortable columns (created_at, deadline, severity)
* infinite scroll / cursor pagination
* “claim case” action (assign to me)

Include loading skeletons and error handling.

**Prompt 4B3-C — CaseDetail (evidence + timeline)**

Implement CaseDetail:
* timeline of events (append-only)
* evidence panel (artifacts/receipts/derivation/policy decisions)
* actions: assign, hold/unhold, escalate, resolve, add comment/rationale

Ensure actions produce new events and refresh timeline.

**Prompt 4B3-D — E2E tests**

Add Playwright/Cypress E2E tests:
* open queue
* claim case
* add comment
* place hold
* resolve

Verify timeline order and UI gating by role.

#### Phase 4B.4 — Enterprise Features (The “buyers pay for this”) (6–10 weeks)
**Outcomes**
* Legal/compliance-grade exports (evidence bundle, signed)
* Policy change audit linkage (“what policy was in effect when decision made”)
* Overrides with justification (append-only, dual-control optional)
* Escalation integrations (ticketing, email, webhook)
* Retention + redaction events (not delete; redact-with-event)
* Search + eDiscovery-ready queries (no BI dashboards)

**Definition of Done**
* Export bundle is reproducible, signed, and verifiable
* Policies are versioned; case events record policy version hashes
* Overrides require elevated capability and mandatory rationale
* Full audit export of a case: human + system evidence

##### Codex prompts (Phase 4B.4)

**Prompt 4B4-A — Evidence bundle export**

Implement export job:
* create export request for case_id
* generate bundle (JSON + attachments) with stable ordering
* include receipts, derivation graph snapshots, policy decisions, event timeline
* sign export manifest using Proteus signing key

Provide download endpoint with access control and audit event emission.

**Prompt 4B4-B — Policy version linkage**

Ensure every require_review decision and every case resolution event references:
* policy_bundle_id
* policy_bundle_hash
* evaluator version

Add API + UI to display “policy in effect at decision time”.

**Prompt 4B4-C — Overrides + dual control (optional flag)**

Add override decision type:
* requires capability cases:override
* mandatory justification + optional second approver
* records structured rationale and references evidence viewed

Never mutates past events; just appends.

**Prompt 4B4-D — Retention + redaction**

Implement retention settings per tenant and a redaction workflow:
* redaction creates event evidence.redacted
* evidence remains referenced but content access is denied/removed in exports

Add tests proving historical integrity remains (hash chain unaffected).

#### Phase 4B.5 — Production Hardening (ongoing / parallel)
**Outcomes**
* SSO + RBAC integration (OIDC groups → roles)
* Rate limiting, abuse prevention, audit integrity
* Observability: traces, metrics, workflow visibility
* Backups + disaster recovery
* Multi-region readiness (optional)

**Definition of Done**
* Load tests for queue listing + case detail
* Disaster recovery runbook
* Security review checklist complete

##### Codex prompts (Phase 4B.5)

**Prompt 4B5-A — Observability**

Add OpenTelemetry tracing across CaseSvc and WorkflowSvc. Include workflow correlation IDs. Add dashboards (basic): request latency, queue depth, SLA breach count, workflow failures.

**Prompt 4B5-B — Security hardening**

Implement strict RBAC capability checks for all case actions. Add audit events for auth failures and export access. Add tests for privilege boundaries.

**Prompt 4B5-C — DR + backups**

Add documentation + scripts for Postgres backup/restore and Temporal persistence backup strategy. Include runbook and verification steps.


#### “What NOT to build” (so you don’t become a bloated Trust Dashboard)

Keep these explicitly out of scope unless a paying customer demands it:
1. Analytics / BI dashboards (charts of “trust score”, trendlines, etc.)
2. ML retraining loops (you said it: not ML training)
3. Generic GRC platform (policy authoring suite, risk registers, vendor audits)
4. Case = ticket clone (don’t recreate Jira; integrate with it)
5. Infinite customization (custom fields / layouts per tenant → bloat)
6. Real-time collaboration suite (presence cursors, live co-edit)
7. Evidence mutation tools (editing receipts, altering proofs) — never

Your Phase 4B product is: resolve disputes with provable evidence + auditable human decisions.

#### Copy/paste “Codex Run Order” (fastest path)

4B0-A → 4B0-B

4B1-A → 4B1-B → 4B1-C

4B2-A → 4B2-B → 4B2-C

4B3-A → 4B3-B → 4B3-C → 4B3-D

4B4-A → 4B4-B → 4B4-C → 4B4-D

4B5-A → 4B5-B → 4B5-C