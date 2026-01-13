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
