# PROTEUS
## Forensics, Provenance, and Verifiable Evidence for Digital & AI Systems
### Pre-Seed / Board-Ready Whitepaper (2026)

---

> **Positioning**
>
> PROTEUS is not an AI detector.
> PROTEUS is not a monitoring dashboard.
>
> **PROTEUS is post-incident truth infrastructure** — a cryptographic system of record for disputes, audits, and regulatory scrutiny involving digital and AI-generated artifacts.

---

## 1. Executive Summary

Modern enterprises increasingly depend on digital and AI-generated artifacts that carry **legal, financial, and reputational consequences**:

- AI-generated reports used in regulated decisions  
- Automated content published at scale  
- Machine-produced records used in compliance, finance, or safety contexts  

When disputes arise, organizations must answer questions that **traditional logging, monitoring, and AI detection tools cannot reliably answer**:

- *What exactly was produced?*
- *Who or what produced it?*
- *Was it altered?*
- *What policies were in effect at the time?*
- *Can this be proven to a third party — offline, without trusting the vendor?*

**PROTEUS exists to answer these questions deterministically.**

It provides:
- Cryptographic proof of authenticity and integrity  
- Tamper-evident timelines  
- Replayable, offline-verifiable evidence bundles  
- Human decision audit trails suitable for courts and regulators  

This whitepaper describes the **technical, architectural, and product vision** for PROTEUS as a foundational enterprise trust platform.

---

## 2. The Enterprise Forensics Gap

### 2.1 Why Existing Systems Fail

Most enterprises rely on:
- Application logs
- SIEMs and monitoring dashboards
- AI classifiers (deepfake detection, watermarking, anomaly scoring)

These systems fail under **adversarial or legal scrutiny**:

| Tool | Failure Mode |
|----|----|
| Logs | Mutable, selectively retained, operator-controlled |
| Dashboards | Require trust in vendor/operator |
| AI Detectors | Probabilistic, contestable, non-deterministic |
| Screenshots | Non-verifiable, chain of custody unclear |

In audits or court proceedings, these tools provide **context**, not **proof**.

### 2.2 The Legal Standard Problem

Courts, regulators, and compliance bodies require:
- Deterministic verification
- Immutable timelines
- Clear chain of custody
- Reproducible results

**PROTEUS is designed to meet these standards by construction.**

### 2.3 Real-World Use Cases

**Use Case 1: Financial Services - AI Credit Decisions**

A regional bank uses AI to evaluate mortgage applications. Six months after a rejection, an applicant sues, claiming age discrimination. The bank must prove:
- The exact AI model version used
- The specific data inputs considered
- That the decision followed approved policies
- That no human operator tampered with the output

*Without PROTEUS:* Application logs are mutable, policy versions unclear, no cryptographic proof of integrity.

*With PROTEUS:* Complete evidence bundle with signed manifests, policy snapshots, inclusion proofs, and human audit trail—verifiable offline by plaintiff's expert.

**Use Case 2: Healthcare - AI Diagnostic Support**

A hospital's AI system recommends a treatment plan. A year later, during a malpractice case, the plaintiff claims the AI was malfunctioning at the time. The hospital must prove:
- The AI output was not altered post-facto
- The clinician reviewed and approved the recommendation
- The system was operating within validated parameters
- All data inputs were properly sanitized

*Without PROTEUS:* EHR logs are vendor-controlled, no proof system wasn't altered, expert testimony becomes "he said, she said."

*With PROTEUS:* Tamper-evident record with cryptographic signatures, physician approval timestamps, policy compliance verification—admissible as evidence.

**Use Case 3: Media & Journalism - Content Authenticity**

A news organization publishes an AI-assisted investigative report. Months later, subjects of the report claim quotes were fabricated by AI. The publisher must prove:
- Which portions were AI-generated vs human-written
- Source materials the AI referenced
- Editorial oversight and fact-checking occurred
- No post-publication alteration of records

*Without PROTEUS:* CMS logs are editable, version control doesn't prove AI vs human authorship, no chain of custody for source materials.

*With PROTEUS:* Complete provenance graph showing AI inputs/outputs, human edits, source attribution, editorial approvals—cryptographically verifiable.

### 2.4 Concrete Financial Impact

Based on recent AI liability cases:

- **iTutorGroup (2023):** Settled EEOC age discrimination lawsuit for **$365,000** due to AI hiring tool biases[^1]
- **SafeRent (2024):** Paid **$2+ million** to settle housing discrimination claims from AI screening algorithm[^2]
- **Workday (2024-ongoing):** Facing class action potentially affecting **millions of applicants**, certified as collective ADEA claim in May 2025[^3]

The pattern is clear: **AI discrimination lawsuits are accelerating, settlements are substantial, and enterprises lack tools to defend themselves with deterministic evidence.**

[^1]: Sullivan & Cromwell LLP, "EEOC Settles First AI-Discrimination Lawsuit," August 2023
[^2]: Quinn Emanuel, "When Machines Discriminate: The Rise of AI Bias Lawsuits," August 2025  
[^3]: Fisher Phillips, "Discrimination Lawsuit Over Workday's AI Hiring Tools Can Proceed as Class Action," May 2025

### 2.5 The Triggering Events

**Regulatory Forcing Functions**

The **EU AI Act**, which entered into force in August 2024, creates mandatory evidence requirements:

**Article 12 (Record-Keeping):**[^4]
> "High-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system."

**Article 19 (Automatically Generated Logs):**[^5]
> "Providers of high-risk AI systems shall keep the logs referred to in Article 12(1), automatically generated by their high-risk AI systems... for a period appropriate to the intended purpose of the high-risk AI system, of at least six months."

Key requirements include:
- Recording period of each use (start/end timestamps)
- Reference databases checked
- Input data that led to matches
- Identification of humans verifying results

**Timeline pressures:**
- **August 2026:** Obligations for high-risk AI systems begin
- **August 2027:** Full compliance required for most provisions

**The gap:** Current logging systems don't provide **deterministic, offline-verifiable, tamper-evident records** that meet legal standards. Regulators will demand proof, not just logs.

[^4]: EU AI Act Article 12, Regulation (EU) 2024/1689
[^5]: EU AI Act Article 19, Regulation (EU) 2024/1689

**Litigation Precedents**

Recent court decisions establish that:

1. **AI vendors can be held directly liable** as "agents" of employers (*Mobley v. Workday*, July 2024)[^6]
2. **Disparate impact claims survive** even when discrimination is unintentional (*SafeRent settlement*, 2024)
3. **Courts are certifying class actions** for AI discrimination, potentially affecting millions (Workday collective action, May 2025)

**The panic-buying moment:** The first **$100M+ AI liability settlement** will trigger enterprise-wide procurement of forensic evidence tools. Organizations will realize traditional logs are insufficient for legal defense.

[^6]: Seyfarth Shaw LLP, "Mobley v. Workday: Court Holds AI Service Providers Could Be Directly Liable," July 2024

**Industry-Specific Drivers**

- **Financial Services:** SOX compliance + AI model governance = need for deterministic audit trails
- **Healthcare:** FDA regulated AI systems require validated, tamper-evident logs
- **Government:** Federal AI executive orders mandate transparency and accountability
- **Insurance:** Cyber insurance policies will soon require AI audit capabilities

---

## 3. Core Philosophy

> **Evidence must be verifiable without trusting the system that produced it.**

This principle drives every architectural decision:
- Append-only transparency logs
- Signed manifests instead of opaque events
- Inclusion and consistency proofs instead of dashboards
- Offline verification instead of vendor portals

PROTEUS treats **cryptography as the source of truth**, not infrastructure.

---

## 4. Non-Negotiable Guarantees

1. **Tamper-Evident Recording**  
   All evidence is recorded in append-only Merkle logs. Any rewrite attempt is detectable.

2. **Deterministic Verification**  
   Given the same inputs, verification always yields the same result.

3. **Portable Evidence**  
   Evidence bundles can be verified offline without PROTEUS availability.

4. **Explicit Identity & Key Lifecycle**  
   Key issuance, rotation, and revocation are provable and auditable.

5. **Legal-Grade Chain of Custody**  
   Evidence is suitable for audits, arbitration, and litigation.

---

## 5. What PROTEUS Is — and Is Not

### 5.1 What PROTEUS Is

- A cryptographic evidence system
- A provenance and derivation verifier
- A decision accountability platform
- A case-based human review system

### 5.2 What PROTEUS Is Not

- An AI detector
- A generic GRC platform
- A ticketing system clone
- A BI or analytics dashboard

This discipline is **critical to defensibility**.

---

## 6. System Architecture Overview

PROTEUS is composed of five foundational layers:

```
┌─────────────────────────────────────────────────────┐
│  Case Management & Human Audit Trails              │
│  (Review queues, decisions, holds, rationales)     │
└─────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│  Provenance & Policy Decisioning                    │
│  (Derivation graphs, policy engine, risk scoring)  │
└─────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│  Verification & Proof APIs                          │
│  (Inclusion proofs, consistency proofs, receipts)  │
└─────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│  Immutable Recording (Transparency Logs)            │
│  (Merkle tree, signed tree heads, append-only)     │
└─────────────────────────────────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────────┐
│  Evidence Capture & Signing                         │
│  (Artifact hashing, manifest creation, signatures) │
└─────────────────────────────────────────────────────┘
```

Each layer is independently verifiable. Full architecture diagram provided in Appendix B.

---

## 7. Evidence Lifecycle (High Level)

1. Artifact is produced
2. Canonicalized and hashed
3. Signed into a manifest
4. Recorded in an append-only log
5. Verified via cryptographic proofs
6. Optionally escalated into a Case
7. Reviewed, decided, exported

---

## 8. Transparency Logs & Cryptographic Proofs

PROTEUS uses **Certificate Transparency-style Merkle logs**:

- Each entry is a signed manifest
- Logs produce Signed Tree Heads (STHs)
- Inclusion and consistency proofs are provided

This ensures:
- No silent deletion
- No history rewrite
- Public or private verifiability

---

## 9. Provenance & Derivation

PROTEUS reconstructs **how artifacts were produced**, not just who signed them.

- Input artifacts
- Tools and versions
- Intermediate outputs
- Final outputs

Derivation graphs are:
- Deterministic
- Replayable
- Verifiable

---

## 10. Policy & Decisioning

Policies are:
- Deterministic
- Versioned
- Hash-identified
- Side-effect free

Decisions are:
- Explicit
- Replayable
- Explainable
- Recorded as evidence

---

## 11. From Decisions to Cases

When systems emit:

```
decision = require_review
```

PROTEUS creates a **Case**, not a log entry.

A Case bundles:
- Evidence
- Proofs
- Policies
- Human decisions
- Timelines

---

## 12. Case Management (Phase 4)

Cases support:
- Review queues
- SLAs
- Holds
- Escalations
- Overrides
- Resolution states

Everything is append-only.

---

## 13. Human Audit Trails

Human actions are first-class evidence:
- Who acted
- When
- Why
- Under what authority

These logs are what courts and regulators actually read.

---

## 14. Evidence Bundles

Exports include:
- Manifests
- Proofs
- Policies
- Decisions
- Human actions

Bundles are:
- Deterministic
- Signed
- Offline verifiable

**See Appendix A for sample evidence bundle structure.**

---

## 15. Security & Threat Model

Threats addressed:
- Insider tampering
- Vendor compromise
- Log deletion
- Policy rewriting
- Evidence forgery

Threats explicitly *not* solved:
- Real-time prevention
- Probabilistic authenticity scoring

---

## 16. Business Model & Buyers

### 16.1 Primary Buyers

- Regulated enterprises (finance, healthcare, government)
- AI-heavy organizations (tech, SaaS, platforms)
- Platforms exposed to disputes (marketplaces, content platforms)

### 16.2 What They Pay For

- Risk reduction
- Audit survival
- Legal defensibility
- Regulatory compliance

### 16.3 Pricing Philosophy

**Pricing Model:** Usage-based + enterprise base fee

- **Starter Tier (SMB):** $5,000/year base + $0.10 per artifact recorded
  - Up to 50,000 artifacts/year
  - Standard support
  - 1-year retention
  
- **Professional (Mid-Market):** $25,000/year base + $0.05 per artifact
  - Up to 500,000 artifacts/year
  - Priority support
  - 3-year retention
  - SSO/SAML
  
- **Enterprise:** Custom pricing (typically $100K-$500K/year)
  - Unlimited artifacts or volume-based
  - White-glove support
  - 7+ year retention
  - On-premise deployment option
  - Custom SLAs
  - Dedicated customer success

**Unit Economics:**
- Cost per artifact recorded: ~$0.02 (storage + compute)
- Gross margin target: 80%+
- Average contract value (Year 1): $75K

### 16.4 Initial Wedge Customers

**Phase 1 (Months 1-12): Financial Services (SOX + AI)**

Target: Regional banks, fintech companies, investment firms using AI for:
- Credit decisioning
- Fraud detection
- Trading algorithms
- Compliance automation

*Why they buy first:*
- Already required to maintain audit trails (SOX, FINRA, SEC)
- AI introduces new liability exposure
- Regulatory scrutiny is immediate
- Budget exists for compliance tooling

*Entry point:* "SOX compliance for AI systems"

*Typical deal:* $150K-$300K/year for 5-10 high-risk AI systems

**Phase 2 (Months 13-24): Healthcare (FDA-Regulated AI)**

Target: Hospital systems, medical device makers, pharma using AI for:
- Diagnostic support
- Clinical decision support
- Drug discovery
- Medical imaging analysis

*Why they're next:*
- FDA regulations for AI/ML medical devices require validation
- Malpractice liability demands proof of proper AI use
- HIPAA + AI = complex compliance requirements
- High consequences for errors

*Entry point:* "FDA validation evidence for AI medical devices"

*Typical deal:* $200K-$500K/year for clinical AI systems

**Phase 3 (Months 25-36): Platforms & Media (Content Authenticity)**

Target: Social platforms, news organizations, content marketplaces
- AI-generated content at scale
- User-generated + AI-augmented content
- Attribution and copyright concerns
- Deepfake/misinformation liability

*Why they're third:*
- Litigation risk is growing but not yet catastrophic
- Reputation management drives need
- Advertising revenue depends on trust
- Platform liability shield may not cover AI

*Entry point:* "Provenance for AI-generated content"

*Typical deal:* $100K-$1M/year depending on scale

**Phase 4 (Months 37+): Horizontal Expansion**

- Government agencies (AI accountability)
- Manufacturing (AI quality control)
- Legal services (e-discovery for AI artifacts)
- Insurance (claims automation)

---

## 17. Competitive Moat

PROTEUS is defensible because:
- Cryptographic guarantees are hard to fake
- Determinism resists legal challenge
- Evidence portability breaks vendor lock-in accusations
- Discipline avoids feature bloat

### 17.1 Competitive Landscape

**Direct Competitors (Emerging Category):**

*Reality Check:* No established category leader yet. Market is forming.

**Adjacent Technologies (Not Direct Competitors):**

**Sigstore (Open Source Software Supply Chain)**[^7]
- *What it does:* Code signing, transparency logs (Rekor), certificate authority (Fulcio)
- *How PROTEUS differs:*
  - Sigstore solves **signing**, not **provenance graphs** of multi-step AI workflows
  - Sigstore doesn't track **human decisions** or **policy compliance**
  - PROTEUS adds **legal-grade chain of custody** + **case management**
  - Sigstore is for software artifacts; PROTEUS handles **any digital artifact + AI outputs**

**Chainguard (Software Supply Chain Security)**
- *What it does:* Secure base images, SBOM generation, vulnerability scanning
- *How PROTEUS differs:*
  - Chainguard focuses on **container security**, not AI evidence
  - No case management or human audit trails
  - Not designed for legal/regulatory compliance use cases

**Blockchain Timestamping Services (e.g., OpenTimestamps)**
- *What they do:* Cryptographic timestamping via Bitcoin/Ethereum
- *How PROTEUS differs:*
  - Blockchain only provides **timestamps**, not provenance, policies, or decisions
  - No derivation graphs or case management
  - PROTEUS is enterprise-deployable (not dependent on public blockchains)
  - Offers deterministic verification without blockchain transaction costs

**Traditional GRC Platforms (e.g., ServiceNow, LogicGate)**
- *What they do:* Risk management, policy management, compliance workflows
- *How PROTEUS differs:*
  - GRC tools lack **cryptographic guarantees**
  - Evidence is mutable in traditional GRC systems
  - PROTEUS provides **offline verifiability** + **legal-grade proofs**

[^7]: Sigstore documentation: https://docs.sigstore.dev

### 17.2 Why Open Source Isn't Enough

**Could enterprises just use Sigstore + TimescaleDB?**

**No, for three reasons:**

1. **Provenance Graphs ≠ Signing**
   - Sigstore signs individual artifacts
   - PROTEUS reconstructs **multi-step derivation chains** (input → tool → output)
   - Enterprises need to prove "how AI produced this result," not just "who signed it"

2. **Storage ≠ Deterministic Verification**
   - TimescaleDB provides time-series storage
   - PROTEUS provides **cryptographic inclusion proofs** + **consistency verification**
   - Courts demand proofs, not just database records

3. **Legal-Grade Chain of Custody**
   - OSS tools don't include:
     - Human decision audit trails
     - Policy snapshots at decision time
     - Offline-verifiable evidence bundles
     - Case management for disputes
   - PROTEUS combines all these + integrates with legal workflows

**The Integration Burden:**
Assembling Sigstore + TimescaleDB + policy engine + case management + export tools requires:
- 6-12 months of engineering
- Deep cryptography expertise
- Ongoing maintenance burden
- No legal defensibility guarantee

**PROTEUS provides turnkey enterprise solution with SLAs, support, and legal backing.**

---

## 18. Why Now

AI increases:
- Output volume
- Dispute frequency
- Regulatory pressure

The market lacks **truth infrastructure**.

### 18.1 Market Timing Indicators

- **EU AI Act enforcement:** August 2026 (high-risk systems), August 2027 (full compliance)
- **US state AI laws:** Colorado, Illinois, NYC already enacted; 20+ states considering
- **Litigation acceleration:** 300%+ increase in AI discrimination lawsuits (2023-2025)[^8]
- **Insurance requirements:** Cyber insurers beginning to require AI audit capabilities

[^8]: American Bar Association, "Recent Developments in Artificial Intelligence Cases and Legislation 2025"

**The Window:** Next 18-24 months before big tech vendors bolt compliance features onto existing products. First-mover advantage in establishing legal standards.

---

## 19. Long-Term Vision

PROTEUS becomes:
- The system of record for digital truth
- The neutral ground for disputes
- The cryptographic memory of AI systems

**5-Year Vision:**
- Industry standard for AI forensics
- Integrated into major cloud platforms (AWS, Azure, GCP) as optional compliance layer
- Regulatory agencies reference PROTEUS evidence format in guidance
- Case law establishes PROTEUS exports as admissible evidence standard

---

## 20. Team & Why Us

### 20.1 Founding Team (To Be Assembled)

**Ideal Team Composition:**

**Technical Co-Founder / CTO:**
- Background in cryptography, distributed systems, or security engineering
- Prior experience: Meta integrity team, Google Certificate Transparency, or similar
- Deep understanding of Merkle trees, append-only logs, zero-trust architectures

**Business Co-Founder / CEO:**
- Legal tech background or compliance/audit experience
- Prior enterprise SaaS sales (ideally to regulated industries)
- Understanding of GRC market and buyer personas

**Founding Engineer #1:**
- Full-stack with focus on cryptographic systems
- Experience with transparency log implementations
- Go/Rust expertise

### 20.2 Unfair Advantages (To Validate)

Potential differentiators:
- **Regulatory connections:** Direct relationships with EU AI Act working groups or NIST AI frameworks
- **Academic credibility:** Published research on cryptographic provenance or transparency logs
- **Industry access:** Existing relationships with Fortune 500 compliance officers
- **Technical IP:** Novel approaches to provenance graph verification or policy determinism

**Note for investors:** This whitepaper presents the product vision. Team assembly and unfair advantage validation are critical next steps for pre-seed fundraising.

---

## 21. Why Not Open Source?

### 21.1 The Open Source Landscape

**Existing OSS Tools:**

- **Sigstore/Rekor:** Software signing + transparency logs
- **TimescaleDB:** Time-series storage
- **Open Policy Agent (OPA):** Policy-as-code
- **Git/Merkle Trees:** Version control + cryptographic hashing

**What They Solve:**
- Individual components of the trust infrastructure
- Point solutions for specific problems

**What They Don't Solve:**
1. **Provenance Graphs:** No OSS tool reconstructs multi-step AI derivation chains
2. **Legal-Grade Evidence:** No turnkey solution for court-admissible bundles
3. **Human Audit Trails:** No case management for disputes + human decisions
4. **Policy Versioning:** No deterministic policy snapshot + replay capability
5. **Enterprise Integration:** No ready-made compliance workflow integration

### 21.2 Why Enterprises Will Pay

**The "Build vs. Buy" Reality:**

Building PROTEUS-equivalent from OSS requires:
- **6-12 months** of engineering (3-5 engineers)
- **$500K-$1M** in labor costs
- **Ongoing maintenance:** 1-2 engineers dedicated
- **No legal defensibility guarantee:** DIY solution untested in court

**What Enterprises Actually Pay For:**
1. **Risk transfer:** Vendor liability + indemnification
2. **SLAs:** Guaranteed uptime, response times
3. **Support:** 24/7 compliance with audit timelines
4. **Legal validation:** Evidence format accepted by courts
5. **Ecosystem integration:** Works with existing GRC, SIEM, case management tools

**Precedent:** Enterprises pay for Splunk, DataDog, Snowflake despite OSS alternatives (ELK, Prometheus, PostgreSQL) because **operational burden + risk >> license cost**.

### 21.3 Open Source Strategy for PROTEUS

**Hybrid Approach (Recommended):**

**Open Source Components:**
- Core cryptographic libraries (Merkle tree, signing)
- Evidence verification CLI (offline verification)
- Client SDKs (capture + signing)

**Proprietary/Commercial:**
- Case management system
- Enterprise integrations (SIEM, GRC, ticketing)
- Hosted transparency log service
- Evidence export + legal workflow tools
- Policy engine + compliance templates

**Benefits:**
- **Trust through transparency:** Core crypto is auditable
- **Ecosystem adoption:** Developers can integrate verification without licensing
- **Commercial moat:** Enterprise features remain differentiated

**Precedent:** HashiCorp (Terraform), Elastic (Elasticsearch), MongoDB—all use open core model successfully.

---

## Appendix A: Sample Evidence Bundle

### A.1 Evidence Bundle Structure

When a case is exported, PROTEUS generates a **deterministic, signed evidence bundle**. Below is the structure a court or auditor would receive:

```
evidence-bundle-case-123.zip
│
├── manifest.json              # Top-level manifest
├── signatures.json            # Cryptographic signatures
│
├── case/
│   └── case.export.json       # Case details, status, question, outcomes
│
├── evidence/
│   ├── items/
│   │   ├── ev-1.json          # Evidence item: verification receipt
│   │   ├── ev-2.json          # Evidence item: derivation graph
│   │   └── ev-3.json          # Evidence item: policy decision
│   │
│   └── blobs/
│       ├── artifact-aaa...aaa.pdf    # Original artifact (if included)
│       └── artifact-bbb...bbb.json   # AI model output
│
├── receipts/
│   ├── verify/
│   │   └── rcpt-1.json        # Verification receipt (signature + inclusion proof)
│   │
│   └── derive/
│       └── rcpt-2.json        # Derivation receipt (provenance graph)
│
├── policies/
│   └── snapshots/
│       └── policy-snap-12.json # Policy bundle at decision time
│
├── audit/
│   └── events.ndjson          # Human + system audit events (append-only)
│
└── proofs/
    ├── inclusion-proofs/
    │   └── proof-ev-1.json    # Merkle inclusion proof for evidence
    │
    └── consistency-proofs/
        └── consistency-12-34.json # Log consistency proof
```

### A.2 Key Files Explained

**manifest.json** (Pack Manifest)
```json
{
  "pack_version": "v1",
  "pack_id": "pack_01HZZZZZZZZZZZZZZZZZZZZZZZ",
  "generated_at": "2026-01-26T03:00:00Z",
  "generated_by": {
    "principal_hash": "sha256:abc123...",
    "principal_type": "user",
    "display": "reviewer-1@acme.com"
  },
  "tenant_id": "tenant-acme-corp",
  "case_id": "case-123",
  "files": [
    {
      "path": "manifest.json",
      "sha256": "0000...",
      "bytes": 1234,
      "content_type": "application/json",
      "role": "manifest"
    },
    {
      "path": "case/case.export.json",
      "sha256": "1111...",
      "bytes": 2345,
      "content_type": "application/json",
      "role": "case"
    },
    ...
  ]
}
```

**case/case.export.json** (Case Export)
```json
{
  "case_id": "case-123",
  "tenant_id": "tenant-acme-corp",
  "status": "RESOLVED",
  "opened_at": "2026-01-26T03:00:00Z",
  "closed_at": "2026-01-27T15:30:00Z",
  "question": "Was the AI-generated credit decision authentic, policy-compliant, and untampered at time of applicant notification?",
  "scope": {
    "artifacts": [
      "artifact:sha256:aaaa...aaaa"  # Credit decision output
    ],
    "time_range": {
      "start": "2025-12-15T10:00:00Z",
      "end": "2025-12-15T10:05:00Z"
    }
  },
  "holds": [
    {
      "hold_id": "hold-legal-1",
      "type": "litigation_hold",
      "placed_at": "2026-01-26T03:00:00Z",
      "placed_by": "legal-team@acme.com",
      "rationale": "Pending discrimination lawsuit - Smith v. Acme Bank"
    }
  ],
  "outcomes": [
    {
      "outcome_id": "out-1",
      "decided_at": "2026-01-27T15:30:00Z",
      "decided_by": "compliance-officer@acme.com",
      "decision": "authentic_and_compliant",
      "justification": "Verification receipt confirms valid signature and inclusion proof. Policy snapshot v12 was in effect. Derivation graph shows all inputs were properly sanitized. Human approval by loan officer recorded.",
      "policy_snapshot_ref": "policy-snap-12",
      "supporting_evidence": ["ev-1", "ev-2", "ev-3"]
    }
  ]
}
```

**evidence/items/ev-1.json** (Verification Receipt Evidence)
```json
{
  "evidence_id": "ev-1",
  "tenant_id": "tenant-acme-corp",
  "case_id": "case-123",
  "kind": "verification_receipt",
  "created_at": "2026-01-26T03:15:00Z",
  "label": "Cryptographic verification of credit decision artifact",
  "summary": "Signature valid, not revoked, included in transparency log at position 12,456",
  "references": [
    {
      "type": "receipt_verify",
      "ref": "receipts/verify/rcpt-1.json"
    }
  ],
  "pack_paths": {
    "metadata": "evidence/items/ev-1.json",
    "blobs": ["evidence/blobs/artifact-aaa...aaa.json"]
  }
}
```

**audit/events.ndjson** (Audit Trail - NDJSON format for append-only log)
```json
{"event_id":"evt-1","occurred_at":"2026-01-26T03:00:00Z","tenant_id":"tenant-acme-corp","case_id":"case-123","type":"CASE_OPENED","actor":{"actor_type":"system","actor_hash":"sha256:system","display":"PROTEUS Policy Engine"},"details":{"trigger":"policy_decision_require_review","artifact":"artifact:sha256:aaaa...aaaa"}}
{"event_id":"evt-2","occurred_at":"2026-01-26T03:05:00Z","tenant_id":"tenant-acme-corp","case_id":"case-123","type":"HOLD_PLACED","actor":{"actor_type":"user","actor_hash":"sha256:user-legal-1","display":"legal-team@acme.com"},"details":{"hold_id":"hold-legal-1","hold_type":"litigation_hold","rationale":"Pending discrimination lawsuit"}}
{"event_id":"evt-3","occurred_at":"2026-01-27T15:30:00Z","tenant_id":"tenant-acme-corp","case_id":"case-123","type":"