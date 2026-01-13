# agents.md — Trust Infrastructure (Category 3)

This file defines how AI coding agents (ChatGPT Codex, etc.) must operate in this repository.

It is **authoritative**.

---

## 1. Project Intent

This repository implements a **Category 3 Trust Infrastructure** providing:

- Cryptographic proof of origin
- Content integrity guarantees
- Per-tenant transparency logs
- Portable, offline-verifiable receipts

This is **infrastructure**, not an application.

Phase 0 specifications define immutable cryptographic and protocol contracts.

---

## 2. Phase Awareness

### Phase 0 (COMPLETE — IMMUTABLE)

Artifacts under:
- `/docs`
- `/testvectors/v0`
- `/migrations/0001_init.sql`

**MUST NOT be modified** unless explicitly instructed by the human owner.

Phase 0 defines:
- Canonicalization rules
- Hashing rules
- Signature formats
- Merkle tree construction
- Inclusion & consistency proof semantics
- API request/response shapes
- Error codes

If code disagrees with Phase 0, **code is wrong**.

---

### Phase 1 (IN PROGRESS — IMPLEMENTATION ONLY)

Allowed work:
- Implement cryptographic primitives
- Implement transparency log logic
- Implement `/record` and `/verify` endpoints
- Make all v0 test vectors pass
- Add tests that validate Phase 0 behavior

Phase 1 MUST NOT:
- Change Phase 0 semantics
- Introduce new crypto schemes
- Add batching, async issuance, or background jobs
- Add watermarking, ML, or detection logic
- “Improve” or reinterpret specs

---

## 3. Source of Truth Hierarchy

When conflicts arise, agents MUST follow this order:

1. `/docs/*.md` (Phase 0 specifications)
2. `/testvectors/v0/*` (byte-for-byte truth)
3. Domain interfaces (`/internal/domain`, `/internal/usecase`)
4. Infrastructure code (`/internal/infra`)

Agent intuition, best practices, blog posts, or libraries are **not** sources of truth.

---

## 4. Cryptography Rules (Non-Negotiable)

Agents MUST:

- Use **Ed25519** only (Phase 1 / v0)
- Use **RFC 8785 (JCS)** for JSON canonicalization
- Use `sha256` exactly as specified
- Implement Merkle internal node hashing as:
    ```node_hash = sha256(0x01 || left || right)```

- Implement **RFC 6962 / Certificate Transparency–style Merkle trees**:
- Largest-power-of-two split
- **No odd-leaf duplication**
- Tree-size–aware inclusion proofs
- CT-style consistency proofs
- Match `/testvectors/v0` **byte-for-byte**

Agents MUST NOT:

- Replace crypto libraries without approval
- Change byte encodings or canonicalization
- Change leaf / manifest / STH payload shapes
- “Optimize” hashing, tree shape, or proof logic
- Modify `/docs` or `/testvectors` unless explicitly instructed

---

## 5. Test Vector Discipline

Before declaring work “done”, agents MUST:

- Validate against `/testvectors/v0`
- Explicitly confirm correctness for:
- Canonical bytes
- Leaf hashes
- Merkle roots
- Inclusion proofs
- Consistency proofs
- Receipts

If a test vector fails:

> **The implementation is wrong — not the vector.**

---

## 6. Clean Architecture Enforcement

Agents MUST respect architectural boundaries:

- `/internal/domain`
- Pure types only
- No IO
- No crypto
- `/internal/usecase`
- Orchestration and policy
- No DB or HTTP
- `/internal/infra`
- Crypto implementations
- Merkle logic
- DB, HTTP, adapters

Agents MUST NOT:
- Call DB from domain
- Perform crypto in HTTP handlers
- Collapse layers “for convenience”

---

## 7. Phase 1 Roadmap (Strict Order)

Agents MUST follow this execution order:

1. **CryptoService**
 - Text canonicalization
 - JSON RFC 8785 JCS
 - Ed25519 verification
 - Leaf hash computation

2. **Transparency Log Core**
 - Append-only per-tenant log
 - STH-per-append
 - Inclusion proof generation
 - Consistency proof generation

3. **/v1/manifests:record**
 - Schema validation
 - Signature verification
 - Revocation check
 - Log append
 - Portable receipt output

4. **/v1/manifests:verify**
 - Offline-first verification
 - Proof verification
 - Deterministic verdicts

Steps MUST NOT be skipped, merged, or reordered.

---

## 8. When Agents Must Stop

Agents MUST stop and ask for human input if:

- A spec appears ambiguous
- A test vector contradicts implementation intuition
- A change would affect Phase 0 behavior
- Performance concerns would alter correctness
- Any crypto rule appears unclear

Silence is worse than asking.

---

## 9. Engineering Philosophy

This system is **trust infrastructure**.

- Correctness > cleverness  
- Determinism > performance  
- Proofs > heuristics  

Agents are expected to behave like **cryptography engineers**, not startup hackers.
