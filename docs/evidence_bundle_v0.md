# Evidence Bundle v0 (Normative)

This document defines the **Evidence Bundle** format for legal-grade, offline
verification of Proteus receipts. It is an **auditor-facing**, portable JSON
artifact that allows third parties to reproduce verification, policy, and
decision outcomes without network access.

## 1. Purpose
The evidence bundle exists to:
- Enable **offline** verification and replay.
- Provide a **third-party verifiable** record of proofs and decisions.
- Bind all deterministic inputs and outputs via hashes.

## 2. Non-goals
The evidence bundle does **not**:
- Trust or depend on Proteus databases.
- Require online lookups (no network).
- Introduce new timestamps beyond those already signed.

## 3. Required components
An evidence bundle MUST include:
- Signed envelope(s).
- Manifest(s) (as received, including embedded inputs).
- Signatures + key metadata.
- Inclusion proof(s).
- Signed Tree Head(s).
- Revocation statements.
- Derivation summary (if present).
- Verification receipt.
- `replay_inputs_digest`.
- Engine versions (verification, derivation, policy, decision).

## 4. Canonical JSON structure (JCS)
The bundle MUST be serialized using RFC 8785 (JCS).

### Top-level structure
```json
{
  "bundle_id": "string",
  "version": "v0",
  "envelopes": [ { "...": "..." } ],
  "manifests": [ { "...": "..." } ],
  "keys": {
    "signing": [ { "...": "..." } ],
    "log": [ { "...": "..." } ]
  },
  "revocations": [ { "...": "..." } ],
  "proofs": {
    "sths": [ { "...": "..." } ],
    "inclusion_proofs": [ { "...": "..." } ]
  },
  "derivation": { "...": "..." },
  "engines": {
    "verification": "string",
    "derivation": "string",
    "policy": "string",
    "decision": "string"
  },
  "receipt": { "...": "..." },
  "receipt_digest": "hex",
  "replay_inputs_digest": "hex"
}
```

### Required fields
- `bundle_id`: stable identifier for the bundle instance.
- `version`: MUST be `"v0"`.
- `envelopes`: one or more signed envelopes.
- `manifests`: manifests referenced by `envelopes`.
- `keys.signing`: signing public keys used by `envelopes`.
- `keys.log`: log public keys used by `sths`.
- `revocations`: revocation statements applicable to signing or log keys.
- `proofs.sths`: STH objects used in verification.
- `proofs.inclusion_proofs`: inclusion proofs for each envelope leaf.
- `receipt`: verification receipt (v0 semantics).
- `receipt_digest`: deterministic hash of `receipt` (see §6).
- `replay_inputs_digest`: deterministic hash of replay inputs (see §6).
- `engines`: engine version identifiers (see `docs/decision_replay_v0.md`).

### Optional fields
- `derivation`: derivation summary if derivation evaluation was performed.

## 5. Deterministic ordering rules
Arrays MUST be deterministically ordered to ensure stable hashing:
- `envelopes`: order by `manifest.manifest_id` ascending (bytewise).
- `manifests`: order by `manifest_id` ascending (bytewise).
- `keys.signing` and `keys.log`: order by `kid` ascending (bytewise).
- `revocations`: order by `kid` ascending, then `revoked_at` ascending.
- `proofs.sths`: order by `tree_size` ascending, then `root_hash` ascending.
- `proofs.inclusion_proofs`: order by `leaf_index` ascending, then `sth_tree_size`.

If any ordering keys are missing, the bundle MUST be rejected as invalid.

## 6. Hash binding rules
All hashes MUST use `sha256` over JCS canonical bytes, encoded as lowercase hex.

### 6.1 receipt_digest
`receipt_digest = sha256( JCS(receipt) )`

The receipt digest binds the receipt payload as the authoritative summary.

### 6.2 replay_inputs_digest
`replay_inputs_digest` MUST follow `docs/decision_replay_v0.md`.

Notes:
- `sth.signature` and `sth.issued_at` are **excluded** from replay inputs digest.
- v0 replay/policy evaluation is **time-independent**.

## 7. Offline verification steps (exact order)
An offline verifier MUST execute the following steps in order:
1. **Parse and canonicalize** the bundle via JCS.
2. **Validate ordering** rules (§5).
3. **Verify signatures**:
   - For each envelope, verify the Ed25519 signature over canonical manifest bytes.
   - For each STH, verify the Ed25519 signature over canonical STH bytes.
4. **Verify inclusion proofs** against the matching STH root for each envelope.
5. **Apply revocations** to signing/log keys.
6. **Evaluate derivation** if `derivation` is present.
7. **Evaluate policy** using the deterministic policy input.
8. **Evaluate decision** using verification + derivation + policy results.
9. **Recompute `receipt_digest` and `replay_inputs_digest`** and compare.

If any step fails, verification MUST fail.

## 8. Security constraints
- No online lookups are permitted.
- No timestamps other than those already signed are allowed.
- No randomness or environment-dependent inputs may be used.

## 9. Backward compatibility
Bundles that omit `derivation` remain valid as long as all required fields
are present and hashes match.
