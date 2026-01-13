# Decision Replay v0 (Normative)

This document defines **deterministic decision replay** for offline verification.
Replay bundles allow auditors to reproduce verification -> policy -> decision
results byte-for-byte from a portable JSON artifact.

## 1. Required replay inputs
To replay a decision deterministically, the following inputs are REQUIRED:
- **Signed manifest envelope** (exact bytes as received).
- **Transparency proof**: `sth` + `inclusion_proof` for the leaf.
- **Trust anchors**: tenant signing public key(s) and log public key.
- **Policy bundle** (OPA bundle or equivalent) and its identity hash.
- **Engine versions** for verification, derivation, policy, and decision.

Optional inputs:
- Artifact bytes + media_type (if subject hash verification is required).
- Derivation summary (if derivation evaluation was performed).

## 2. Deterministic evaluation order
Replay MUST execute in this order:
1. **Verification**
   - Canonicalize manifest (RFC 8785).
   - Verify Ed25519 signature.
   - Compute leaf hash and validate inclusion proof against STH.
2. **Derivation** (if derivation summary present)
   - Evaluate derivation rules deterministically over manifest inputs.
3. **Policy** (OPA)
   - Load policy bundle by hash.
   - Evaluate policy with a stable input schema.
4. **Decision**
   - Combine verification + derivation + policy results into a decision.

All steps MUST be pure (no network, no wall-clock, no randomness).

## 3. Policy bundle identity and hashing
`policy.bundle_hash` MUST be `sha256` over RFC 8785 canonical JSON bytes
of the policy bundle content.

Policy bundle content is defined as:

```json
{
  "files": [
    {
      "path": "relative/path.rego",
      "sha256": "hex"
    }
  ]
}
```

Rules:
- Include all files under the bundle directory.
- Paths are relative to the bundle root and sorted lexicographically.
- `sha256` is computed over raw file bytes.
- Only normative files are included: `*.rego`, `data.json`, `manifest.json`.
- Ignore dotfiles, `__MACOSX/`, archive files, and `vendor/` directories.

If `policy.bundle_id` is provided, it MUST refer to the same content
identified by `bundle_hash`. `bundle_id` is informational; `bundle_hash`
is authoritative.

## 4. Engine version binding
Replay MUST be bound to explicit engine versions:
- `engines.verification`
- `engines.derivation`
- `engines.policy`
- `engines.decision`

If a replay engine does not match the bundle’s declared version, the replay
MUST fail.

## 5. Replay inputs digest (optional helper)
Implementations MAY include a `replay_inputs_digest` to bind deterministic
policy/decision inputs and outputs. It MUST be computed over the following JSON object:

```json
{
  "envelope": { "...": "..." },
  "proof": {
    "sth": {
      "tenant_id": "optional",
      "tree_size": 4,
      "root_hash": "hex"
    },
    "inclusion_proof": {
      "tenant_id": "optional",
      "leaf_index": 2,
      "path": ["hex", "hex"],
      "sth_tree_size": 4,
      "sth_root_hash": "hex"
    }
  },
  "derivation": { "...": "..." },
  "policy": {
    "bundle_hash": "hex",
    "result": { "...": "..." }
  },
  "decision": { "...": "..." },
  "engines": {
    "verification": "string",
    "derivation": "string",
    "policy": "string",
    "decision": "string"
  }
}
```

Notes:
- `derivation`, `policy`, and `decision` are omitted if not present.
- `sth.signature` and `sth.issued_at` are **excluded** from the digest.
- Canonicalization MUST use RFC 8785 (JCS), then `sha256` (lowercase hex).
 - v0 replay and policy evaluation is time-independent; no wall-clock inputs are allowed.

## 6. Replay bundle JSON structure
Replay bundles MUST follow this structure:

```json
{
  "envelope": { "...": "..." },
  "proof": {
    "sth": {
      "tenant_id": "optional",
      "tree_size": 4,
      "root_hash": "hex",
      "issued_at": "RFC3339",
      "signature": "base64"
    },
    "inclusion_proof": {
      "tenant_id": "optional",
      "leaf_index": 2,
      "path": ["hex", "hex"],
      "sth_tree_size": 4,
      "sth_root_hash": "hex"
    }
  },
  "derivation": { "...": "..." },
  "policy": {
    "bundle_id": "optional",
    "bundle_hash": "hex",
    "result": { "...": "..." }
  },
  "decision": { "...": "..." },
  "engines": {
    "verification": "string",
    "derivation": "string",
    "policy": "string",
    "decision": "string"
  },
  "replay_inputs_digest": "optional hex"
}
```

Notes:
- `derivation`, `policy`, `decision`, and `replay_inputs_digest` are optional.
- The replay bundle MUST be valid without network access.
