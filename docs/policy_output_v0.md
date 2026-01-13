# Policy Output v0 (Normative)

This document defines the deterministic output schema for OPA policy evaluation.

## 1. Result object
OPA policies MUST return a `result` object with:

```json
{
  "allow": true,
  "deny": [
    { "code": "SIGNATURE_INVALID", "message": "optional" }
  ]
}
```

Rules:
- `allow` MUST be `true` if and only if `deny` is empty.
- `deny` MUST be ordered deterministically (lexicographic by `code`).
- `message` is optional and informational only.

## 2. Receipt / replay binding
When policy results are attached to receipts or replay bundles:

```json
{
  "bundle_hash": "hex",
  "bundle_id": "optional",
  "result": { "...": "..." }
}
```

`bundle_hash` MUST be the deterministic hash of the policy bundle (see `docs/decision_replay_v0.md`).
