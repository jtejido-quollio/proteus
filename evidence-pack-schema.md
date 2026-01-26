# Regulator-facing Evidence Pack schema (ZIP)

## ZIP layout
```text
evidence-pack
  manifest.json
  signatures.json
  case/
    case.export.json
  evidence/
    items/
      <evidence_id>.json
    blobs/
      <evidence_id>/<filename>
  audit/
    events.ndjson
  policy/
    snapshots/
      <policy_snapshot_id>.json
  derivation/
    graph.json
  receipts/
    verify/
      <receipt_id>.json
    anchor/
      <receipt_id>.json
```

## Determinism + chain-of-custody
- `manifest.json` lists every file with sha256 + size.
- `signatures.json` includes manifest hash + overall pack hash; optional org signature.
- `audit/events.ndjson` records export request, approvals, completion, and redactions (if any).
