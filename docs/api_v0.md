# API v0 Contract (Draft)

## POST /v1/manifests:record
Request: Signed Manifest Envelope

Response (draft):
```json
{
  "manifest_id": "uuid",
  "leaf_hash": "hex",
  "leaf_index": 123,
  "sth": {
    "tree_size": 124,
    "root_hash": "hex",
    "issued_at": "RFC3339",
    "signature": "base64"
  },
  "inclusion_proof": {
    "leaf_index": 123,
    "path": ["hex", "hex"],
    "sth_tree_size": 124,
    "sth_root_hash": "hex"
  }
}
```

## POST /v1/manifests:verify
Request:
```json
{
  "envelope": { "...": "..." },
  "artifact": {
    "media_type": "application/json",
    "bytes_base64": "optional",
    "uri": "optional"
  }
}
```

Response: Verification Receipt (see Phase 0 spec).
