# Manifest Schema v0 (Normative)

## Manifest example
```json
{
  "schema": "trust.manifest.v0",
  "manifest_id": "2c2a1a8d-1d88-4e1e-8f88-5d1c8b0e6a7e",
  "tenant_id": "c6d1fcb6-2e5c-4d80-9e61-1ac7c0e8f2d1",
  "subject": {
    "type": "artifact",
    "media_type": "application/json",
    "hash": { "alg": "sha256", "value": "b5c4..." },
    "size_bytes": 2310,
    "uri": "s3://bucket/path/or/external/url"
  },
  "actor": { "type": "service", "id": "inference-gateway", "display": "Inference Gateway" },
  "tool": { "name": "llm-pipeline", "version": "1.3.0", "vendor": "acme", "environment": "prod" },
  "time": { "created_at": "2026-01-12T05:00:00Z", "submitted_at": "2026-01-12T05:00:01Z" },
  "inputs": [
    { "media_type": "text/plain", "hash": { "alg": "sha256", "value": "9c1d..." }, "uri": "s3://..." }
  ],
  "claims": { "model_id": "gpt-4.x", "tags": ["customer-support"] }
}
```

## Signed Manifest Envelope example
```json
{
  "manifest": { "...": "..." },
  "signature": {
    "alg": "ed25519",
    "kid": "tenant-key-001",
    "value": "BASE64_SIGNATURE"
  },
  "cert_chain": []
}
```

## Requirements
- `schema`, `tenant_id`, `subject.hash.value`, `signature.kid`, `signature.value` are required.
- The signed payload is the canonical JSON bytes (RFC 8785 JCS) of `manifest` only.
