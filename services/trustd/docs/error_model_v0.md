# Error Model v0

Errors are returned as:
```json
{
  "code": "STRING",
  "message": "STRING",
  "details": { }
}
```

## HTTP status mapping
- `400 Bad Request`: `INVALID_MANIFEST`, `INVALID_JSON`, `INVALID_ARTIFACT_ENCODING`, `SIGNATURE_INVALID`, `KEY_UNKNOWN`, `KEY_REVOKED`, `LOG_PROOF_INVALID`, `STH_INVALID`, `ARTIFACT_HASH_MISMATCH`, `PROOF_REQUIRED`
- `401 Unauthorized`: `UNAUTHORIZED`
- `404 Not Found`: `NOT_FOUND`
- `409 Conflict` (optional; discouraged for idempotency): `ALREADY_EXISTS`
- `429 Too Many Requests`: `RATE_LIMITED`
- `500 Internal Server Error`: `INTERNAL`

## Canonical codes
- `INVALID_MANIFEST`
- `INVALID_JSON`
- `INVALID_ARTIFACT_ENCODING`
- `SIGNATURE_INVALID`
- `KEY_UNKNOWN`
- `KEY_REVOKED`
- `LOG_PROOF_INVALID`
- `STH_INVALID`
- `ARTIFACT_HASH_MISMATCH`
- `PROOF_REQUIRED`
- `NOT_FOUND`
- `UNAUTHORIZED`
- `RATE_LIMITED`
- `INTERNAL`
