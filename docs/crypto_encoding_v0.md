# Crypto & Encoding Spec v0 (Normative)

This document defines **byte-level** encodings to ensure interoperability across SDKs and verifiers.

## 1. Canonicalization

### 1.1 Text (text/plain; charset=utf-8)
Canonical bytes are produced by:
1. Interpret input as UTF-8 bytes. If invalid UTF-8 is provided, the system MUST reject with `INVALID_ARTIFACT_ENCODING`.
2. Normalize line endings: replace all occurrences of `\r\n` with `\n`.
3. Do not trim whitespace.
4. Canonical bytes = resulting byte sequence.

### 1.2 JSON (application/json)
Canonical bytes MUST be produced according to **RFC 8785 (JCS)**:
- UTF-8 encoding
- Object member names sorted lexicographically by Unicode code points
- Numbers normalized per RFC 8785
- No insignificant whitespace

If the JSON is invalid, the system MUST reject with `INVALID_JSON`.

## 2. Hashing
- Algorithm: `sha256`
- Digest representation: lowercase hex string when serialized into JSON; raw 32 bytes when used inside cryptographic payloads.

## 3. Signed payload (manifest signature)
- Payload = `JCS(manifest)` bytes (per RFC 8785).
- Signature alg v0: `ed25519`
- Signature value in envelope: base64 of raw signature bytes.

## 4. Leaf hash encoding (transparency log)
A leaf binds the signed manifest envelope (manifest + signature metadata).

### 4.1 Leaf payload structure
Define a canonical leaf JSON object:
```json
{
  "manifest": <Manifest>,
  "signature": { "alg": "ed25519", "kid": "<kid>", "value": "<base64sig>" }
}
```

Leaf payload bytes:
- `leaf_payload = JCS(leaf_object)` (RFC 8785 bytes)

Leaf hash:
- `leaf_hash = sha256(leaf_payload)` (raw 32 bytes)

### 4.2 Notes
- `cert_chain` is not included in the leaf hash in v0. (It may be supported in a future version with explicit encoding.)
- Any change to `manifest`, `kid`, `alg`, or `signature.value` changes the leaf hash.

## 5. Signed Tree Head (STH) encoding
STH payload is a canonical JSON object:

```json
{
  "tenant_id": "<uuid>",
  "tree_size": 123,
  "root_hash": "<hex>",
  "issued_at": "RFC3339"
}
```

STH payload bytes:
- `sth_payload = JCS(sth_object)` (RFC 8785 bytes)

STH signature:
- `sth_signature = ed25519_sign(log_private_key, sth_payload)` (raw signature bytes)
- Serialized as base64 in API responses.

## 6. Inclusion proof encoding (API)
Inclusion proof object:
- `leaf_index` (int64)
- `path` (array of hex-encoded 32-byte hashes, from leaf sibling upwards)
- `sth_tree_size` (int64)
- `sth_root_hash` (hex)

Verification recomputes the RFC 6962 tree hash using the leaf hash and `path`, matching `sth_root_hash`.

## 7. Consistency proof encoding (API)
Consistency proof object:
- `from_size` (int64)
- `to_size` (int64)
- `path` (array of hex-encoded 32-byte hashes)

Verification follows the standard RFC 6962 / CT-style consistency proof algorithm.

## 8. Merkle tree hashing (Normative)

This system uses a binary Merkle tree over **leaf hashes** (32-byte values).

- Leaf node value: `L[i] = leaf_hash[i]` (raw 32 bytes as defined in section 4)
- Internal node hash:
  - `node_hash(left, right) = sha256( 0x01 || left || right )`
    - where `0x01` is a single byte prefix
    - `left` and `right` are each 32 bytes

Notes:
- The prefix prevents ambiguity between internal-node hashing and other concatenations.
- Leaves are already 32-byte hashes; no additional `0x00` prefixing is used in v0.

Merkle tree hash (RFC 6962 / CT-style):
- For `n = 1`, `root = leaf_hash[0]`.
- For `n > 1`, let `k` be the largest power of two less than `n`.
  - `root = node_hash(MTH(leaf_hash[0:k]), MTH(leaf_hash[k:n]))`.
- Odd-node duplication is not used.
