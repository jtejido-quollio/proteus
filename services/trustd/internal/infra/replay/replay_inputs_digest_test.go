package replay

import "testing"

func TestComputeReplayInputsDigest_IgnoresSTHSignatureAndIssuedAt(t *testing.T) {
	payload := map[string]any{
		"envelope": map[string]any{
			"manifest": map[string]any{
				"schema":      "trust.manifest.v0",
				"manifest_id": "manifest-1",
				"tenant_id":   "tenant-1",
				"subject": map[string]any{
					"type":       "artifact",
					"media_type": "application/json",
					"hash": map[string]any{
						"alg":   "sha256",
						"value": "aaaa",
					},
				},
				"actor": map[string]any{
					"type": "person",
					"id":   "actor-1",
				},
				"tool": map[string]any{
					"name":    "tool",
					"version": "1.0.0",
				},
				"time": map[string]any{
					"created_at":   "2025-01-01T00:00:00Z",
					"submitted_at": "2025-01-01T00:00:00Z",
				},
			},
			"signature": map[string]any{
				"alg":   "ed25519",
				"kid":   "kid-1",
				"value": "SIG",
			},
		},
		"proof": map[string]any{
			"sth": map[string]any{
				"tenant_id": "tenant-1",
				"tree_size": 4,
				"root_hash": "bbbb",
				"issued_at": "2025-01-01T00:00:00Z",
				"signature": "SIG_A",
			},
			"inclusion_proof": map[string]any{
				"leaf_index":    2,
				"path":          []any{"cccc", "dddd"},
				"sth_tree_size": 4,
				"sth_root_hash": "bbbb",
			},
		},
		"policy": map[string]any{
			"bundle_hash": "hash",
			"result": map[string]any{
				"allow": true,
			},
		},
		"engines": map[string]any{
			"verification": "verify@v0",
			"policy":       "opa@v0",
			"decision":     "decision@v0",
		},
		"revocation_epoch": int64(0),
	}

	digestA, err := ComputeReplayInputsDigestFromPayload(payload)
	if err != nil {
		t.Fatalf("digest A: %v", err)
	}

	sth := payload["proof"].(map[string]any)["sth"].(map[string]any)
	sth["issued_at"] = "2026-01-01T00:00:00Z"
	sth["signature"] = "SIG_B"
	digestB, err := ComputeReplayInputsDigestFromPayload(payload)
	if err != nil {
		t.Fatalf("digest B: %v", err)
	}
	if digestA != digestB {
		t.Fatalf("expected signature/issued_at changes to keep digest stable")
	}

	sth["root_hash"] = "cccc"
	digestC, err := ComputeReplayInputsDigestFromPayload(payload)
	if err != nil {
		t.Fatalf("digest C: %v", err)
	}
	if digestC == digestA {
		t.Fatalf("expected replay input changes to alter digest")
	}

	policy := payload["policy"].(map[string]any)
	policy["result"] = map[string]any{"allow": false}
	digestD, err := ComputeReplayInputsDigestFromPayload(payload)
	if err != nil {
		t.Fatalf("digest D: %v", err)
	}
	if digestD == digestC {
		t.Fatalf("expected policy result changes to alter digest")
	}

	payload["decision"] = map[string]any{"action": "allow"}
	digestE, err := ComputeReplayInputsDigestFromPayload(payload)
	if err != nil {
		t.Fatalf("digest E: %v", err)
	}
	payload["decision"] = map[string]any{"action": "block"}
	digestF, err := ComputeReplayInputsDigestFromPayload(payload)
	if err != nil {
		t.Fatalf("digest F: %v", err)
	}
	if digestE == digestF {
		t.Fatalf("expected decision result changes to alter digest")
	}

	payload["revocation_epoch"] = int64(1)
	digestG, err := ComputeReplayInputsDigestFromPayload(payload)
	if err != nil {
		t.Fatalf("digest G: %v", err)
	}
	payload["revocation_epoch"] = int64(2)
	digestH, err := ComputeReplayInputsDigestFromPayload(payload)
	if err != nil {
		t.Fatalf("digest H: %v", err)
	}
	if digestG == digestH {
		t.Fatalf("expected revocation_epoch changes to alter digest")
	}
}
