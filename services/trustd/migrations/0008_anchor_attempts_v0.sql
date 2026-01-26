-- Phase 3: anchor attempts (append-only operational log).

CREATE TABLE IF NOT EXISTS anchor_attempts (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  tree_size BIGINT NOT NULL,
  provider TEXT NOT NULL,
  bundle_id TEXT NOT NULL,
  status TEXT NOT NULL,
  error_code TEXT NULL,
  payload_hash TEXT NOT NULL,
  provider_receipt_json JSONB NULL,
  provider_receipt_truncated BOOLEAN NOT NULL DEFAULT false,
  provider_receipt_size_bytes INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_anchor_attempts_tenant_created
  ON anchor_attempts (tenant_id, created_at);

CREATE INDEX IF NOT EXISTS idx_anchor_attempts_tenant_provider_created
  ON anchor_attempts (tenant_id, provider, created_at);

CREATE INDEX IF NOT EXISTS idx_anchor_attempts_tenant_payload
  ON anchor_attempts (tenant_id, payload_hash, created_at);

-- Append-only enforcement.
CREATE OR REPLACE FUNCTION anchor_attempts_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'anchor_attempts is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS anchor_attempts_no_update_delete ON anchor_attempts;
CREATE TRIGGER anchor_attempts_no_update_delete
BEFORE UPDATE OR DELETE ON anchor_attempts
FOR EACH ROW EXECUTE FUNCTION anchor_attempts_no_update_delete();
