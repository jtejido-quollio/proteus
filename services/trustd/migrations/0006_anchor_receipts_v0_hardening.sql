-- Phase 3: anchor receipts hardening (append-only + dedupe).

ALTER TABLE anchor_receipts
  ADD COLUMN IF NOT EXISTS tree_size BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS provider_receipt_truncated BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS provider_receipt_size_bytes INT NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX IF NOT EXISTS idx_anchor_receipts_unique
  ON anchor_receipts (tenant_id, tree_size, provider, payload_hash);

CREATE INDEX IF NOT EXISTS idx_anchor_receipts_tenant_created
  ON anchor_receipts (tenant_id, created_at);

CREATE INDEX IF NOT EXISTS idx_anchor_receipts_tenant_provider_created
  ON anchor_receipts (tenant_id, provider, created_at);

-- Append-only enforcement.
CREATE OR REPLACE FUNCTION anchor_receipts_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'anchor_receipts is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS anchor_receipts_no_update_delete ON anchor_receipts;
CREATE TRIGGER anchor_receipts_no_update_delete
BEFORE UPDATE OR DELETE ON anchor_receipts
FOR EACH ROW EXECUTE FUNCTION anchor_receipts_no_update_delete();
