-- Phase 3: anchor receipts for external integrity providers.

CREATE TABLE IF NOT EXISTS anchor_receipts (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  bundle_id TEXT NOT NULL,
  status TEXT NOT NULL,
  error_code TEXT NULL,
  payload_hash TEXT NOT NULL,
  entry_uuid TEXT NULL,
  log_index BIGINT NULL,
  integrated_time BIGINT NULL,
  entry_url TEXT NULL,
  tx_id TEXT NULL,
  chain_id TEXT NULL,
  explorer_url TEXT NULL,
  provider_receipt_json JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_anchor_receipts_tenant_payload
  ON anchor_receipts (tenant_id, payload_hash);

CREATE INDEX IF NOT EXISTS idx_anchor_receipts_tenant_created
  ON anchor_receipts (tenant_id, created_at);

CREATE INDEX IF NOT EXISTS idx_anchor_receipts_provider
  ON anchor_receipts (provider, bundle_id);
