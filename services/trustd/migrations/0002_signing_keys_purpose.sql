-- Phase 3 additive: distinguish signing vs log keys while preserving v0 semantics.

ALTER TABLE signing_keys
  ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'signing';

CREATE INDEX IF NOT EXISTS idx_signing_keys_tenant_purpose
  ON signing_keys (tenant_id, purpose);
