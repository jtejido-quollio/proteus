-- Phase 3 additive: per-tenant revocation epoch for cache invalidation and replay binding.

CREATE TABLE IF NOT EXISTS tenant_revocation_epoch (
  tenant_id TEXT PRIMARY KEY,
  epoch BIGINT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

INSERT INTO tenant_revocation_epoch (tenant_id, epoch, updated_at)
  SELECT id::text, 0, now()
  FROM tenants
  ON CONFLICT (tenant_id) DO NOTHING;

CREATE INDEX IF NOT EXISTS idx_tenant_revocation_epoch_updated_at
  ON tenant_revocation_epoch (updated_at);
