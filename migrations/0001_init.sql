-- Phase 0 schema: tenants, keys, revocations, manifests, signed envelopes, per-tenant transparency log leaves, tree heads.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS signing_keys (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kid TEXT NOT NULL,
  alg TEXT NOT NULL,
  public_key BYTEA NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  not_before TIMESTAMPTZ NULL,
  not_after TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, kid)
);

CREATE TABLE IF NOT EXISTS revocations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  kid TEXT NOT NULL,
  revoked_at TIMESTAMPTZ NOT NULL,
  reason TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, kid)
);

CREATE TABLE IF NOT EXISTS manifests (
  id UUID PRIMARY KEY, -- manifest_id
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  subject_hash_alg TEXT NOT NULL,
  subject_hash_value TEXT NOT NULL,
  subject_media_type TEXT NOT NULL,
  manifest_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_manifests_tenant_subjecthash
  ON manifests (tenant_id, subject_hash_value);

CREATE TABLE IF NOT EXISTS signed_manifests (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  manifest_id UUID NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
  kid TEXT NOT NULL,
  sig_alg TEXT NOT NULL,
  signature BYTEA NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_signed_manifests_tenant_manifest
  ON signed_manifests (tenant_id, manifest_id);

CREATE TABLE IF NOT EXISTS transparency_log_leaves (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  leaf_index BIGINT NOT NULL,
  leaf_hash BYTEA NOT NULL,
  signed_manifest_id UUID NOT NULL REFERENCES signed_manifests(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, leaf_index),
  UNIQUE (tenant_id, leaf_hash)
);

CREATE TABLE IF NOT EXISTS tree_heads (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  tree_size BIGINT NOT NULL,
  root_hash BYTEA NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  sth_signature BYTEA NOT NULL,
  UNIQUE (tenant_id, tree_size)
);

-- Optional cache table (Phase 1+)
CREATE TABLE IF NOT EXISTS proof_cache (
  cache_key TEXT PRIMARY KEY,
  value_json JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);
