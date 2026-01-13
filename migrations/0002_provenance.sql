-- Phase 2 schema: provenance artifacts and edges.

CREATE TABLE IF NOT EXISTS artifacts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  hash_alg TEXT NOT NULL,
  hash_value TEXT NOT NULL,
  media_type TEXT NOT NULL,
  uri TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, hash_alg, hash_value)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_tenant_hash
  ON artifacts (tenant_id, hash_value);

CREATE TABLE IF NOT EXISTS provenance_edges (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  manifest_id UUID NOT NULL REFERENCES manifests(id) ON DELETE CASCADE,
  edge_type TEXT NOT NULL,
  artifact_id UUID NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  kid TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_provenance_edges_manifest
  ON provenance_edges (tenant_id, manifest_id);

CREATE INDEX IF NOT EXISTS idx_provenance_edges_artifact
  ON provenance_edges (tenant_id, artifact_id);

CREATE INDEX IF NOT EXISTS idx_provenance_edges_type_artifact
  ON provenance_edges (tenant_id, edge_type, artifact_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_provenance_edges_artifact_unique
  ON provenance_edges (tenant_id, manifest_id, edge_type, artifact_id)
  WHERE artifact_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_provenance_edges_kid_unique
  ON provenance_edges (tenant_id, manifest_id, edge_type, kid)
  WHERE kid IS NOT NULL;
