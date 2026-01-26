-- Phase 4B schema: case management (cases, events, evidence, holds, escalations, assignments, queues, slas, exports, comments).

CREATE TABLE IF NOT EXISTS slas (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  target_seconds INT NULL,
  warn_after_seconds INT NULL,
  breach_after_seconds INT NOT NULL,
  schedule_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS queues (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NULL,
  default_sla_id UUID NULL REFERENCES slas(id) ON DELETE SET NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  priority INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_queues_tenant_active
  ON queues (tenant_id, is_active, priority);

CREATE TABLE IF NOT EXISTS cases (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source_type TEXT NOT NULL,
  source_ref_type TEXT NOT NULL,
  source_ref_hash TEXT NOT NULL,
  source_ref_raw TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, source_type, source_ref_hash)
);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_created
  ON cases (tenant_id, created_at);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_source_ref_hash
  ON cases (tenant_id, source_ref_hash);

CREATE TABLE IF NOT EXISTS case_state_projection (
  case_id UUID PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  queue_id UUID NULL REFERENCES queues(id) ON DELETE SET NULL,
  owner_type TEXT NULL,
  owner_id TEXT NULL,
  sla_id UUID NULL REFERENCES slas(id) ON DELETE SET NULL,
  sla_state TEXT NOT NULL DEFAULT 'active',
  sla_due_at TIMESTAMPTZ NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_case_state_tenant_queue_status_due
  ON case_state_projection (tenant_id, queue_id, status, sla_due_at, case_id);

CREATE INDEX IF NOT EXISTS idx_case_state_tenant_owner_status
  ON case_state_projection (tenant_id, owner_id, status, case_id);

CREATE INDEX IF NOT EXISTS idx_case_state_tenant_severity_status
  ON case_state_projection (tenant_id, severity, status, case_id);

CREATE INDEX IF NOT EXISTS idx_case_state_tenant_sla_state_due
  ON case_state_projection (tenant_id, sla_state, sla_due_at, case_id);

CREATE TABLE IF NOT EXISTS case_queue_projection (
  case_id UUID PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  queue_id UUID NULL REFERENCES queues(id) ON DELETE SET NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  owner_id TEXT NULL,
  sla_state TEXT NOT NULL DEFAULT 'active',
  sla_due_at TIMESTAMPTZ NULL,
  case_created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  projection_version BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_case_queue_tenant_queue_status_cursor
  ON case_queue_projection (tenant_id, queue_id, status, sla_due_at, case_created_at, case_id);

CREATE INDEX IF NOT EXISTS idx_case_queue_tenant_queue_owner_status_cursor
  ON case_queue_projection (tenant_id, queue_id, owner_id, status, case_created_at, case_id);

CREATE TABLE IF NOT EXISTS case_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  event_index BIGSERIAL,
  event_type TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT NULL,
  request_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  prev_event_hash TEXT NULL,
  event_hash TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_case_events_tenant_case_event_index
  ON case_events (tenant_id, case_id, event_index);

CREATE INDEX IF NOT EXISTS idx_case_events_tenant_case_created
  ON case_events (tenant_id, case_id, created_at);

CREATE INDEX IF NOT EXISTS idx_case_events_tenant_type_created
  ON case_events (tenant_id, event_type, created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_case_events_request_id
  ON case_events (tenant_id, case_id, request_id);

CREATE TABLE IF NOT EXISTS case_evidence_links (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  evidence_type TEXT NOT NULL,
  evidence_ref TEXT NOT NULL,
  evidence_hash TEXT NULL,
  added_by TEXT NULL,
  added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  UNIQUE (tenant_id, case_id, evidence_type, evidence_ref)
);

CREATE INDEX IF NOT EXISTS idx_case_evidence_links_case
  ON case_evidence_links (tenant_id, case_id);

CREATE INDEX IF NOT EXISTS idx_case_evidence_links_evidence
  ON case_evidence_links (tenant_id, evidence_type, evidence_ref);

CREATE TABLE IF NOT EXISTS case_policy_snapshots (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  bundle_id TEXT NOT NULL,
  bundle_hash TEXT NOT NULL,
  bundle_uri TEXT NULL,
  activated_at TIMESTAMPTZ NOT NULL,
  deactivated_at TIMESTAMPTZ NULL,
  actor_id TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE EXTENSION IF NOT EXISTS btree_gist;

ALTER TABLE case_policy_snapshots
  ADD CONSTRAINT no_overlap_policy_windows
  EXCLUDE USING gist (
    tenant_id WITH =,
    bundle_id WITH =,
    tstzrange(activated_at, COALESCE(deactivated_at, 'infinity'::timestamptz), '[)') WITH &&
  );

CREATE INDEX IF NOT EXISTS idx_case_policy_snapshots_tenant_bundle
  ON case_policy_snapshots (tenant_id, bundle_id, activated_at);

CREATE INDEX IF NOT EXISTS idx_case_policy_snapshots_tenant_active_window
  ON case_policy_snapshots (tenant_id, bundle_id, activated_at, deactivated_at);

CREATE INDEX IF NOT EXISTS idx_case_policy_snapshots_tenant_hash
  ON case_policy_snapshots (tenant_id, bundle_hash);

CREATE TABLE IF NOT EXISTS holds (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  hold_type TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  placed_by TEXT NULL,
  placed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  released_at TIMESTAMPTZ NULL,
  release_reason TEXT NULL,
  hold_until TIMESTAMPTZ NULL,
  request_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_holds_case_status
  ON holds (tenant_id, case_id, status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_holds_request_id
  ON holds (tenant_id, case_id, request_id);

CREATE TABLE IF NOT EXISTS escalations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  from_queue_id UUID NULL REFERENCES queues(id) ON DELETE SET NULL,
  to_queue_id UUID NOT NULL REFERENCES queues(id) ON DELETE SET NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  escalated_by TEXT NULL,
  escalated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ NULL,
  request_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_escalations_case_status
  ON escalations (tenant_id, case_id, status);

CREATE INDEX IF NOT EXISTS idx_escalations_to_queue_status
  ON escalations (tenant_id, to_queue_id, status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_escalations_request_id
  ON escalations (tenant_id, case_id, request_id);

CREATE TABLE IF NOT EXISTS assignments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  assignee_type TEXT NOT NULL,
  assignee_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  assigned_by TEXT NULL,
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  unassigned_at TIMESTAMPTZ NULL,
  request_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assignments_assignee_status
  ON assignments (tenant_id, assignee_id, status);

CREATE INDEX IF NOT EXISTS idx_assignments_case_status
  ON assignments (tenant_id, case_id, status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_assignments_request_id
  ON assignments (tenant_id, case_id, request_id);

CREATE TABLE IF NOT EXISTS exports (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  format TEXT NOT NULL,
  requested_by TEXT NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ NULL,
  export_uri TEXT NULL,
  export_hash TEXT NULL,
  error_code TEXT NULL,
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exports_case
  ON exports (tenant_id, case_id);

CREATE INDEX IF NOT EXISTS idx_exports_status_created
  ON exports (tenant_id, status, requested_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_exports_request_id
  ON exports (tenant_id, case_id, request_id);

CREATE TABLE IF NOT EXISTS comments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  author_type TEXT NOT NULL,
  author_id TEXT NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  request_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_comments_case_created
  ON comments (tenant_id, case_id, created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_comments_request_id
  ON comments (tenant_id, case_id, request_id);

-- Append-only enforcement for canonical and evidence tables.
CREATE OR REPLACE FUNCTION cases_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'cases is immutable';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS cases_no_update_delete ON cases;
CREATE TRIGGER cases_no_update_delete
BEFORE UPDATE OR DELETE ON cases
FOR EACH ROW EXECUTE FUNCTION cases_no_update_delete();

CREATE OR REPLACE FUNCTION case_events_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'case_events is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS case_events_no_update_delete ON case_events;
CREATE TRIGGER case_events_no_update_delete
BEFORE UPDATE OR DELETE ON case_events
FOR EACH ROW EXECUTE FUNCTION case_events_no_update_delete();

CREATE OR REPLACE FUNCTION case_evidence_links_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'case_evidence_links is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS case_evidence_links_no_update_delete ON case_evidence_links;
CREATE TRIGGER case_evidence_links_no_update_delete
BEFORE UPDATE OR DELETE ON case_evidence_links
FOR EACH ROW EXECUTE FUNCTION case_evidence_links_no_update_delete();

CREATE OR REPLACE FUNCTION case_policy_snapshots_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'case_policy_snapshots is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS case_policy_snapshots_no_update_delete ON case_policy_snapshots;
CREATE TRIGGER case_policy_snapshots_no_update_delete
BEFORE UPDATE OR DELETE ON case_policy_snapshots
FOR EACH ROW EXECUTE FUNCTION case_policy_snapshots_no_update_delete();

CREATE OR REPLACE FUNCTION comments_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'comments is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS comments_no_update_delete ON comments;
CREATE TRIGGER comments_no_update_delete
BEFORE UPDATE OR DELETE ON comments
FOR EACH ROW EXECUTE FUNCTION comments_no_update_delete();

CREATE OR REPLACE FUNCTION holds_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'holds is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS holds_no_update_delete ON holds;
CREATE TRIGGER holds_no_update_delete
BEFORE UPDATE OR DELETE ON holds
FOR EACH ROW EXECUTE FUNCTION holds_no_update_delete();

CREATE OR REPLACE FUNCTION escalations_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'escalations is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS escalations_no_update_delete ON escalations;
CREATE TRIGGER escalations_no_update_delete
BEFORE UPDATE OR DELETE ON escalations
FOR EACH ROW EXECUTE FUNCTION escalations_no_update_delete();

CREATE OR REPLACE FUNCTION assignments_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'assignments is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS assignments_no_update_delete ON assignments;
CREATE TRIGGER assignments_no_update_delete
BEFORE UPDATE OR DELETE ON assignments
FOR EACH ROW EXECUTE FUNCTION assignments_no_update_delete();

CREATE OR REPLACE FUNCTION exports_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'exports is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS exports_no_update_delete ON exports;
CREATE TRIGGER exports_no_update_delete
BEFORE UPDATE OR DELETE ON exports
FOR EACH ROW EXECUTE FUNCTION exports_no_update_delete();
