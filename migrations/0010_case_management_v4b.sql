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
  source_ref TEXT NULL,
  idempotency_key TEXT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  queue_id UUID NULL REFERENCES queues(id) ON DELETE SET NULL,
  owner_type TEXT NULL,
  owner_id TEXT NULL,
  sla_id UUID NULL REFERENCES slas(id) ON DELETE SET NULL,
  sla_state TEXT NOT NULL DEFAULT 'active',
  sla_due_at TIMESTAMPTZ NULL,
  summary TEXT NULL,
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  resolved_at TIMESTAMPTZ NULL,
  closed_at TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_tenant_idempotency
  ON cases (tenant_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cases_tenant_queue_status_due
  ON cases (tenant_id, queue_id, status, sla_due_at, created_at);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_source
  ON cases (tenant_id, source_type, source_ref);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_owner_status
  ON cases (tenant_id, owner_id, status);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_severity_status
  ON cases (tenant_id, severity, status);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_sla_state_due
  ON cases (tenant_id, sla_state, sla_due_at);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_created
  ON cases (tenant_id, created_at);

CREATE TABLE IF NOT EXISTS case_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  event_index BIGSERIAL,
  event_type TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT NULL,
  request_id TEXT NULL,
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
  ON case_events (tenant_id, case_id, request_id)
  WHERE request_id IS NOT NULL;

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
  request_id TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_holds_case_status
  ON holds (tenant_id, case_id, status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_holds_request_id
  ON holds (tenant_id, case_id, request_id)
  WHERE request_id IS NOT NULL;

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
  request_id TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_escalations_case_status
  ON escalations (tenant_id, case_id, status);

CREATE INDEX IF NOT EXISTS idx_escalations_to_queue_status
  ON escalations (tenant_id, to_queue_id, status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_escalations_request_id
  ON escalations (tenant_id, case_id, request_id)
  WHERE request_id IS NOT NULL;

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
  request_id TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_assignments_assignee_status
  ON assignments (tenant_id, assignee_id, status);

CREATE INDEX IF NOT EXISTS idx_assignments_case_status
  ON assignments (tenant_id, case_id, status);

CREATE UNIQUE INDEX IF NOT EXISTS idx_assignments_request_id
  ON assignments (tenant_id, case_id, request_id)
  WHERE request_id IS NOT NULL;

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
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_exports_case
  ON exports (tenant_id, case_id);

CREATE INDEX IF NOT EXISTS idx_exports_status_created
  ON exports (tenant_id, status, requested_at);

CREATE TABLE IF NOT EXISTS comments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  author_type TEXT NOT NULL,
  author_id TEXT NULL,
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  request_id TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_comments_case_created
  ON comments (tenant_id, case_id, created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_comments_request_id
  ON comments (tenant_id, case_id, request_id)
  WHERE request_id IS NOT NULL;

-- Append-only enforcement for event and evidence tables.
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
