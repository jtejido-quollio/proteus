-- Phase 3 schema: append-only audit events with optional hash-chain.

CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id UUID NULL REFERENCES tenants(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_type TEXT NOT NULL,
  actor_id_hash TEXT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NULL,
  request_hash TEXT NULL,
  result TEXT NOT NULL,
  error_code TEXT NULL,
  prev_event_hash TEXT NULL,
  event_hash TEXT NOT NULL
);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'audit_events' AND column_name = 'created_at'
  ) THEN
    CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created
      ON audit_events (tenant_id, created_at);
  ELSIF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'audit_events' AND column_name = 'ts'
  ) THEN
    CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_ts
      ON audit_events (tenant_id, ts);
  END IF;
END;
$$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'audit_events' AND column_name = 'action'
  ) THEN
    CREATE INDEX IF NOT EXISTS idx_audit_events_action
      ON audit_events (tenant_id, action);
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_audit_events_target
  ON audit_events (tenant_id, target_type, target_id);
