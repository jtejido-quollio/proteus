-- Phase 3: audit_events hardening for append-only, per-tenant hash-chain.

-- Ensure tenant audit sequence tracking exists.
CREATE TABLE IF NOT EXISTS tenant_audit_seq (
  tenant_id TEXT PRIMARY KEY,
  seq BIGINT NOT NULL
);

-- Normalize columns.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'audit_events' AND column_name = 'ts'
  ) THEN
    ALTER TABLE audit_events RENAME COLUMN ts TO created_at;
  END IF;
END;
$$;

ALTER TABLE audit_events
  DROP CONSTRAINT IF EXISTS audit_events_tenant_id_fkey;

ALTER TABLE audit_events
  ALTER COLUMN tenant_id TYPE TEXT USING tenant_id::text;

UPDATE audit_events
  SET tenant_id = '__system__'
  WHERE tenant_id IS NULL;

ALTER TABLE audit_events
  ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE audit_events
  ADD COLUMN IF NOT EXISTS seq BIGINT,
  ADD COLUMN IF NOT EXISTS event_type TEXT,
  ADD COLUMN IF NOT EXISTS payload_json JSONB,
  ADD COLUMN IF NOT EXISTS payload_hash TEXT;

ALTER TABLE audit_events
  ALTER COLUMN created_at SET NOT NULL;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'audit_events' AND column_name = 'action'
  ) THEN
    UPDATE audit_events
      SET event_type = action
      WHERE event_type IS NULL AND action IS NOT NULL;
  END IF;
END;
$$;

ALTER TABLE audit_events
  DROP COLUMN IF EXISTS action;

UPDATE audit_events
  SET payload_json = '{}'::jsonb
  WHERE payload_json IS NULL;

UPDATE audit_events
  SET payload_hash = repeat('0', 64)
  WHERE payload_hash IS NULL;

UPDATE audit_events
  SET prev_event_hash = repeat('0', 64)
  WHERE prev_event_hash IS NULL;

-- Assign sequence numbers for existing rows if any.
WITH ordered AS (
  SELECT id, row_number() OVER (PARTITION BY tenant_id ORDER BY created_at, id) AS rn
  FROM audit_events
)
UPDATE audit_events
  SET seq = ordered.rn
  FROM ordered
  WHERE audit_events.id = ordered.id AND audit_events.seq IS NULL;

INSERT INTO tenant_audit_seq (tenant_id, seq)
  SELECT tenant_id, MAX(seq) FROM audit_events GROUP BY tenant_id
  ON CONFLICT (tenant_id) DO NOTHING;

ALTER TABLE audit_events
  ALTER COLUMN seq SET NOT NULL,
  ALTER COLUMN event_type SET NOT NULL,
  ALTER COLUMN payload_json SET NOT NULL,
  ALTER COLUMN payload_hash SET NOT NULL,
  ALTER COLUMN prev_event_hash SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_tenant_seq
  ON audit_events (tenant_id, seq);

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_tenant_event_hash
  ON audit_events (tenant_id, event_hash);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created
  ON audit_events (tenant_id, created_at);

CREATE INDEX IF NOT EXISTS idx_audit_events_event_type
  ON audit_events (tenant_id, event_type);

-- Append-only enforcement.
CREATE OR REPLACE FUNCTION audit_events_no_update_delete()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_events_no_update_delete ON audit_events;
CREATE TRIGGER audit_events_no_update_delete
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION audit_events_no_update_delete();
