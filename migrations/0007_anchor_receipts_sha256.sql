-- Phase 3: store provider receipt sha256 for anchor receipts.

ALTER TABLE anchor_receipts
  ADD COLUMN IF NOT EXISTS provider_receipt_sha256 TEXT;

UPDATE anchor_receipts
  SET provider_receipt_sha256 = ''
  WHERE provider_receipt_sha256 IS NULL;

ALTER TABLE anchor_receipts
  ALTER COLUMN provider_receipt_sha256 SET NOT NULL,
  ALTER COLUMN provider_receipt_sha256 SET DEFAULT '';
