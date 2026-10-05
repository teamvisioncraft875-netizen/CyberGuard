-- ======================================================================================
-- CYBERGUARD Migration 025: Incident Deduplication Schema Extension
-- ======================================================================================

-- 1. Extend incidents table with deduplication and tracking columns
ALTER TABLE public.incidents
  ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64) NULL,
  ADD COLUMN IF NOT EXISTS device_id UUID NULL REFERENCES public.devices(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  ADD COLUMN IF NOT EXISTS occurrence_count INTEGER NOT NULL DEFAULT 1;

-- 2. Partial Index for Fast Open-Incident Fingerprint Lookup per Organization
CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint_org
  ON public.incidents (organization_id, fingerprint)
  WHERE status = 'open';

-- 3. Device Correlation Index
CREATE INDEX IF NOT EXISTS idx_incidents_device_id
  ON public.incidents (device_id);

-- 4. Temporal Index for Sliding Window Deduplication
CREATE INDEX IF NOT EXISTS idx_incidents_last_seen
  ON public.incidents (last_seen_at);
