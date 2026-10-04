-- ======================================================================================
-- CYBERGUARD: Migration 010 — Execution Metadata & Scheduling Indexes
-- ======================================================================================

-- 1. Add execution metadata columns to response_actions
ALTER TABLE public.response_actions 
  ADD COLUMN IF NOT EXISTS execution_attempts INT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_execution_error TEXT,
  ADD COLUMN IF NOT EXISTS executed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS result JSONB DEFAULT '{}'::jsonb;

-- 2. Index for background scheduler queries
CREATE INDEX IF NOT EXISTS idx_response_actions_status_scheduled 
  ON public.response_actions(status, scheduled_at);

-- 3. Ensure devices table has status and device_id columns (values: 'active', 'suspended', 'isolated')
ALTER TABLE public.devices 
  ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS device_id TEXT;

CREATE INDEX IF NOT EXISTS idx_devices_status 
  ON public.devices(status);

CREATE INDEX IF NOT EXISTS idx_devices_device_id 
  ON public.devices(device_id);
