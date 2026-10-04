-- ======================================================================================
-- CYBERGUARD Migration 011: Extend devices table for Enterprise Agent v1
-- ======================================================================================

-- 1. Ensure user_id is nullable (enterprise devices enroll before human user assignment)
ALTER TABLE public.devices ALTER COLUMN user_id DROP NOT NULL;

-- 2. Add organization_id for multi-tenant isolation
ALTER TABLE public.devices 
  ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE;

-- 3. Add enterprise agent identity and enrollment columns
ALTER TABLE public.devices
  ADD COLUMN IF NOT EXISTS enrollment_token TEXT NULL,
  ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS agent_credentials_id UUID NULL,
  ADD COLUMN IF NOT EXISTS agent_credentials_hash TEXT NULL,
  ADD COLUMN IF NOT EXISTS agent_version TEXT DEFAULT '1.0.0',
  ADD COLUMN IF NOT EXISTS hostname TEXT NULL,
  ADD COLUMN IF NOT EXISTS os TEXT NULL,
  ADD COLUMN IF NOT EXISTS platform TEXT NULL,
  ADD COLUMN IF NOT EXISTS last_heartbeat TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS policy_version INT DEFAULT 0;

-- 4. Set status default to 'pending' and add lifecycle constraint
ALTER TABLE public.devices ALTER COLUMN status SET DEFAULT 'pending';

-- Drop existing status check constraint if any exists
ALTER TABLE public.devices DROP CONSTRAINT IF EXISTS devices_status_check;

ALTER TABLE public.devices 
  ADD CONSTRAINT devices_status_check 
  CHECK (status IN ('pending', 'online', 'offline', 'disabled', 'active', 'suspended', 'isolated'));

-- 5. Add unique constraints for tokens and agent credentials
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'devices_enrollment_token_key'
  ) THEN
    ALTER TABLE public.devices ADD CONSTRAINT devices_enrollment_token_key UNIQUE (enrollment_token);
  END IF;
  
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'devices_agent_credentials_id_key'
  ) THEN
    ALTER TABLE public.devices ADD CONSTRAINT devices_agent_credentials_id_key UNIQUE (agent_credentials_id);
  END IF;
END $$;

-- 6. Indexes for high-throughput lookup
CREATE INDEX IF NOT EXISTS idx_devices_enrollment_token 
  ON public.devices (enrollment_token) WHERE enrollment_token IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devices_agent_credentials_id 
  ON public.devices (agent_credentials_id) WHERE agent_credentials_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_devices_org_status 
  ON public.devices (organization_id, status);

CREATE INDEX IF NOT EXISTS idx_devices_last_heartbeat 
  ON public.devices (last_heartbeat);

COMMENT ON COLUMN public.devices.status IS 
  'Status lifecycle: pending (pre-enrollment) -> online (active heartbeat) -> offline (missed heartbeats) -> disabled (admin action or compromised)';
