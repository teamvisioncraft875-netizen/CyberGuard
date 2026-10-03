-- ======================================================================================
-- CYBERGUARD Migration 012: Create agent_commands table & RLS policies
-- ======================================================================================

CREATE TABLE IF NOT EXISTS public.agent_commands (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES public.devices(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  command_type TEXT NOT NULL CHECK (command_type IN (
    'collect_snapshot',
    'refresh_policy',
    'temporary_block_ip'
  )),
  target_data JSONB NOT NULL DEFAULT '{}'::jsonb,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
    'pending',
    'executing',
    'completed',
    'failed'
  )),
  requested_by_id UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
  executed_at TIMESTAMPTZ NULL,
  result JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_agent_commands_device_status 
  ON public.agent_commands (device_id, status);

CREATE INDEX IF NOT EXISTS idx_agent_commands_org_status 
  ON public.agent_commands (organization_id, status);

CREATE INDEX IF NOT EXISTS idx_agent_commands_created_at 
  ON public.agent_commands (created_at DESC);

-- RLS: Admins can read/write their org's commands
ALTER TABLE public.agent_commands ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "agent_commands_admin_all" ON public.agent_commands;
CREATE POLICY "agent_commands_admin_all"
ON public.agent_commands
FOR ALL
TO authenticated
USING (
  organization_id IS NOT NULL
  AND organization_id = get_auth_org_id()
  AND is_admin()
)
WITH CHECK (
  organization_id IS NOT NULL
  AND organization_id = get_auth_org_id()
  AND is_admin()
);
