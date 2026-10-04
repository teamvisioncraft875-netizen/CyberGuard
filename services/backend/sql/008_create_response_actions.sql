-- ======================================================================================
-- CYBERGUARD Migration 008: Create Response Actions Table & Indexes
-- ======================================================================================

CREATE TABLE IF NOT EXISTS public.response_actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  incident_id UUID NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
  policy_id UUID NULL REFERENCES public.response_policies(id) ON DELETE SET NULL,
  action_type TEXT NOT NULL CHECK (action_type IN (
    'notify_admin',
    'notify_user',
    'revoke_session',
    'force_password_reset',
    'require_mfa',
    'block_ip',
    'block_domain',
    'suspend_device',
    'isolate_device'
  )),
  action_mode TEXT NOT NULL CHECK (action_mode IN ('shadow', 'live')),
  status TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN (
    'proposed',
    'pending_approval',
    'approved',
    'rejected',
    'executed',
    'failed',
    'expired',
    'rolled_back'
  )),
  requested_by_id UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
  approved_by_id UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
  approved_at TIMESTAMPTZ NULL,
  target JSONB NOT NULL DEFAULT '{}'::jsonb,
  result JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  scheduled_at TIMESTAMPTZ NULL,
  executed_at TIMESTAMPTZ NULL,
  expires_at TIMESTAMPTZ NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_response_actions_org_inc ON public.response_actions (organization_id, incident_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_status ON public.response_actions (status);
CREATE INDEX IF NOT EXISTS idx_response_actions_scheduled_at ON public.response_actions (scheduled_at);

-- RLS: admins see and manage their org's actions
ALTER TABLE public.response_actions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "response_actions_admin_all" ON public.response_actions;
CREATE POLICY "response_actions_admin_all"
ON public.response_actions
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
