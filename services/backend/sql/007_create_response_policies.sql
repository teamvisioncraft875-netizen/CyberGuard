-- ======================================================================================
-- CYBERGUARD Migration 007: Create Response Policies Table & Indexes
-- ======================================================================================

CREATE TABLE IF NOT EXISTS public.response_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_by_id UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  rules JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index: (organization_id, enabled)
CREATE INDEX IF NOT EXISTS idx_response_policies_org_enabled ON public.response_policies (organization_id, enabled);

-- Enable RLS: admins of the org can see and edit their own policies, others get 403
ALTER TABLE public.response_policies ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "response_policies_admin_all" ON public.response_policies;
CREATE POLICY "response_policies_admin_all"
ON public.response_policies
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
