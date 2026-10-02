-- ======================================================================================
-- CYBERGUARD Migration 006: Create Append-Only Audit Logs Table & Indexes
-- ======================================================================================
-- Note: An older legacy table 'audit_log' (singular) may exist in the database.
-- Do NOT drop the legacy table. This migration establishes the canonical 'audit_logs' table.

CREATE TABLE IF NOT EXISTS public.audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  user_id UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
  actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'admin', 'system_policy', 'system_guard')),
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip_address TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Optimized query indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_org_created_at ON public.audit_logs (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON public.audit_logs (resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON public.audit_logs (action);


-- Row Level Security (RLS)
-- NOTE: RLS is future-proofing because the gateway connects with a BYPASSRLS role,
-- so real enforcement is in application code.
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "audit_logs_select_policy" ON public.audit_logs;
CREATE POLICY "audit_logs_select_policy"
ON public.audit_logs
FOR SELECT
TO authenticated
USING (
  organization_id IS NOT NULL
  AND organization_id = get_auth_org_id()
  AND is_admin()
);

DROP POLICY IF EXISTS "audit_logs_insert_policy" ON public.audit_logs;
CREATE POLICY "audit_logs_insert_policy"
ON public.audit_logs
FOR INSERT
TO authenticated
WITH CHECK (true);

-- Explicitly append-only: NO update or delete policies exist for audit_logs.
