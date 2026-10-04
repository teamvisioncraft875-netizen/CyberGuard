-- ======================================================================================
-- CYBERGUARD Migration 013: Create agent_firewall_rules table & RLS policies
-- Immutable log and lifecycle management for firewall rules created by agents.
-- ======================================================================================

CREATE TABLE IF NOT EXISTS public.agent_firewall_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID NOT NULL REFERENCES public.devices(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  rule_type TEXT NOT NULL CHECK (rule_type IN ('block_ip', 'block_domain')),
  target_ip TEXT NULL,
  target_domain TEXT NULL,
  rule_id_local TEXT NULL, -- Windows DisplayName or Linux rule hash
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
    'pending',
    'active',
    'pending_delete',
    'deleted'
  )),
  created_by_id UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NULL,
  deleted_at TIMESTAMPTZ NULL,
  result JSONB NOT NULL DEFAULT '{}'::jsonb -- stores firewall command output
);

-- Table Comment
COMMENT ON TABLE public.agent_firewall_rules IS 'Immutable log of firewall rules created by agents. Status tracks lifecycle. expires_at auto-deletes stale rules.';

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_agent_firewall_rules_agent_status
  ON public.agent_firewall_rules (agent_id, status);

CREATE INDEX IF NOT EXISTS idx_agent_firewall_rules_org_type
  ON public.agent_firewall_rules (organization_id, rule_type);

CREATE INDEX IF NOT EXISTS idx_agent_firewall_rules_target_ip
  ON public.agent_firewall_rules (target_ip);

CREATE INDEX IF NOT EXISTS idx_agent_firewall_rules_target_domain
  ON public.agent_firewall_rules (target_domain);

CREATE INDEX IF NOT EXISTS idx_agent_firewall_rules_expires_at
  ON public.agent_firewall_rules (expires_at);

-- RLS: Admins can read/delete/write their org's rules
ALTER TABLE public.agent_firewall_rules ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "agent_firewall_rules_admin_all" ON public.agent_firewall_rules;
CREATE POLICY "agent_firewall_rules_admin_all"
ON public.agent_firewall_rules
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
