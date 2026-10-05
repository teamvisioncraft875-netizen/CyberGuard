-- ======================================================================================
-- CYBERGUARD Migration 028: Attack Chain Engine & MITRE Progression Analysis
-- ======================================================================================

CREATE TABLE IF NOT EXISTS public.attack_chain_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  organization_id UUID NOT NULL
    REFERENCES public.organizations(id)
    ON DELETE CASCADE,

  root_incident_id UUID NOT NULL
    REFERENCES public.incidents(id)
    ON DELETE CASCADE,

  attack_chain_group_id UUID NULL
    REFERENCES public.incident_groups(id)
    ON DELETE CASCADE,

  confidence_score NUMERIC(4,3)
    NOT NULL DEFAULT 0.800,

  chain_length INTEGER NOT NULL DEFAULT 1,

  timeline JSONB NOT NULL DEFAULT '[]'::jsonb,

  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attack_chain_snapshots_org
  ON public.attack_chain_snapshots(organization_id);

CREATE INDEX IF NOT EXISTS idx_attack_chain_snapshots_root
  ON public.attack_chain_snapshots(root_incident_id);
