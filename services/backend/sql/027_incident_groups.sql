-- ======================================================================================
-- CYBERGUARD Migration 027: Incident Groups & Campaign Aggregation
-- ======================================================================================

-- 1. incident_groups
CREATE TABLE IF NOT EXISTS public.incident_groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  organization_id UUID NOT NULL
    REFERENCES public.organizations(id)
    ON DELETE CASCADE,

  title TEXT NOT NULL,

  description TEXT,

  group_type TEXT NOT NULL
    CHECK (
      group_type IN (
        'dedup_cluster',
        'campaign',
        'attack_chain',
        'distributed_attack'
      )
    ),

  status TEXT NOT NULL DEFAULT 'open'
    CHECK (
      status IN (
        'open',
        'investigating',
        'resolved'
      )
    ),

  severity TEXT NOT NULL DEFAULT 'medium'
    CHECK (
      severity IN (
        'low',
        'medium',
        'high',
        'critical'
      )
    ),

  confidence_score NUMERIC(4,3)
    NOT NULL DEFAULT 0.800,

  primary_incident_id UUID
    REFERENCES public.incidents(id)
    ON DELETE SET NULL,

  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_groups_org
  ON public.incident_groups(organization_id);

CREATE INDEX IF NOT EXISTS idx_incident_groups_status
  ON public.incident_groups(status);

-- 2. incident_group_members
CREATE TABLE IF NOT EXISTS public.incident_group_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  group_id UUID NOT NULL
    REFERENCES public.incident_groups(id)
    ON DELETE CASCADE,

  incident_id UUID NOT NULL
    REFERENCES public.incidents(id)
    ON DELETE CASCADE,

  added_by TEXT NOT NULL DEFAULT 'rule_engine'
    CHECK (
      added_by IN (
        'rule_engine',
        'ml_model',
        'analyst_manual'
      )
    ),

  confidence NUMERIC(4,3)
    NOT NULL DEFAULT 1.000,

  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT uq_group_incident_membership
    UNIQUE(group_id, incident_id)
);

CREATE INDEX IF NOT EXISTS idx_group_members_group
  ON public.incident_group_members(group_id);

CREATE INDEX IF NOT EXISTS idx_group_members_incident
  ON public.incident_group_members(incident_id);
