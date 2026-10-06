-- ======================================================================================
-- CYBERGUARD Migration 026: Incident Correlation Graph & Relationship Engine
-- ======================================================================================

CREATE TABLE IF NOT EXISTS public.incident_relationships (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  source_incident_id UUID NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
  target_incident_id UUID NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
  relationship_type TEXT NOT NULL CHECK (
    relationship_type IN (
      'shares_ioc',
      'same_attacker_ip',
      'same_host_progression',
      'same_user_campaign',
      'same_infrastructure',
      'attack_chain_step',
      'duplicate_of'
    )
  ),
  confidence_score NUMERIC(4,3) NOT NULL,
  rule_id TEXT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_no_self_references CHECK (source_incident_id != target_incident_id),
  CONSTRAINT uq_incident_relationships_edge UNIQUE (source_incident_id, target_incident_id, relationship_type)
);

-- Indexes for high-performance correlation queries and tenant isolation
CREATE INDEX IF NOT EXISTS idx_incident_relationships_org
  ON public.incident_relationships (organization_id);

CREATE INDEX IF NOT EXISTS idx_incident_relationships_source
  ON public.incident_relationships (source_incident_id);

CREATE INDEX IF NOT EXISTS idx_incident_relationships_target
  ON public.incident_relationships (target_incident_id);
