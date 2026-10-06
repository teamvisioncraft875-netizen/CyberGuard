-- ======================================================================================
-- CYBERGUARD Migration 029: SOC Investigation, Intelligence & Response Platform
-- ======================================================================================

-- 1. Extend incidents table with workflow and prioritization columns
ALTER TABLE public.incidents
  ADD COLUMN IF NOT EXISTS priority VARCHAR(10) NOT NULL DEFAULT 'P3' CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
  ADD COLUMN IF NOT EXISTS assigned_to UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS assigned_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS escalated_at TIMESTAMPTZ NULL,
  ADD COLUMN IF NOT EXISTS baseline_severity VARCHAR(20) NULL;

-- 2. Incident Notes Table
CREATE TABLE IF NOT EXISTS public.incident_notes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  incident_id UUID NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
  user_id UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
  note TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_notes_incident
  ON public.incident_notes(incident_id);

CREATE INDEX IF NOT EXISTS idx_incident_notes_org
  ON public.incident_notes(organization_id);

-- 3. Incident Automated Response Recommendations Table
CREATE TABLE IF NOT EXISTS public.incident_recommendations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  incident_id UUID NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('P1', 'P2', 'P3', 'P4', 'low', 'medium', 'high', 'critical')),
  automatable BOOLEAN NOT NULL DEFAULT false,
  action_type TEXT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incident_recommendations_incident
  ON public.incident_recommendations(incident_id);

CREATE INDEX IF NOT EXISTS idx_incident_recommendations_org
  ON public.incident_recommendations(organization_id);

-- 4. High-Performance Query & Prioritization Indexes
CREATE INDEX IF NOT EXISTS idx_incidents_org_priority_status
  ON public.incidents(organization_id, priority, status);

CREATE INDEX IF NOT EXISTS idx_incidents_org_created
  ON public.incidents(organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_org_assigned
  ON public.incidents(organization_id, assigned_to);
