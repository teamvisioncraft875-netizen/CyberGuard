-- CYBERGUARD Migration 032: SIEM Phase 3 — Real-Time SOC Monitoring & Alert Lifecycle Platform
-- Adds siem_alerts table for alert lifecycle management, MTTR/MTTD analytics, and analyst queues

CREATE TABLE IF NOT EXISTS public.siem_alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  hit_id UUID REFERENCES public.siem_detection_hits(id) ON DELETE SET NULL,
  incident_id UUID REFERENCES public.incidents(id) ON DELETE SET NULL,
  rule_id UUID REFERENCES public.siem_detection_rules(id) ON DELETE SET NULL,
  title VARCHAR(255) NOT NULL,
  severity VARCHAR(50) NOT NULL DEFAULT 'medium',
  status VARCHAR(50) NOT NULL DEFAULT 'new',
  assigned_analyst UUID REFERENCES public.users(id) ON DELETE SET NULL,
  notes TEXT,
  resolution TEXT,
  mitre_technique VARCHAR(100),
  source_type VARCHAR(100),
  rule_code VARCHAR(100),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  investigating_at TIMESTAMPTZ,
  contained_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_siem_alerts_org ON public.siem_alerts(organization_id);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_status ON public.siem_alerts(status);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_severity ON public.siem_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_created_at ON public.siem_alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_org_status_sev ON public.siem_alerts(organization_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_analyst ON public.siem_alerts(assigned_analyst);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_incident ON public.siem_alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_hit ON public.siem_alerts(hit_id);
