-- CYBERGUARD Migration 034: SIEM Phase 5 — Threat Intelligence & IOC Management Platform
-- Stores Indicators of Compromise (IOCs), tracks real-time sightings, and enriches detection telemetry.

CREATE TABLE IF NOT EXISTS public.threat_iocs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  ioc_type VARCHAR(50) NOT NULL, -- 'ip', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email', 'hostname'
  ioc_value TEXT NOT NULL,
  confidence INTEGER DEFAULT 50 CHECK (confidence >= 0 AND confidence <= 100),
  risk_score INTEGER DEFAULT 50 CHECK (risk_score >= 0 AND risk_score <= 100),
  threat_actor TEXT,
  malware_family TEXT,
  campaign_name TEXT,
  source_name TEXT,
  first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expiration_date TIMESTAMP WITH TIME ZONE NULL,
  tags JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  CONSTRAINT uq_threat_iocs_org_type_val UNIQUE (organization_id, ioc_type, ioc_value)
);

CREATE INDEX IF NOT EXISTS idx_threat_iocs_org_type
  ON public.threat_iocs(organization_id, ioc_type);

CREATE INDEX IF NOT EXISTS idx_threat_iocs_org_val_lower
  ON public.threat_iocs(organization_id, lower(ioc_value));

CREATE INDEX IF NOT EXISTS idx_threat_iocs_org_risk_desc
  ON public.threat_iocs(organization_id, risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_threat_iocs_org_exp
  ON public.threat_iocs(organization_id, expiration_date);

CREATE TABLE IF NOT EXISTS public.threat_ioc_sightings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  ioc_id UUID NOT NULL REFERENCES public.threat_iocs(id) ON DELETE CASCADE,
  event_id UUID NULL REFERENCES public.security_events(id) ON DELETE SET NULL,
  detection_id UUID NULL,
  matched_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  source_ip TEXT,
  destination_ip TEXT,
  user_name TEXT,
  asset_name TEXT,
  metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_threat_ioc_sightings_org_matched_desc
  ON public.threat_ioc_sightings(organization_id, matched_at DESC);

CREATE INDEX IF NOT EXISTS idx_threat_ioc_sightings_ioc_id
  ON public.threat_ioc_sightings(ioc_id);
