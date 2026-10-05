-- ======================================================================================
-- CYBERGUARD Migration 023: Create Threat Intelligence Tables & Security Policies
-- ======================================================================================

-- 1. Threat Feeds Registry
CREATE TABLE IF NOT EXISTS public.threat_feeds (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id             UUID NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  feed_name                   TEXT NOT NULL,
  feed_slug                   TEXT NOT NULL,
  feed_type                   TEXT NOT NULL CHECK (feed_type IN ('abuseipdb', 'virustotal', 'otx', 'misp', 'stix_taxii', 'csv', 'json_custom', 'text', 'plain_text')),
  feed_url                    TEXT NOT NULL,
  auth_config                 JSONB NOT NULL DEFAULT '{}'::jsonb,
  polling_frequency_minutes   INTEGER NOT NULL DEFAULT 60 CHECK (polling_frequency_minutes >= 5),
  confidence_weight           NUMERIC(4,3) NOT NULL DEFAULT 1.000 CHECK (confidence_weight >= 0.000 AND confidence_weight <= 1.000),
  is_enabled                  BOOLEAN NOT NULL DEFAULT true,
  last_sync_at                TIMESTAMPTZ NULL,
  next_sync_due_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  sync_status                 TEXT NOT NULL DEFAULT 'idle' CHECK (sync_status IN ('idle', 'in_progress', 'success', 'failed', 'circuit_broken')),
  consecutive_failures        INTEGER NOT NULL DEFAULT 0,
  last_error                  TEXT NULL,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial unique indexes for threat_feeds (global vs tenant-scoped)
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_feeds_global_slug 
  ON public.threat_feeds (feed_slug) 
  WHERE organization_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_feeds_tenant_slug 
  ON public.threat_feeds (organization_id, feed_slug) 
  WHERE organization_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_threat_feeds_org 
  ON public.threat_feeds (organization_id);

CREATE INDEX IF NOT EXISTS idx_threat_feeds_next_sync 
  ON public.threat_feeds (next_sync_due_at) 
  WHERE is_enabled = true;

-- 2. Threat Indicators (IOC Master Store)
CREATE TABLE IF NOT EXISTS public.threat_indicators (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id             UUID NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  feed_id                     UUID NULL REFERENCES public.threat_feeds(id) ON DELETE SET NULL,
  indicator_type              TEXT NOT NULL CHECK (indicator_type IN ('ip', 'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256')),
  indicator_value             TEXT NOT NULL,
  threat_actor                TEXT NULL,
  malware_family              TEXT NULL,
  severity                    TEXT NOT NULL DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  confidence_score            INTEGER NOT NULL DEFAULT 50 CHECK (confidence_score >= 0 AND confidence_score <= 100),
  tags                        TEXT[] NOT NULL DEFAULT '{}'::text[],
  observation_count           INTEGER NOT NULL DEFAULT 1,
  first_seen_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at                  TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '30 days'),
  is_active                   BOOLEAN NOT NULL DEFAULT true,
  metadata                    JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial unique indexes ensuring deduplication within global and tenant namespaces
CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_indicators_global 
  ON public.threat_indicators (indicator_type, indicator_value) 
  WHERE organization_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_threat_indicators_tenant 
  ON public.threat_indicators (organization_id, indicator_type, indicator_value) 
  WHERE organization_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_threat_indicators_lookup 
  ON public.threat_indicators (indicator_type, indicator_value) 
  WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_threat_indicators_org 
  ON public.threat_indicators (organization_id);

CREATE INDEX IF NOT EXISTS idx_threat_indicators_feed 
  ON public.threat_indicators (feed_id);

CREATE INDEX IF NOT EXISTS idx_threat_indicators_expires 
  ON public.threat_indicators (expires_at) 
  WHERE is_active = true;

-- 3. Incident IOC Matches (Correlation Junction)
CREATE TABLE IF NOT EXISTS public.incident_ioc_matches (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id             UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  incident_id                 UUID NOT NULL REFERENCES public.incidents(id) ON DELETE CASCADE,
  indicator_id                UUID NOT NULL REFERENCES public.threat_indicators(id) ON DELETE RESTRICT,
  signal_id                   UUID NULL REFERENCES public.detection_signals(id) ON DELETE SET NULL,
  matched_value               TEXT NOT NULL,
  match_context               TEXT NOT NULL CHECK (match_context IN ('source_ip', 'destination_ip', 'url_domain', 'url_path', 'payload_hash', 'listening_port_ip', 'message_body', 'raw_input')),
  reputation_score            INTEGER NOT NULL CHECK (reputation_score >= 0 AND reputation_score <= 100),
  severity                    TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  feed_source                 TEXT NOT NULL,
  matched_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata                    JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_incident_ioc_match 
  ON public.incident_ioc_matches (incident_id, indicator_id, match_context);

CREATE INDEX IF NOT EXISTS idx_incident_ioc_matches_org_inc 
  ON public.incident_ioc_matches (organization_id, incident_id);

CREATE INDEX IF NOT EXISTS idx_incident_ioc_matches_indicator 
  ON public.incident_ioc_matches (indicator_id);

CREATE INDEX IF NOT EXISTS idx_incident_ioc_matches_matched_at 
  ON public.incident_ioc_matches (matched_at DESC);

-- 4. Row-Level Security (RLS) Enablement & Tenant Policies
ALTER TABLE public.threat_feeds ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_ioc_matches ENABLE ROW LEVEL SECURITY;

-- 4.1 threat_feeds policies
DROP POLICY IF EXISTS "threat_feeds_select" ON public.threat_feeds;
CREATE POLICY "threat_feeds_select"
ON public.threat_feeds FOR SELECT TO authenticated
USING (
  organization_id IS NULL
  OR (organization_id = get_auth_org_id())
);

DROP POLICY IF EXISTS "threat_feeds_admin_modify" ON public.threat_feeds;
CREATE POLICY "threat_feeds_admin_modify"
ON public.threat_feeds FOR ALL TO authenticated
USING (
  organization_id IS NOT NULL
  AND organization_id = get_auth_org_id()
  AND is_admin()
);

-- 4.2 threat_indicators policies
DROP POLICY IF EXISTS "threat_indicators_select" ON public.threat_indicators;
CREATE POLICY "threat_indicators_select"
ON public.threat_indicators FOR SELECT TO authenticated
USING (
  organization_id IS NULL
  OR (organization_id = get_auth_org_id())
);

DROP POLICY IF EXISTS "threat_indicators_admin_modify" ON public.threat_indicators;
CREATE POLICY "threat_indicators_admin_modify"
ON public.threat_indicators FOR ALL TO authenticated
USING (
  organization_id IS NOT NULL
  AND organization_id = get_auth_org_id()
  AND is_admin()
);

-- 4.3 incident_ioc_matches policies
DROP POLICY IF EXISTS "incident_ioc_matches_select" ON public.incident_ioc_matches;
CREATE POLICY "incident_ioc_matches_select"
ON public.incident_ioc_matches FOR SELECT TO authenticated
USING (
  organization_id = get_auth_org_id()
);

DROP POLICY IF EXISTS "incident_ioc_matches_admin_modify" ON public.incident_ioc_matches;
CREATE POLICY "incident_ioc_matches_admin_modify"
ON public.incident_ioc_matches FOR ALL TO authenticated
USING (
  organization_id = get_auth_org_id()
  AND is_admin()
);

COMMENT ON TABLE public.threat_feeds IS 'Threat intelligence providers and synchronization parameters';
COMMENT ON TABLE public.threat_indicators IS 'Master indicator of compromise (IOC) catalog for IP, domain, URL, and hash reputation';
COMMENT ON TABLE public.incident_ioc_matches IS 'Forensic correlation records between detection incidents and known threat indicators';
