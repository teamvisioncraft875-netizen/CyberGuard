-- ======================================================================================
-- CYBERGUARD Migration 030: SIEM Foundation & Unified Event Ingestion Platform
-- ======================================================================================

-- 1. Extend source_type enum to include 'siem' if not already present
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_enum e 
    JOIN pg_type t ON e.enumtypid = t.oid 
    WHERE t.typname = 'source_type' AND e.enumlabel = 'siem'
  ) THEN
    ALTER TYPE public.source_type ADD VALUE 'siem';
  END IF;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

-- 2. Event Sources Table
CREATE TABLE IF NOT EXISTS public.event_sources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  source_name VARCHAR(255) NOT NULL,
  source_type VARCHAR(100) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'degraded', 'error')),
  last_seen_at TIMESTAMPTZ NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_event_sources_org
  ON public.event_sources(organization_id);

CREATE INDEX IF NOT EXISTS idx_event_sources_type
  ON public.event_sources(organization_id, source_type);

CREATE INDEX IF NOT EXISTS idx_event_sources_status
  ON public.event_sources(organization_id, status);

-- 3. Security Events Table
CREATE TABLE IF NOT EXISTS public.security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  source_id UUID NULL REFERENCES public.event_sources(id) ON DELETE SET NULL,
  event_timestamp TIMESTAMPTZ NOT NULL,
  source_type VARCHAR(100) NOT NULL,
  event_type VARCHAR(150) NOT NULL,
  severity VARCHAR(50) NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  device_id UUID NULL REFERENCES public.devices(id) ON DELETE SET NULL,
  user_id UUID NULL REFERENCES public.users(id) ON DELETE SET NULL,
  raw_event JSONB NOT NULL,
  normalized_event JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Core High-Performance B-Tree Indexes for Millions of Events
CREATE INDEX IF NOT EXISTS idx_security_events_org_timestamp
  ON public.security_events(organization_id, event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_org_event_type
  ON public.security_events(organization_id, event_type);

CREATE INDEX IF NOT EXISTS idx_security_events_org_source_type
  ON public.security_events(organization_id, source_type);

CREATE INDEX IF NOT EXISTS idx_security_events_org_severity
  ON public.security_events(organization_id, severity);

CREATE INDEX IF NOT EXISTS idx_security_events_org_device
  ON public.security_events(organization_id, device_id);

CREATE INDEX IF NOT EXISTS idx_security_events_org_user
  ON public.security_events(organization_id, user_id);

-- GIN index for search within normalized_event JSONB
CREATE INDEX IF NOT EXISTS idx_security_events_normalized_gin
  ON public.security_events USING GIN (normalized_event);

-- 4. Event Ingestion Jobs Table
CREATE TABLE IF NOT EXISTS public.event_ingestion_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  source_id UUID NULL REFERENCES public.event_sources(id) ON DELETE SET NULL,
  total_events INTEGER NOT NULL DEFAULT 0,
  successful_events INTEGER NOT NULL DEFAULT 0,
  failed_events INTEGER NOT NULL DEFAULT 0,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'completed' CHECK (status IN ('in_progress', 'completed', 'failed', 'partial')),
  error_details JSONB NULL
);

CREATE INDEX IF NOT EXISTS idx_event_ingestion_jobs_org
  ON public.event_ingestion_jobs(organization_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_event_ingestion_jobs_source
  ON public.event_ingestion_jobs(source_id);
