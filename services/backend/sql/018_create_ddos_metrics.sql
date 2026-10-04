-- ======================================================================================
-- CYBERGUARD Migration 018: Create ddos_metrics table & add ddos enums
-- ======================================================================================

-- 1. Ensure threat_type enum includes 'ddos' and incidents can be org-scoped (nullable user_id)
ALTER TYPE threat_type ADD VALUE IF NOT EXISTS 'ddos';
ALTER TABLE public.incidents ALTER COLUMN user_id DROP NOT NULL;

-- 2. Create ddos_metrics table
CREATE TABLE IF NOT EXISTS public.ddos_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE,
  metric_type TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  endpoint TEXT,
  count INT NOT NULL DEFAULT 1,
  window_start TIMESTAMPTZ NOT NULL,
  window_end TIMESTAMPTZ NOT NULL,
  threshold_exceeded BOOLEAN NOT NULL DEFAULT false,
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT chk_ddos_metrics_type CHECK (metric_type IN ('request_spike', 'post_flood', 'login_abuse', 'ip_flooding'))
);

-- 3. Indexes for fast aggregation and auditing
CREATE INDEX IF NOT EXISTS idx_ddos_metrics_org_type ON public.ddos_metrics (organization_id, metric_type);
CREATE INDEX IF NOT EXISTS idx_ddos_metrics_source_ip_created_at ON public.ddos_metrics (source_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ddos_metrics_window ON public.ddos_metrics (window_start, window_end);
