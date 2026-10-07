-- =========================================================================
-- CYBERGUARD DATABASE MIGRATION 037: SOAR CONNECTORS & ENTERPRISE INTEGRATIONS
-- =========================================================================

-- 1. SOAR CONNECTORS TABLE
CREATE TABLE IF NOT EXISTS public.soar_connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- webhook, jira, slack, teams, custom
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- active, disabled, error
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_default BOOLEAN NOT NULL DEFAULT false,
    health_status JSONB NOT NULL DEFAULT '{"status": "unknown"}'::jsonb,
    last_health_check TIMESTAMPTZ,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_connectors_org_type 
    ON public.soar_connectors (organization_id, type);

CREATE INDEX IF NOT EXISTS idx_soar_connectors_org_status 
    ON public.soar_connectors (organization_id, status);

CREATE INDEX IF NOT EXISTS idx_soar_connectors_default 
    ON public.soar_connectors (organization_id, is_default) WHERE is_default = true;

-- 2. SOAR CONNECTOR LOGS (AUDIT TRAIL & RESPONSE LOGGING)
CREATE TABLE IF NOT EXISTS public.soar_connector_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connector_id UUID REFERENCES public.soar_connectors(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    action VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL, -- success, failed, error
    request_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    external_id VARCHAR(255),
    duration_ms INT DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_connector_logs_conn 
    ON public.soar_connector_logs (connector_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_soar_connector_logs_org 
    ON public.soar_connector_logs (organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_soar_connector_logs_external 
    ON public.soar_connector_logs (external_id);

-- 3. TRIGGER TO AUTOMATICALLY UPDATE updated_at
CREATE OR REPLACE FUNCTION public.set_soar_connectors_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_soar_connectors_updated_at ON public.soar_connectors;
CREATE TRIGGER trg_soar_connectors_updated_at
BEFORE UPDATE ON public.soar_connectors
FOR EACH ROW
EXECUTE FUNCTION public.set_soar_connectors_updated_at();
