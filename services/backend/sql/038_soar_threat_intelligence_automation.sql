-- =========================================================================
-- CYBERGUARD DATABASE MIGRATION 038: SOAR THREAT INTEL AUTOMATION & RESPONSE OPTIMIZATION
-- =========================================================================

-- 1. SOAR RESPONSE RECOMMENDATIONS TABLE
CREATE TABLE IF NOT EXISTS public.soar_response_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES public.siem_alerts(id) ON DELETE CASCADE,
    case_id UUID REFERENCES public.soar_cases(id) ON DELETE CASCADE,
    ioc_id UUID REFERENCES public.threat_iocs(id) ON DELETE SET NULL,
    action_type VARCHAR(100) NOT NULL, -- block_ip, disable_account, isolate_endpoint, dns_sinkhole, create_ticket, escalate_approval, launch_playbook
    recommended_action VARCHAR(100) NOT NULL,
    action_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    confidence_score NUMERIC(5,2) NOT NULL DEFAULT 50.00 CHECK (confidence_score >= 0 AND confidence_score <= 100),
    risk_score INTEGER DEFAULT 50 CHECK (risk_score >= 0 AND risk_score <= 100),
    mitre_techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
    rationale TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, applied, dismissed, superseded
    applied_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    applied_at TIMESTAMPTZ,
    dismissed_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    dismissed_reason TEXT,
    dismissed_at TIMESTAMPTZ,
    execution_id UUID REFERENCES public.soar_executions(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_recommendations_org_status 
    ON public.soar_response_recommendations (organization_id, status);

CREATE INDEX IF NOT EXISTS idx_soar_recommendations_alert 
    ON public.soar_response_recommendations (alert_id);

CREATE INDEX IF NOT EXISTS idx_soar_recommendations_case 
    ON public.soar_response_recommendations (case_id);

CREATE INDEX IF NOT EXISTS idx_soar_recommendations_ioc 
    ON public.soar_response_recommendations (ioc_id);

-- 2. SOAR RESPONSE KNOWLEDGE BASE TABLE
CREATE TABLE IF NOT EXISTS public.soar_knowledge_base (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    summary TEXT,
    procedures JSONB NOT NULL DEFAULT '[]'::jsonb,
    investigation_notes TEXT,
    resolution_summary TEXT,
    lessons_learned TEXT,
    mitre_mappings JSONB NOT NULL DEFAULT '[]'::jsonb,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    linked_case_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    linked_playbook_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_kb_org 
    ON public.soar_knowledge_base (organization_id);

CREATE INDEX IF NOT EXISTS idx_soar_kb_tags 
    ON public.soar_knowledge_base USING GIN (tags);

CREATE INDEX IF NOT EXISTS idx_soar_kb_mitre 
    ON public.soar_knowledge_base USING GIN (mitre_mappings);

-- 3. TRIGGERS FOR updated_at
CREATE OR REPLACE FUNCTION public.set_soar_phase4_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_soar_recommendations_updated_at ON public.soar_response_recommendations;
CREATE TRIGGER trg_soar_recommendations_updated_at
BEFORE UPDATE ON public.soar_response_recommendations
FOR EACH ROW
EXECUTE FUNCTION public.set_soar_phase4_updated_at();

DROP TRIGGER IF EXISTS trg_soar_kb_updated_at ON public.soar_knowledge_base;
CREATE TRIGGER trg_soar_kb_updated_at
BEFORE UPDATE ON public.soar_knowledge_base
FOR EACH ROW
EXECUTE FUNCTION public.set_soar_phase4_updated_at();
