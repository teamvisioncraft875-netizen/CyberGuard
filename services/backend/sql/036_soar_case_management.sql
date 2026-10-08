-- =========================================================================
-- CYBERGUARD DATABASE MIGRATION 036: SOAR CASE MANAGEMENT & ADVANCED ORCHESTRATION
-- =========================================================================

-- 1. SOAR CASES TABLE
CREATE TABLE IF NOT EXISTS public.soar_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL DEFAULT 'medium',
    status VARCHAR(50) NOT NULL DEFAULT 'open', -- open, investigating, contained, resolved, closed
    priority VARCHAR(50) NOT NULL DEFAULT 'medium',
    assigned_to UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    alert_id UUID REFERENCES public.siem_alerts(id) ON DELETE SET NULL,
    incident_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    ioc_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    threat_intel_findings JSONB NOT NULL DEFAULT '{}'::jsonb,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_soar_cases_org_status 
    ON public.soar_cases (organization_id, status);

CREATE INDEX IF NOT EXISTS idx_soar_cases_org_severity 
    ON public.soar_cases (organization_id, severity);

CREATE INDEX IF NOT EXISTS idx_soar_cases_alert_id 
    ON public.soar_cases (alert_id);

CREATE INDEX IF NOT EXISTS idx_soar_cases_assigned_to 
    ON public.soar_cases (assigned_to);

-- 2. SOAR CASE EVIDENCE TABLE
CREATE TABLE IF NOT EXISTS public.soar_case_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES public.soar_cases(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    evidence_type VARCHAR(100) NOT NULL, -- action_result, remediation_output, execution_log, analyst_note, ioc_match, alert_snapshot
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    execution_id UUID REFERENCES public.soar_executions(id) ON DELETE SET NULL,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_case_evidence_case 
    ON public.soar_case_evidence (case_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_soar_case_evidence_org 
    ON public.soar_case_evidence (organization_id);

CREATE INDEX IF NOT EXISTS idx_soar_case_evidence_execution 
    ON public.soar_case_evidence (execution_id);

-- 3. APPROVAL SYSTEM EXTENSIONS (L1 Analyst, L2 Senior Analyst, L3 SOC Admin)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_approvals' AND column_name = 'level'
    ) THEN
        ALTER TABLE public.soar_approvals ADD COLUMN level VARCHAR(20) NOT NULL DEFAULT 'L1';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_approvals' AND column_name = 'escalated_to_level'
    ) THEN
        ALTER TABLE public.soar_approvals ADD COLUMN escalated_to_level VARCHAR(20) DEFAULT NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_approvals' AND column_name = 'expires_at'
    ) THEN
        ALTER TABLE public.soar_approvals ADD COLUMN expires_at TIMESTAMPTZ DEFAULT NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_approvals' AND column_name = 'is_expired'
    ) THEN
        ALTER TABLE public.soar_approvals ADD COLUMN is_expired BOOLEAN NOT NULL DEFAULT false;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_approvals' AND column_name = 'rejection_comment'
    ) THEN
        ALTER TABLE public.soar_approvals ADD COLUMN rejection_comment TEXT DEFAULT NULL;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_soar_approvals_level_status 
    ON public.soar_approvals (level, status);

CREATE INDEX IF NOT EXISTS idx_soar_approvals_expires_at 
    ON public.soar_approvals (expires_at) WHERE status = 'pending';

-- 4. EXECUTION RESILIENCY EXTENSIONS (Retry Policy, Exponential Backoff, Resumability)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_executions' AND column_name = 'retry_count'
    ) THEN
        ALTER TABLE public.soar_executions ADD COLUMN retry_count INT NOT NULL DEFAULT 0;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_executions' AND column_name = 'max_retries'
    ) THEN
        ALTER TABLE public.soar_executions ADD COLUMN max_retries INT NOT NULL DEFAULT 3;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_executions' AND column_name = 'backoff_metadata'
    ) THEN
        ALTER TABLE public.soar_executions ADD COLUMN backoff_metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_playbook_steps' AND column_name = 'retry_policy'
    ) THEN
        ALTER TABLE public.soar_playbook_steps ADD COLUMN retry_policy JSONB NOT NULL DEFAULT '{"max_retries": 3, "backoff_ms": 1000, "backoff_multiplier": 2}'::jsonb;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_execution_steps' AND column_name = 'retry_count'
    ) THEN
        ALTER TABLE public.soar_execution_steps ADD COLUMN retry_count INT NOT NULL DEFAULT 0;
    END IF;
END $$;

-- 5. TRIGGER ON SOAR CASES UPDATED_AT
CREATE OR REPLACE FUNCTION public.set_soar_cases_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_soar_cases_updated_at ON public.soar_cases;
CREATE TRIGGER trg_soar_cases_updated_at
BEFORE UPDATE ON public.soar_cases
FOR EACH ROW
EXECUTE FUNCTION public.set_soar_cases_updated_at();
