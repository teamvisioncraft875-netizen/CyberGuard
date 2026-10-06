-- =========================================================================
-- CYBERGUARD DATABASE MIGRATION 035: SOAR AUTOMATION & PLAYBOOK ENGINE
-- =========================================================================

-- 1. SOAR PLAYBOOKS TABLE
CREATE TABLE IF NOT EXISTS public.soar_playbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    trigger_type VARCHAR(50) NOT NULL DEFAULT 'alert',
    trigger_conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_playbooks_org_enabled 
    ON public.soar_playbooks (organization_id, enabled);

CREATE INDEX IF NOT EXISTS idx_soar_playbooks_trigger_type 
    ON public.soar_playbooks (trigger_type);

-- 2. SOAR PLAYBOOK STEPS TABLE
CREATE TABLE IF NOT EXISTS public.soar_playbook_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id UUID NOT NULL REFERENCES public.soar_playbooks(id) ON DELETE CASCADE,
    step_order INT NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    action_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_playbook_steps_playbook 
    ON public.soar_playbook_steps (playbook_id, step_order);

-- 3. SOAR EXECUTIONS TABLE
CREATE TABLE IF NOT EXISTS public.soar_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    playbook_id UUID NOT NULL REFERENCES public.soar_playbooks(id) ON DELETE CASCADE,
    trigger_alert_id UUID,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, running, waiting_approval, completed, failed, cancelled
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soar_executions_org_status 
    ON public.soar_executions (organization_id, status);

CREATE INDEX IF NOT EXISTS idx_soar_executions_playbook 
    ON public.soar_executions (playbook_id);

CREATE INDEX IF NOT EXISTS idx_soar_executions_trigger_alert 
    ON public.soar_executions (trigger_alert_id);

-- 4. SOAR EXECUTION STEPS TABLE
CREATE TABLE IF NOT EXISTS public.soar_execution_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID NOT NULL REFERENCES public.soar_executions(id) ON DELETE CASCADE,
    playbook_step_id UUID NOT NULL REFERENCES public.soar_playbook_steps(id) ON DELETE CASCADE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, running, completed, failed, skipped
    result_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    executed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_soar_execution_steps_execution 
    ON public.soar_execution_steps (execution_id);

-- 5. SOAR APPROVALS TABLE
CREATE TABLE IF NOT EXISTS public.soar_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id UUID NOT NULL REFERENCES public.soar_executions(id) ON DELETE CASCADE,
    requested_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    approved_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, approved, rejected
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_soar_approvals_execution_status 
    ON public.soar_approvals (execution_id, status);

-- Trigger to automatically update updated_at on soar_playbooks
CREATE OR REPLACE FUNCTION public.set_soar_playbooks_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_soar_playbooks_updated_at ON public.soar_playbooks;
CREATE TRIGGER trg_soar_playbooks_updated_at
BEFORE UPDATE ON public.soar_playbooks
FOR EACH ROW
EXECUTE FUNCTION public.set_soar_playbooks_updated_at();
