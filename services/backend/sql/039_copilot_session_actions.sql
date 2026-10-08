-- ======================================================================================
-- CYBERGUARD Migration 039: Copilot Investigation Session Actions & Execution Memory
-- ======================================================================================

CREATE TABLE IF NOT EXISTS public.copilot_session_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES public.copilot_sessions(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    action_type VARCHAR(100) NOT NULL,
    action_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(50) NOT NULL DEFAULT 'recommended' CHECK (status IN ('recommended', 'pending_approval', 'approved', 'rejected', 'executed', 'failed')),
    execution_id UUID REFERENCES public.soar_executions(id) ON DELETE SET NULL,
    approval_id UUID REFERENCES public.soar_approvals(id) ON DELETE SET NULL,
    case_id UUID REFERENCES public.soar_cases(id) ON DELETE SET NULL,
    confidence NUMERIC(5, 2) DEFAULT 0.90,
    reason TEXT,
    explanation JSONB NOT NULL DEFAULT '{}'::jsonb,
    requires_approval BOOLEAN NOT NULL DEFAULT false,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_copilot_session_actions_session ON public.copilot_session_actions(session_id);
CREATE INDEX IF NOT EXISTS idx_copilot_session_actions_org ON public.copilot_session_actions(organization_id);
CREATE INDEX IF NOT EXISTS idx_copilot_session_actions_status ON public.copilot_session_actions(status);
CREATE INDEX IF NOT EXISTS idx_copilot_session_actions_type ON public.copilot_session_actions(action_type);
CREATE INDEX IF NOT EXISTS idx_copilot_session_actions_created ON public.copilot_session_actions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_copilot_session_actions_execution ON public.copilot_session_actions(execution_id);
CREATE INDEX IF NOT EXISTS idx_copilot_session_actions_approval ON public.copilot_session_actions(approval_id);
CREATE INDEX IF NOT EXISTS idx_copilot_session_actions_case ON public.copilot_session_actions(case_id);

-- 2. Ensure soar_approvals supports single-use consumption
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_approvals' AND column_name = 'consumed'
    ) THEN
        ALTER TABLE public.soar_approvals ADD COLUMN consumed BOOLEAN NOT NULL DEFAULT false;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_schema = 'public' AND table_name = 'soar_approvals' AND column_name = 'consumed_at'
    ) THEN
        ALTER TABLE public.soar_approvals ADD COLUMN consumed_at TIMESTAMPTZ DEFAULT NULL;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_soar_approvals_consumed 
    ON public.soar_approvals (consumed) WHERE status = 'approved';

-- 3. Idempotently add missing foreign key constraints on copilot_session_actions
DO $$
BEGIN
    -- execution_id foreign key
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_copilot_session_actions_execution' 
          AND table_name = 'copilot_session_actions'
    ) THEN
        -- Safely nullify orphaned references prior to constraint enforcement
        UPDATE public.copilot_session_actions
        SET execution_id = NULL
        WHERE execution_id IS NOT NULL 
          AND execution_id NOT IN (SELECT id FROM public.soar_executions);

        ALTER TABLE public.copilot_session_actions
            ADD CONSTRAINT fk_copilot_session_actions_execution
            FOREIGN KEY (execution_id) REFERENCES public.soar_executions(id) ON DELETE SET NULL;
    END IF;

    -- approval_id foreign key
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_copilot_session_actions_approval' 
          AND table_name = 'copilot_session_actions'
    ) THEN
        -- Safely nullify orphaned references prior to constraint enforcement
        UPDATE public.copilot_session_actions
        SET approval_id = NULL
        WHERE approval_id IS NOT NULL 
          AND approval_id NOT IN (SELECT id FROM public.soar_approvals);

        ALTER TABLE public.copilot_session_actions
            ADD CONSTRAINT fk_copilot_session_actions_approval
            FOREIGN KEY (approval_id) REFERENCES public.soar_approvals(id) ON DELETE SET NULL;
    END IF;

    -- case_id foreign key
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'fk_copilot_session_actions_case' 
          AND table_name = 'copilot_session_actions'
    ) THEN
        -- Safely nullify orphaned references prior to constraint enforcement
        UPDATE public.copilot_session_actions
        SET case_id = NULL
        WHERE case_id IS NOT NULL 
          AND case_id NOT IN (SELECT id FROM public.soar_cases);

        ALTER TABLE public.copilot_session_actions
            ADD CONSTRAINT fk_copilot_session_actions_case
            FOREIGN KEY (case_id) REFERENCES public.soar_cases(id) ON DELETE SET NULL;
    END IF;
END $$;

-- 4. Trigger to automatically update updated_at on copilot_session_actions
CREATE OR REPLACE FUNCTION public.set_copilot_session_actions_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_copilot_session_actions_updated ON public.copilot_session_actions;
CREATE TRIGGER trigger_copilot_session_actions_updated
    BEFORE UPDATE ON public.copilot_session_actions
    FOR EACH ROW
    EXECUTE FUNCTION public.set_copilot_session_actions_updated_at();

