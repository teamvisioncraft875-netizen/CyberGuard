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
    execution_id UUID,
    approval_id UUID,
    case_id UUID,
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
