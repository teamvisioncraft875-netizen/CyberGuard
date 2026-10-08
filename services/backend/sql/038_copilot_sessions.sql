-- ======================================================================================
-- CYBERGUARD Migration 038: Copilot Investigation Sessions & Multi-Turn Message History
-- ======================================================================================

-- 1. Copilot Investigation Sessions Table
CREATE TABLE IF NOT EXISTS public.copilot_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL DEFAULT 'New Investigation Session',
    entity_type VARCHAR(50),
    entity_id VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived', 'closed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_copilot_sessions_org ON public.copilot_sessions(organization_id);
CREATE INDEX IF NOT EXISTS idx_copilot_sessions_user ON public.copilot_sessions(created_by);
CREATE INDEX IF NOT EXISTS idx_copilot_sessions_entity ON public.copilot_sessions(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_copilot_sessions_status ON public.copilot_sessions(status);
CREATE INDEX IF NOT EXISTS idx_copilot_sessions_updated ON public.copilot_sessions(updated_at DESC);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION public.set_copilot_session_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_copilot_session_updated ON public.copilot_sessions;
CREATE TRIGGER trigger_copilot_session_updated
    BEFORE UPDATE ON public.copilot_sessions
    FOR EACH ROW
    EXECUTE FUNCTION public.set_copilot_session_updated_at();

-- 2. Copilot Messages Table
CREATE TABLE IF NOT EXISTS public.copilot_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES public.copilot_sessions(id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
    content TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_copilot_messages_session ON public.copilot_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_copilot_messages_timestamp ON public.copilot_messages(timestamp ASC);
CREATE INDEX IF NOT EXISTS idx_copilot_messages_role ON public.copilot_messages(role);
