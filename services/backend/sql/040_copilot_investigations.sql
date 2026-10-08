-- ======================================================================================
-- CYBERGUARD Migration 040: Copilot Autonomous Investigations, Hunts & Graph Memory
-- ======================================================================================

CREATE TABLE IF NOT EXISTS public.copilot_investigations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES public.copilot_sessions(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    investigation_type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    target_type VARCHAR(50),
    target_id VARCHAR(255),
    findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
    graph JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    severity VARCHAR(20) DEFAULT 'medium',
    confidence NUMERIC(5, 2) DEFAULT 0.90,
    created_by UUID REFERENCES public.users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_copilot_investigations_severity CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'))
);

CREATE INDEX IF NOT EXISTS idx_copilot_investigations_session ON public.copilot_investigations(session_id);
CREATE INDEX IF NOT EXISTS idx_copilot_investigations_org ON public.copilot_investigations(organization_id);
CREATE INDEX IF NOT EXISTS idx_copilot_investigations_type ON public.copilot_investigations(investigation_type);
CREATE INDEX IF NOT EXISTS idx_copilot_investigations_created ON public.copilot_investigations(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_copilot_investigations_target ON public.copilot_investigations(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_copilot_investigations_org_target ON public.copilot_investigations(organization_id, target_type, target_id);

-- Idempotently ensure severity CHECK constraint exists on copilot_investigations
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'chk_copilot_investigations_severity' 
          AND table_name = 'copilot_investigations'
    ) THEN
        ALTER TABLE public.copilot_investigations
            ADD CONSTRAINT chk_copilot_investigations_severity
            CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'));
    END IF;
END $$;

-- Trigger to automatically update updated_at on copilot_investigations
CREATE OR REPLACE FUNCTION public.set_copilot_investigations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_copilot_investigations_updated ON public.copilot_investigations;
CREATE TRIGGER trigger_copilot_investigations_updated
    BEFORE UPDATE ON public.copilot_investigations
    FOR EACH ROW
    EXECUTE FUNCTION public.set_copilot_investigations_updated_at();
