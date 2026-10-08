-- =========================================================================
-- CYBERGUARD DATABASE MIGRATION 042: COPILOT & SOAR PERFORMANCE INDEXES
-- =========================================================================

-- 1. Composite Sorting Indexes for Tenant Dashboard & Listing Views (Issue I-1)
CREATE INDEX IF NOT EXISTS idx_soar_cases_org_created
    ON public.soar_cases (organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_soar_executions_org_created
    ON public.soar_executions (organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_copilot_sessions_org_updated
    ON public.copilot_sessions (organization_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_copilot_messages_session_ts
    ON public.copilot_messages (session_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_copilot_messages_session_ts_asc
    ON public.copilot_messages (session_id, timestamp ASC);

-- 2. Foreign Key Indexes for Execution Steps & Response Recommendations (Issues I-2, I-3)
CREATE INDEX IF NOT EXISTS idx_soar_execution_steps_step
    ON public.soar_execution_steps (playbook_step_id);

CREATE INDEX IF NOT EXISTS idx_soar_recommendations_execution
    ON public.soar_response_recommendations (execution_id);
