-- ==============================================================================
-- CYBERGUARD Migration 043: Enable Row Level Security (RLS) on Public Tables
-- ==============================================================================
-- Purpose:
--   Resolves Supabase Security Advisor Critical findings ("RLS Disabled in Public")
--   across all public tables.
--
-- Safety & Architecture Notes:
--   1. CYBERGUARD Node.js Express backend and Python ML engine connect via direct
--      PostgreSQL credentials (user: postgres).
--   2. In PostgreSQL, table owners and superusers bypass Row Level Security by default.
--   3. Enabling RLS blocks unauthorized anonymous access over the public Supabase
--      PostgREST Data API (anon key) without restricting backend database operations.
--   4. Fully idempotent: Safe to execute repeatedly without schema mutations.
-- ==============================================================================

-- Explicit idempotent RLS activation for all public tables
ALTER TABLE IF EXISTS public.refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.ddos_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.incident_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.incident_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.incident_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.incident_notes ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.incident_recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.attack_chain_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.event_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.event_ingestion_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.siem_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.siem_detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.siem_detection_hits ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.threat_iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.threat_ioc_sightings ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.soar_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.soar_case_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.soar_playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.soar_playbook_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.soar_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.soar_execution_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.soar_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.soar_connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.soar_connector_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.soar_response_recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.soar_knowledge_base ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.copilot_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.copilot_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.copilot_session_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.copilot_investigations ENABLE ROW LEVEL SECURITY;

-- Dynamic fallback block: guarantees RLS is enabled on any remaining or future public tables
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public'
          AND rowsecurity = false
    LOOP
        EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY;', r.tablename);
    END LOOP;
END $$;
