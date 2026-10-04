-- ======================================================================================
-- CYBERGUARD Migration 013: Allow 'device' actor_type in audit_logs & nullable telemetry user_id
-- Enables Enterprise Agents to submit telemetry and system actions with device identity.
-- ======================================================================================

ALTER TABLE public.audit_logs DROP CONSTRAINT IF EXISTS audit_logs_actor_type_check;

ALTER TABLE public.audit_logs ADD CONSTRAINT audit_logs_actor_type_check 
  CHECK (actor_type IN ('user', 'admin', 'system_policy', 'system_guard', 'device'));

-- Allow machine/agent device telemetry without requiring a linked human user
ALTER TABLE public.telemetry_events ALTER COLUMN user_id DROP NOT NULL;
