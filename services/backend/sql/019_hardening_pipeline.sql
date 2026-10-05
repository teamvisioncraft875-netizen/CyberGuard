-- ======================================================================================
-- CYBERGUARD Migration 019: Pipeline Security Hardening & Concurrency Protection
-- Adds unique dedup indexes, rule_hash, response_action_id tracking, and performance indexes
-- ======================================================================================

-- 0. Ensure distributed_ddos is a valid threat_type
ALTER TYPE threat_type ADD VALUE IF NOT EXISTS 'distributed_ddos';

-- Allow 'executing' in response_actions status constraint
ALTER TABLE public.response_actions 
  DROP CONSTRAINT IF EXISTS response_actions_status_check;

ALTER TABLE public.response_actions 
  ADD CONSTRAINT response_actions_status_check 
  CHECK (status IN (
    'proposed',
    'pending_approval',
    'approved',
    'scheduled',
    'executing',
    'rejected',
    'executed',
    'failed',
    'expired',
    'rolled_back'
  ));

-- 1. Response Action Deduplication Protection
-- Ensure only one active response action exists per (incident_id, action_type, target)
CREATE UNIQUE INDEX IF NOT EXISTS uq_response_actions_active_dedup
  ON public.response_actions (incident_id, action_type, (target::text))
  WHERE status NOT IN ('rejected', 'failed', 'expired', 'rolled_back');

-- 2. Agent Commands: Add response_action_id & Unique Active Constraint
ALTER TABLE public.agent_commands 
  ADD COLUMN IF NOT EXISTS response_action_id UUID NULL REFERENCES public.response_actions(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_commands_response_action_active
  ON public.agent_commands (response_action_id)
  WHERE status IN ('pending', 'executing') AND response_action_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_commands_response_action_id
  ON public.agent_commands (response_action_id);

-- 3. Firewall Rules: Add rule_hash & Unique Active Constraint
ALTER TABLE public.agent_firewall_rules
  ADD COLUMN IF NOT EXISTS rule_hash TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_firewall_rules_rule_hash
  ON public.agent_firewall_rules (rule_hash);

CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_firewall_rules_active_hash
  ON public.agent_firewall_rules (agent_id, rule_hash)
  WHERE status IN ('pending', 'active') AND rule_hash IS NOT NULL;

-- 4. Performance Indexes for High-Volume Telemetry & DDoS Scans
CREATE INDEX IF NOT EXISTS idx_ddos_metrics_org_window 
  ON public.ddos_metrics (organization_id, metric_type, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_org_ip_created
  ON public.audit_logs (organization_id, ip_address, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_response_actions_sched_due
  ON public.response_actions (scheduled_at)
  WHERE status IN ('scheduled', 'approved');
