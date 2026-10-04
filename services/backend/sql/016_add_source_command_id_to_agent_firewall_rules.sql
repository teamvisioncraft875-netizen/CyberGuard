-- ======================================================================================
-- CYBERGUARD Migration 016: Add source_command_id and 'failed' status to agent_firewall_rules
-- ======================================================================================

-- 1. Add source_command_id column referencing agent_commands
ALTER TABLE public.agent_firewall_rules
  ADD COLUMN IF NOT EXISTS source_command_id UUID NULL REFERENCES public.agent_commands(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_agent_firewall_rules_source_cmd
  ON public.agent_firewall_rules(source_command_id);

COMMENT ON COLUMN public.agent_firewall_rules.source_command_id IS 'Links firewall rule to the originating agent_command.';

-- 2. Expand status constraint to allow 'failed' for reporting execution failures
ALTER TABLE public.agent_firewall_rules DROP CONSTRAINT IF EXISTS agent_firewall_rules_status_check;

ALTER TABLE public.agent_firewall_rules ADD CONSTRAINT agent_firewall_rules_status_check
  CHECK (status IN (
    'pending',
    'active',
    'pending_delete',
    'deleted',
    'failed'
  ));
