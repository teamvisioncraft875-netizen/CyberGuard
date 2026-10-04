-- ======================================================================================
-- CYBERGUARD Migration 017: Add rule_id_local and 'delete_firewall_rule' command_type
-- Enables bidirectional firewall rule deletion tracking: rule_id_local <-> delete command
-- ======================================================================================

-- 1. Ensure rule_id_local exists on agent_firewall_rules
ALTER TABLE public.agent_firewall_rules
  ADD COLUMN IF NOT EXISTS rule_id_local TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_firewall_rules_rule_id_local
  ON public.agent_firewall_rules(rule_id_local);

COMMENT ON COLUMN public.agent_firewall_rules.rule_id_local IS 'Windows DisplayName or Linux rule hash/identifier for host deletion.';

-- 2. Expand agent_commands command_type check constraint to include 'delete_firewall_rule'
ALTER TABLE public.agent_commands DROP CONSTRAINT IF EXISTS agent_commands_command_type_check;

ALTER TABLE public.agent_commands ADD CONSTRAINT agent_commands_command_type_check
  CHECK (command_type IN (
    'collect_snapshot',
    'refresh_policy',
    'temporary_block_ip',
    'block_ip',
    'block_domain',
    'unblock_ip',
    'unblock_domain',
    'delete_firewall_rule'
  ));
