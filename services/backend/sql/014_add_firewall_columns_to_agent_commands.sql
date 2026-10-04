-- ======================================================================================
-- CYBERGUARD Migration 014: Add firewall columns and expanded command_type to agent_commands
-- ======================================================================================

ALTER TABLE public.agent_commands ADD COLUMN IF NOT EXISTS can_execute BOOLEAN DEFAULT false;
ALTER TABLE public.agent_commands ADD COLUMN IF NOT EXISTS validation_error TEXT NULL;
ALTER TABLE public.agent_commands ADD COLUMN IF NOT EXISTS requires_approval BOOLEAN DEFAULT true;

-- Column Comments
COMMENT ON COLUMN public.agent_commands.can_execute IS 'can_execute=true means agent validated and can run.';
COMMENT ON COLUMN public.agent_commands.validation_error IS 'validation_error if input validation failed.';
COMMENT ON COLUMN public.agent_commands.requires_approval IS 'requires_approval for block_* commands.';

-- Update command_type check constraint to support Phase C firewall instructions
ALTER TABLE public.agent_commands DROP CONSTRAINT IF EXISTS agent_commands_command_type_check;

ALTER TABLE public.agent_commands ADD CONSTRAINT agent_commands_command_type_check
  CHECK (command_type IN (
    'collect_snapshot',
    'refresh_policy',
    'temporary_block_ip',
    'block_ip',
    'block_domain',
    'unblock_ip',
    'unblock_domain'
  ));
