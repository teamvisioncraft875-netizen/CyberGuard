-- ======================================================================================
-- CYBERGUARD Migration 024: Threat Intelligence Automated Response Policies
-- ======================================================================================

-- 1. Expand response_actions.action_type check constraint to support 'block_url'
ALTER TABLE public.response_actions DROP CONSTRAINT IF EXISTS response_actions_action_type_check;

ALTER TABLE public.response_actions ADD CONSTRAINT response_actions_action_type_check 
  CHECK (action_type IN (
    'notify_admin',
    'notify_user',
    'revoke_session',
    'force_password_reset',
    'require_mfa',
    'block_ip',
    'block_domain',
    'block_url',
    'suspend_device',
    'isolate_device',
    'block_port'
  ));

-- 2. Add metadata column to response_actions if not present
ALTER TABLE public.response_actions 
  ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;

-- 3. Dedicated index for threat intelligence indicator response actions dedup
CREATE UNIQUE INDEX IF NOT EXISTS uq_response_actions_ti_indicator 
  ON public.response_actions (incident_id, action_type, (metadata->>'indicator_value')) 
  WHERE status NOT IN ('rejected', 'failed', 'expired', 'rolled_back') 
    AND (metadata->>'indicator_value') IS NOT NULL;

-- 4. Index on metadata for threat intel correlation queries
CREATE INDEX IF NOT EXISTS idx_response_actions_ti_indicator_val 
  ON public.response_actions ((metadata->>'indicator_value')) 
  WHERE (metadata->>'indicator_value') IS NOT NULL;
