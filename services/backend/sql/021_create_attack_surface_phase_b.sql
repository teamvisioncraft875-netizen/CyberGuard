-- ======================================================================================
-- CYBERGUARD Migration 021: Create Attack Surface Exposures Table & Constraints (Phase B)
-- ======================================================================================

-- 0. Expand enums for attack surface threat and source types
ALTER TYPE threat_type ADD VALUE IF NOT EXISTS 'attack_surface_exposure';
ALTER TYPE source_type ADD VALUE IF NOT EXISTS 'attack_surface';

-- 1. Create attack_surface_exposures table
CREATE TABLE IF NOT EXISTS public.attack_surface_exposures (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id     UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  device_id           UUID NOT NULL REFERENCES public.devices(id) ON DELETE CASCADE,
  port_id             UUID NOT NULL REFERENCES public.device_listening_ports(id) ON DELETE CASCADE,
  rule_id             VARCHAR(50) NOT NULL,
  severity            VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  risk_score          INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
  title               TEXT NOT NULL,
  description         TEXT NULL,
  remediation         TEXT NULL,
  status              VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'mitigated')),
  first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  mitigated_at        TIMESTAMPTZ NULL,
  incident_id         UUID NULL REFERENCES public.incidents(id) ON DELETE SET NULL,
  metadata            JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Partial unique index ensuring exactly one active finding per device, rule, and port
CREATE UNIQUE INDEX IF NOT EXISTS uq_attack_surface_active_exposure 
  ON public.attack_surface_exposures (device_id, rule_id, port_id) 
  WHERE status = 'active';

-- High-performance query indexes
CREATE INDEX IF NOT EXISTS idx_attack_surface_exposures_org 
  ON public.attack_surface_exposures (organization_id, status);

CREATE INDEX IF NOT EXISTS idx_attack_surface_exposures_device 
  ON public.attack_surface_exposures (device_id, status);

CREATE INDEX IF NOT EXISTS idx_attack_surface_exposures_port 
  ON public.attack_surface_exposures (port_id);

CREATE INDEX IF NOT EXISTS idx_attack_surface_exposures_incident 
  ON public.attack_surface_exposures (incident_id) 
  WHERE incident_id IS NOT NULL;

-- 2. Expand response_actions action_type to support 'block_port'
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
    'suspend_device',
    'isolate_device',
    'block_port'
  ));

-- 3. Expand agent_commands command_type to support 'scan_attack_surface'
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
    'delete_firewall_rule',
    'scan_attack_surface'
  ));

COMMENT ON TABLE public.attack_surface_exposures IS 
  'Catalog of active and mitigated attack surface exposures (Attack Surface Discovery Phase B)';
