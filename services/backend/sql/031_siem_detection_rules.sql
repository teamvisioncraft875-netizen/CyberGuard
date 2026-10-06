-- CYBERGUARD Migration 031: SIEM Correlation & Detection Rules Engine
-- Supports rule-based event correlation, multi-stage attack detection, and detection hit tracking

-- 1. Create siem_detection_rules Table
CREATE TABLE IF NOT EXISTS public.siem_detection_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES public.organizations(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  enabled BOOLEAN NOT NULL DEFAULT true,
  severity VARCHAR(50) NOT NULL DEFAULT 'medium',
  rule_type VARCHAR(100) NOT NULL,
  conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_siem_detection_rules_org ON public.siem_detection_rules(organization_id);
CREATE INDEX IF NOT EXISTS idx_siem_detection_rules_enabled ON public.siem_detection_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_siem_detection_rules_org_enabled ON public.siem_detection_rules(organization_id, enabled);

-- 2. Create siem_detection_hits Table
CREATE TABLE IF NOT EXISTS public.siem_detection_hits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  rule_id UUID REFERENCES public.siem_detection_rules(id) ON DELETE SET NULL,
  incident_id UUID REFERENCES public.incidents(id) ON DELETE SET NULL,
  event_ids UUID[] NOT NULL DEFAULT '{}',
  matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  confidence_score NUMERIC(5,2) NOT NULL DEFAULT 1.0,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_siem_detection_hits_org ON public.siem_detection_hits(organization_id);
CREATE INDEX IF NOT EXISTS idx_siem_detection_hits_rule ON public.siem_detection_hits(rule_id);
CREATE INDEX IF NOT EXISTS idx_siem_detection_hits_matched_at ON public.siem_detection_hits(matched_at);
CREATE INDEX IF NOT EXISTS idx_siem_detection_hits_incident ON public.siem_detection_hits(incident_id);

-- 3. Seed Default System Rules (organization_id NULL indicates global template rules)
INSERT INTO public.siem_detection_rules (id, organization_id, name, description, enabled, severity, rule_type, conditions)
VALUES
  (
    '00000000-0000-0000-0000-000000000101',
    NULL,
    'Brute Force Detection',
    'Detects 10 or more failed login attempts for the same user within 5 minutes',
    true,
    'high',
    'threshold',
    '{"threshold": 10, "window_minutes": 5, "event_types": ["windows_logon_failure", "linux_failed_login"], "group_by": "target_user", "mitre": "T1110"}'::jsonb
  ),
  (
    '00000000-0000-0000-0000-000000000102',
    NULL,
    'Password Spraying',
    'Detects authentication attempts across 10 or more different users from the same source IP within 15 minutes',
    true,
    'high',
    'aggregation',
    '{"threshold": 10, "window_minutes": 15, "distinct_field": "target_user", "group_by": "source_ip", "mitre": "T1110.003"}'::jsonb
  ),
  (
    '00000000-0000-0000-0000-000000000103',
    NULL,
    'Privilege Escalation Sequence',
    'Detects a successful login followed by administrative group membership addition for the same user within 30 minutes',
    true,
    'critical',
    'sequence',
    '{"window_minutes": 30, "group_by": "target_user", "stage1": "login_success", "stage2": "admin_group_added", "mitre": ["T1078", "T1068"]}'::jsonb
  ),
  (
    '00000000-0000-0000-0000-000000000104',
    NULL,
    'PowerShell Obfuscation & Download Abuse',
    'Detects powershell.exe executing with encodedcommand, downloadstring, or iex parameters',
    true,
    'high',
    'pattern',
    '{"process": "powershell.exe", "patterns": ["encodedcommand", "downloadstring", "iex"], "mitre": "T1059"}'::jsonb
  ),
  (
    '00000000-0000-0000-0000-000000000105',
    NULL,
    'Audit Log Clearing Defense Evasion',
    'Detects Windows Security Event ID 1102 indicating the security audit log was cleared',
    true,
    'critical',
    'single_event',
    '{"event_id": "1102", "action": "audit_log_cleared", "mitre": "T1070"}'::jsonb
  ),
  (
    '00000000-0000-0000-0000-000000000106',
    NULL,
    'Persistence Registry Modification',
    'Detects unauthorized modification of Run keys, Services, or Startup entries in Windows registry',
    true,
    'high',
    'pattern',
    '{"keys": ["\\Run", "\\RunOnce", "\\Services\\", "\\Startup"], "mitre": "T1547"}'::jsonb
  ),
  (
    '00000000-0000-0000-0000-000000000107',
    NULL,
    'Suspicious C2 Beaconing',
    'Detects repeated network connections to the same destination 20 or more times within 1 hour',
    true,
    'medium',
    'threshold',
    '{"threshold": 20, "window_minutes": 60, "group_by": "dest_ip", "mitre": "T1071"}'::jsonb
  )
ON CONFLICT (id) DO NOTHING;
