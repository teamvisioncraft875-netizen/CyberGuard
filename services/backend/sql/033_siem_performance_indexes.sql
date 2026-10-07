-- CYBERGUARD Migration 033: SIEM Phase 4 — High-Performance Composite Indexes
-- Accelerates multi-tenant SOC metrics, timeline aggregations, analyst queue, and sliding window lookups

CREATE INDEX IF NOT EXISTS idx_siem_alerts_org_created_desc
  ON public.siem_alerts(organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_siem_alerts_org_sev_created_desc
  ON public.siem_alerts(organization_id, severity, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_siem_alerts_org_status_created_desc
  ON public.siem_alerts(organization_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_siem_detection_hits_org_matched_desc
  ON public.siem_detection_hits(organization_id, matched_at DESC);

CREATE INDEX IF NOT EXISTS idx_siem_detection_hits_org_rule_matched_desc
  ON public.siem_detection_hits(organization_id, rule_id, matched_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_org_timestamp_desc
  ON public.security_events(organization_id, event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_org_created_desc
  ON public.incidents(organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_attack_chain_snapshots_org_created_desc
  ON public.attack_chain_snapshots(organization_id, created_at DESC);
