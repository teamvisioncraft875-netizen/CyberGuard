-- ======================================================================================
-- CYBERGUARD Migration 022: Harden Attack Surface Discovery Phase B
-- ======================================================================================
-- 1. Enable Row Level Security (RLS) on attack surface tables (CRIT-03)
-- 2. Expand status to support 'grace_period' for anti-flapping (CRIT-04)
-- 3. Add composite sorting index for dashboard queries (MED-01)
-- ======================================================================================

-- 1. Update status check constraint to include 'grace_period'
ALTER TABLE public.attack_surface_exposures DROP CONSTRAINT IF EXISTS attack_surface_exposures_status_check;
ALTER TABLE public.attack_surface_exposures ADD CONSTRAINT attack_surface_exposures_status_check 
  CHECK (status IN ('active', 'grace_period', 'mitigated'));

-- 2. Add grace_period_started_at column if not exists
ALTER TABLE public.attack_surface_exposures 
  ADD COLUMN IF NOT EXISTS grace_period_started_at TIMESTAMPTZ NULL;

-- 3. Composite Sorting Index (MED-01)
CREATE INDEX IF NOT EXISTS idx_attack_surface_exposures_sort 
  ON public.attack_surface_exposures (organization_id, status, risk_score DESC, last_seen_at DESC);

-- 4. Enable Row Level Security on Attack Surface tables (CRIT-03)
ALTER TABLE public.attack_surface_exposures ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_listening_ports ENABLE ROW LEVEL SECURITY;

-- 5. Create RLS Policies for attack_surface_exposures
DROP POLICY IF EXISTS "attack_surface_exposures_tenant_isolation" ON public.attack_surface_exposures;
CREATE POLICY "attack_surface_exposures_tenant_isolation"
ON public.attack_surface_exposures
FOR ALL
TO authenticated
USING (
  organization_id IS NOT NULL
  AND organization_id = get_auth_org_id()
)
WITH CHECK (
  organization_id IS NOT NULL
  AND organization_id = get_auth_org_id()
);

-- 6. Create RLS Policies for device_listening_ports
DROP POLICY IF EXISTS "device_listening_ports_tenant_isolation" ON public.device_listening_ports;
CREATE POLICY "device_listening_ports_tenant_isolation"
ON public.device_listening_ports
FOR ALL
TO authenticated
USING (
  organization_id IS NOT NULL
  AND organization_id = get_auth_org_id()
)
WITH CHECK (
  organization_id IS NOT NULL
  AND organization_id = get_auth_org_id()
);
