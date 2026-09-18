-- ======================================================================================
-- CYBERGUARD: Supabase PostgreSQL Row Level Security (RLS) Policies
-- ======================================================================================
--
-- ⚠️ CAUTION & CRITICAL WARNING:
-- These Row Level Security (RLS) policies MUST be tested in a Supabase staging/dev
-- project first. NEVER apply them directly to a project with production or real data
-- without thorough testing. An incorrect RLS policy can either silently expose sensitive
-- multi-tenant data or completely lock out all users, including administrators.
--
-- Access Control Model:
--   1. individual: Can only view and modify their own records (matched by auth.uid() = user_id).
--   2. employee:   Can only view and modify their own records (matched by auth.uid() = user_id),
--                  scoped within their assigned organization.
--   3. admin:      Can view and manage all records belonging to their organization
--                  (matched where organization_id equals the administrator's organization_id).
--
-- Covered Tables:
--   - users
--   - devices
--   - login_events
--   - telemetry_events
--   - incidents
--   - incident_evidence
--   - detection_signals
--   - recommended_actions
--   - mitre_mappings
--   - guardian_links
-- ======================================================================================


-- ======================================================================================
-- 0. SECURITY DEFINER HELPER FUNCTIONS
-- Avoids infinite recursion when policies on the 'users' table query the 'users' table,
-- and dramatically optimizes query execution planning.
-- ======================================================================================

-- Plain language: Retrieves the organization_id of the currently authenticated user without triggering RLS loops.
CREATE OR REPLACE FUNCTION get_auth_org_id()
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT organization_id FROM public.users WHERE id = auth.uid();
$$;

-- Plain language: Checks if the currently authenticated user has the 'admin' role.
CREATE OR REPLACE FUNCTION is_admin()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
  SELECT COALESCE((role::text = 'admin'), false) FROM public.users WHERE id = auth.uid();
$$;


-- ======================================================================================
-- 1. TABLE: users
-- ======================================================================================
-- Schema: id (uuid), email, password_hash, role ('individual'|'employee'|'admin'), organization_id, created_at

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

-- Plain language: Users can see their own profile. Admins can see all users in their organization.
CREATE POLICY "users_select_policy"
ON public.users
FOR SELECT
TO authenticated
USING (
  auth.uid() = id
  OR (
    is_admin()
    AND organization_id IS NOT NULL
    AND organization_id = get_auth_org_id()
  )
);

-- Plain language: Users can update their own profile. Admins can update users in their organization.
CREATE POLICY "users_update_policy"
ON public.users
FOR UPDATE
TO authenticated
USING (
  auth.uid() = id
  OR (
    is_admin()
    AND organization_id IS NOT NULL
    AND organization_id = get_auth_org_id()
  )
)
WITH CHECK (
  auth.uid() = id
  OR (
    is_admin()
    AND organization_id IS NOT NULL
    AND organization_id = get_auth_org_id()
  )
);

-- Plain language: A user can register their own record, or an admin can create user profiles for their organization.
CREATE POLICY "users_insert_policy"
ON public.users
FOR INSERT
TO authenticated
WITH CHECK (
  auth.uid() = id
  OR (
    is_admin()
    AND organization_id IS NOT NULL
    AND organization_id = get_auth_org_id()
  )
);

-- Plain language: Only users themselves or organization admins can delete a user account.
CREATE POLICY "users_delete_policy"
ON public.users
FOR DELETE
TO authenticated
USING (
  auth.uid() = id
  OR (
    is_admin()
    AND organization_id IS NOT NULL
    AND organization_id = get_auth_org_id()
  )
);


-- ======================================================================================
-- 2. TABLE: devices
-- ======================================================================================
-- Schema: id, user_id, device_name, device_fingerprint, is_trusted, last_seen, created_at

ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;

-- Plain language: Users can view their own registered devices. Admins can view devices of all users in their organization.
CREATE POLICY "devices_select_policy"
ON public.devices
FOR SELECT
TO authenticated
USING (
  auth.uid() = user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = devices.user_id
        AND u.organization_id = get_auth_org_id()
    )
  )
);

-- Plain language: Users can register or update their own devices. Admins can manage devices within their organization.
CREATE POLICY "devices_insert_policy"
ON public.devices
FOR INSERT
TO authenticated
WITH CHECK (
  auth.uid() = user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = devices.user_id
        AND u.organization_id = get_auth_org_id()
    )
  )
);

CREATE POLICY "devices_update_policy"
ON public.devices
FOR UPDATE
TO authenticated
USING (
  auth.uid() = user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = devices.user_id
        AND u.organization_id = get_auth_org_id()
    )
  )
)
WITH CHECK (
  auth.uid() = user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = devices.user_id
        AND u.organization_id = get_auth_org_id()
    )
  )
);

CREATE POLICY "devices_delete_policy"
ON public.devices
FOR DELETE
TO authenticated
USING (
  auth.uid() = user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = devices.user_id
        AND u.organization_id = get_auth_org_id()
    )
  )
);


-- ======================================================================================
-- 3. TABLE: login_events
-- ======================================================================================
-- Schema: id, user_id, device_id, ip_address, location, success, failed_attempt_count, created_at

ALTER TABLE public.login_events ENABLE ROW LEVEL SECURITY;

-- Plain language: Users can view their own authentication logs. Admins can audit login events across their organization.
CREATE POLICY "login_events_select_policy"
ON public.login_events
FOR SELECT
TO authenticated
USING (
  auth.uid() = user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = login_events.user_id
        AND u.organization_id = get_auth_org_id()
    )
  )
);

-- Plain language: Users can insert their own authentication attempt records.
CREATE POLICY "login_events_insert_policy"
ON public.login_events
FOR INSERT
TO authenticated
WITH CHECK (
  auth.uid() = user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = login_events.user_id
        AND u.organization_id = get_auth_org_id()
    )
  )
);


-- ======================================================================================
-- 4. TABLE: telemetry_events
-- ======================================================================================
-- Schema: id, user_id, device_id, event_type, payload, created_at

ALTER TABLE public.telemetry_events ENABLE ROW LEVEL SECURITY;

-- Plain language: Users can view their own telemetry events. Admins can view telemetry across their entire organization.
CREATE POLICY "telemetry_events_select_policy"
ON public.telemetry_events
FOR SELECT
TO authenticated
USING (
  auth.uid() = user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = telemetry_events.user_id
        AND u.organization_id = get_auth_org_id()
    )
  )
);

-- Plain language: Endpoints and sensor agents report telemetry matching their authenticated user_id.
CREATE POLICY "telemetry_events_insert_policy"
ON public.telemetry_events
FOR INSERT
TO authenticated
WITH CHECK (
  auth.uid() = user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id = telemetry_events.user_id
        AND u.organization_id = get_auth_org_id()
    )
  )
);


-- ======================================================================================
-- 5. TABLE: incidents
-- ======================================================================================
-- Schema: id, user_id, organization_id, threat_type, source_type, risk_level, risk_score, explanation, status, resolved_by, created_at, resolved_at
--
-- --------------------------------------------------------------------------------------
-- ARCHITECTURAL NOTE: Guardian Mode & GET /api/v1/guardian/alerts
-- --------------------------------------------------------------------------------------
-- The endpoint GET /api/v1/guardian/alerts is hosted by the Node.js API Gateway
-- (services/backend/src/controllers/guardianController.js). It queries Supabase/PostgreSQL
-- through a direct pg.Pool connection using SUPABASE_DB_URL (the administrative/service-role
-- connection). Because this connection operates under PostgreSQL's 'postgres' role,
-- it possesses the BYPASSRLS attribute, meaning all database queries executed by the Gateway
-- bypass Row Level Security at the database driver layer.
--
-- Access control for guardian alerts is therefore enforced at the API Gateway layer:
--   1. The Gateway authenticates the client JWT via auth.js middleware (populating req.user.id).
--   2. guardianController.getDependentAlerts securely queries active dependents linked to
--      req.user.id in guardian_links and retrieves the associated high/critical incidents.
--
-- Future-Proofing Note (Client-Side Supabase Access):
-- If the mobile app or web frontend is ever refactored to query Supabase directly using
-- client-side user sessions (PostgREST / supabase-js with auth.uid()), guardian SELECT
-- access can be enabled at the RLS layer by augmenting incidents_select_policy with:
--   OR EXISTS (
--     SELECT 1 FROM public.guardian_links gl
--     WHERE gl.guardian_user_id = auth.uid()
--       AND gl.dependent_user_id = incidents.user_id
--       AND gl.status = 'active'
--   )
-- Note: Guardian access must strictly remain SELECT-only. Guardians should NEVER be granted
-- INSERT, UPDATE, or DELETE privileges over their dependents' incidents.
-- --------------------------------------------------------------------------------------

ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;

-- Plain language: Users can see incidents targeting their own account. Admins can see all incidents in their organization.
CREATE POLICY "incidents_select_policy"
ON public.incidents
FOR SELECT
TO authenticated
USING (
  auth.uid() = user_id
  OR (
    is_admin()
    AND organization_id IS NOT NULL
    AND organization_id = get_auth_org_id()
  )
);

-- Plain language: Authenticated users can record incidents detected on their accounts; admins can log org-wide incidents.
CREATE POLICY "incidents_insert_policy"
ON public.incidents
FOR INSERT
TO authenticated
WITH CHECK (
  auth.uid() = user_id
  OR (
    is_admin()
    AND organization_id IS NOT NULL
    AND organization_id = get_auth_org_id()
  )
);

-- Plain language: Organization admins can triage and update incident lifecycle status (investigating, resolved).
CREATE POLICY "incidents_update_policy"
ON public.incidents
FOR UPDATE
TO authenticated
USING (
  auth.uid() = user_id
  OR (
    is_admin()
    AND organization_id IS NOT NULL
    AND organization_id = get_auth_org_id()
  )
)
WITH CHECK (
  auth.uid() = user_id
  OR (
    is_admin()
    AND organization_id IS NOT NULL
    AND organization_id = get_auth_org_id()
  )
);


-- ======================================================================================
-- 6. TABLE: incident_evidence
-- ======================================================================================
-- Schema: id, incident_id, evidence_type, evidence_data, metadata, created_at
-- Indirect relation: access is determined by the parent incident's user_id or organization_id.

ALTER TABLE public.incident_evidence ENABLE ROW LEVEL SECURITY;

-- Plain language: Users can view evidence for their own incidents. Admins can view evidence for any incident in their org.
CREATE POLICY "incident_evidence_select_policy"
ON public.incident_evidence
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM public.incidents i
    WHERE i.id = incident_evidence.incident_id
      AND (
        i.user_id = auth.uid()
        OR (
          is_admin()
          AND i.organization_id IS NOT NULL
          AND i.organization_id = get_auth_org_id()
        )
      )
  )
);

-- Plain language: Evidence can only be attached to incidents the user or organization admin has authority over.
CREATE POLICY "incident_evidence_insert_policy"
ON public.incident_evidence
FOR INSERT
TO authenticated
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.incidents i
    WHERE i.id = incident_evidence.incident_id
      AND (
        i.user_id = auth.uid()
        OR (
          is_admin()
          AND i.organization_id IS NOT NULL
          AND i.organization_id = get_auth_org_id()
        )
      )
  )
);


-- ======================================================================================
-- 7. TABLE: detection_signals
-- ======================================================================================
-- Schema: id, incident_id, signal_name, signal_value, weight
-- Indirect relation: access is determined by the parent incident's user_id or organization_id.

ALTER TABLE public.detection_signals ENABLE ROW LEVEL SECURITY;

-- Plain language: Users see detection signals for their own incidents. Admins see signals for incidents in their org.
CREATE POLICY "detection_signals_select_policy"
ON public.detection_signals
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM public.incidents i
    WHERE i.id = detection_signals.incident_id
      AND (
        i.user_id = auth.uid()
        OR (
          is_admin()
          AND i.organization_id IS NOT NULL
          AND i.organization_id = get_auth_org_id()
        )
      )
  )
);

-- Plain language: Signals can only be inserted for valid incidents belonging to the user or admin's organization.
CREATE POLICY "detection_signals_insert_policy"
ON public.detection_signals
FOR INSERT
TO authenticated
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.incidents i
    WHERE i.id = detection_signals.incident_id
      AND (
        i.user_id = auth.uid()
        OR (
          is_admin()
          AND i.organization_id IS NOT NULL
          AND i.organization_id = get_auth_org_id()
        )
      )
  )
);


-- ======================================================================================
-- 8. TABLE: recommended_actions
-- ======================================================================================
-- Schema: id, incident_id, action_type, action_status, created_at
-- Indirect relation: access is determined by the parent incident's user_id or organization_id.

ALTER TABLE public.recommended_actions ENABLE ROW LEVEL SECURITY;

-- Plain language: Users see remediation actions for their incidents. Admins see actions across their org's incidents.
CREATE POLICY "recommended_actions_select_policy"
ON public.recommended_actions
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM public.incidents i
    WHERE i.id = recommended_actions.incident_id
      AND (
        i.user_id = auth.uid()
        OR (
          is_admin()
          AND i.organization_id IS NOT NULL
          AND i.organization_id = get_auth_org_id()
        )
      )
  )
);

-- Plain language: Actions can be created for incidents the user owns or the admin manages.
CREATE POLICY "recommended_actions_insert_policy"
ON public.recommended_actions
FOR INSERT
TO authenticated
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.incidents i
    WHERE i.id = recommended_actions.incident_id
      AND (
        i.user_id = auth.uid()
        OR (
          is_admin()
          AND i.organization_id IS NOT NULL
          AND i.organization_id = get_auth_org_id()
        )
      )
  )
);

-- Plain language: Users and admins can update action status (e.g. mark mitigation completed).
CREATE POLICY "recommended_actions_update_policy"
ON public.recommended_actions
FOR UPDATE
TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM public.incidents i
    WHERE i.id = recommended_actions.incident_id
      AND (
        i.user_id = auth.uid()
        OR (
          is_admin()
          AND i.organization_id IS NOT NULL
          AND i.organization_id = get_auth_org_id()
        )
      )
  )
)
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.incidents i
    WHERE i.id = recommended_actions.incident_id
      AND (
        i.user_id = auth.uid()
        OR (
          is_admin()
          AND i.organization_id IS NOT NULL
          AND i.organization_id = get_auth_org_id()
        )
      )
  )
);


-- ======================================================================================
-- 9. TABLE: mitre_mappings
-- ======================================================================================
-- Schema: id, incident_id, technique_id, technique_name
-- Indirect relation: access is determined by the parent incident's user_id or organization_id.

ALTER TABLE public.mitre_mappings ENABLE ROW LEVEL SECURITY;

-- Plain language: Users see MITRE ATT&CK techniques tagged to their incidents; admins see them across their organization.
CREATE POLICY "mitre_mappings_select_policy"
ON public.mitre_mappings
FOR SELECT
TO authenticated
USING (
  EXISTS (
    SELECT 1 FROM public.incidents i
    WHERE i.id = mitre_mappings.incident_id
      AND (
        i.user_id = auth.uid()
        OR (
          is_admin()
          AND i.organization_id IS NOT NULL
          AND i.organization_id = get_auth_org_id()
        )
      )
  )
);

-- Plain language: MITRE mappings can be created for incidents the user owns or the admin manages.
CREATE POLICY "mitre_mappings_insert_policy"
ON public.mitre_mappings
FOR INSERT
TO authenticated
WITH CHECK (
  EXISTS (
    SELECT 1 FROM public.incidents i
    WHERE i.id = mitre_mappings.incident_id
      AND (
        i.user_id = auth.uid()
        OR (
          is_admin()
          AND i.organization_id IS NOT NULL
          AND i.organization_id = get_auth_org_id()
        )
      )
  )
);


-- ======================================================================================
-- 10. TABLE: guardian_links
-- ======================================================================================
-- Schema: id, guardian_user_id, dependent_user_id, status, created_at
-- Special relationship: both the guardian and the dependent have explicit access.

ALTER TABLE public.guardian_links ENABLE ROW LEVEL SECURITY;

-- Plain language: A guardian can view links where they are guardian_user_id; dependents can view links where they are dependent_user_id. Admins can view links if either party belongs to their organization.
CREATE POLICY "guardian_links_select_policy"
ON public.guardian_links
FOR SELECT
TO authenticated
USING (
  auth.uid() = guardian_user_id
  OR auth.uid() = dependent_user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE (u.id = guardian_links.guardian_user_id OR u.id = guardian_links.dependent_user_id)
        AND u.organization_id = get_auth_org_id()
    )
  )
);

-- Plain language: Either the guardian or the dependent can establish a link request.
CREATE POLICY "guardian_links_insert_policy"
ON public.guardian_links
FOR INSERT
TO authenticated
WITH CHECK (
  auth.uid() = guardian_user_id
  OR auth.uid() = dependent_user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE (u.id = guardian_links.guardian_user_id OR u.id = guardian_links.dependent_user_id)
        AND u.organization_id = get_auth_org_id()
    )
  )
);

-- Plain language: Either the guardian or the dependent can update the link status (e.g. accept or revoke the relationship).
CREATE POLICY "guardian_links_update_policy"
ON public.guardian_links
FOR UPDATE
TO authenticated
USING (
  auth.uid() = guardian_user_id
  OR auth.uid() = dependent_user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE (u.id = guardian_links.guardian_user_id OR u.id = guardian_links.dependent_user_id)
        AND u.organization_id = get_auth_org_id()
    )
  )
)
WITH CHECK (
  auth.uid() = guardian_user_id
  OR auth.uid() = dependent_user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE (u.id = guardian_links.guardian_user_id OR u.id = guardian_links.dependent_user_id)
        AND u.organization_id = get_auth_org_id()
    )
  )
);

-- Plain language: Guardians or dependents can remove the guardian link relationship.
CREATE POLICY "guardian_links_delete_policy"
ON public.guardian_links
FOR DELETE
TO authenticated
USING (
  auth.uid() = guardian_user_id
  OR auth.uid() = dependent_user_id
  OR (
    is_admin()
    AND EXISTS (
      SELECT 1 FROM public.users u
      WHERE (u.id = guardian_links.guardian_user_id OR u.id = guardian_links.dependent_user_id)
        AND u.organization_id = get_auth_org_id()
    )
  )
);
