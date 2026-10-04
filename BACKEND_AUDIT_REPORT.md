# CYBERGUARD — Backend Audit Report & Frontend Integration Readiness

> **Audit Date:** September 2026  
> **Audited Workspace:** `/Users/pritee/CyberGuard`  
> **Auditors:** Antigravity Senior Engineering Team  
> **Scope:** Full architectural review of `services/backend`, `services/ml-service`, `services/guard-app`, database schemas, and API contracts.  

---

## 1. Feature Completion Status Table

| Feature / Module | Status | Evidence (File Paths & Line Numbers) | Architectural Notes & Limitations |
|---|---|---|---|
| **User Registration (`/auth/signup`)** | **STUBBED** | `services/backend/src/controllers/authController.js:12-41` | Validates input format, but **does not hash passwords or query the database**. Issues a JWT with a hardcoded dummy UUID (`a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d`). |
| **User Login (`/auth/login`)** | **STUBBED** | `services/backend/src/controllers/authController.js:46-70` | Checks non-empty credentials, but **does not query `User.findByEmail` or verify passwords**. Any password succeeds. Assigns `role: 'admin'` if email contains "admin", else `individual`. Returns hardcoded dummy IDs. |
| **Current User Profile (`/auth/me`)** | **STUBBED** | `services/backend/src/controllers/authController.js:75-87` | Does not query database for fresh user profile. Returns hardcoded "Jane Doe" / "analyst@enterprise.com" mock data. |
| **Token Refresh & Logout** | **MISSING** | `services/backend/src/routes/authRoutes.js:1-17` | No `/refresh` or `/logout` endpoints exist. Tokens expire after 7 days without refresh or revocation capability. |
| **Message Threat Check** | **DONE** | `services/backend/src/controllers/checkController.js:16-70`<br>`services/ml-service/app/services/message_engine.py:76-215` | Full pipeline: validation, upstream FastAPI ML inference with prompt injection defenses, database transaction persistence, and Socket.io alert emission. |
| **URL Threat Check** | **DONE** | `services/backend/src/controllers/checkController.js:75-128`<br>`services/ml-service/app/services/url_engine.py:5-104` | Full pipeline: lexical feature extraction, brand target matcher, suspicious TLD detection, incident persistence, and WebSocket alert emission. |
| **Media Deepfake Check** | **PARTIAL / STUBBED** | `services/backend/src/controllers/checkController.js:133-192`<br>`services/ml-service/app/services/media_engine.py:8-37` | Gateway handles request and persists incident, but Python ML service has a static stub: returns hardcoded score 87 / High risk for all inputs. ViT and ASVspoof models are not loaded. |
| **Login Telemetry Ingestion** | **DONE** | `services/backend/src/controllers/telemetryController.js:38-200`<br>`services/ml-service/app/services/login_engine.py:5-13` | Full pipeline: validates ISO timestamp and non-negative attempts, calls Cowrie Isolation Forest anomaly model, logs to `login_events`, persists incident if anomalous. |
| **System Telemetry Ingestion** | **DONE** | `services/backend/src/controllers/telemetryController.js:205-305`<br>`services/ml-service/app/services/system_engine.py:29-65` | Ingests Guard App host metrics, calls hybrid `NetworkThreatModel` (Supervised + Isolation Forest), logs to `telemetry_events`, persists incident if anomalous. |
| **Incident Listing & Filters** | **DONE** | `services/backend/src/controllers/incidentController.js:16-112` | Paginated listing with limit/offset, risk level, threat type, and status filtering. Batch-loads actions and MITRE mappings without N+1 queries. Scoped to user or organization. |
| **Incident Details** | **DONE** | `services/backend/src/controllers/incidentController.js:117-200` | Scoped by tenant/user (returns 404 for cross-tenant). Fetches child detection signals, evidence, recommended actions, and MITRE mapping. |
| **Incident Status Update** | **DONE** | `services/backend/src/controllers/incidentController.js:205-238` | Restricted to `role: 'admin'`. Scoped to admin's organization. Automatically records `resolved_by` and `resolved_at`. |
| **Remediation Action Update** | **DONE** | `services/backend/src/controllers/actionController.js:14-67` | Allows authenticated users to mark remediation steps as `taken` or `dismissed` on accessible incidents. |
| **Guardian Link Initiation** | **DONE** | `services/backend/src/controllers/guardianController.js:13-56` | Enforces self-link rejection, verifies caller is either guardian or dependent, persists link with status `pending`. |
| **Guardian Link Acceptance** | **DONE** | `services/backend/src/controllers/guardianController.js:61-102` | Strictly requires caller to be `dependent_user_id`. Transitions status from `pending` to `active`. |
| **Guardian Link Decline** | **DONE** | `services/backend/src/controllers/guardianController.js:107-148` | Strictly requires caller to be `dependent_user_id`. Transitions status from `pending` to `revoked`. |
| **Guardian Link Revocation** | **PARTIAL / BUGGED** | `services/backend/src/controllers/guardianController.js:153-155` | Alias to decline endpoint. **Bug:** Guardians cannot revoke links they created; only dependents can call it, and only when link is still `pending`. |
| **Guardian Alert Feed** | **DONE** | `services/backend/src/controllers/guardianController.js:160-203` | Queries active dependents linked to requesting guardian and filters for High and Critical incidents. |
| **Analytics Overview** | **DONE** | `services/backend/src/controllers/analyticsController.js:11-62` | Computes active/resolved threats, risk breakdown, and threat category distribution via parameterized SQL. Scoped by user/org. |
| **Analytics Trends** | **DONE** | `services/backend/src/controllers/analyticsController.js:67-95` | Time-series aggregation grouping by day. Scoped by user/org. |
| **MITRE ATT&CK Matrix** | **DONE** | `services/backend/src/controllers/analyticsController.js:100-117` | Technique frequency counts grouped by technique ID and name. Scoped by user/org. |
| **Real-Time WebSockets** | **DONE** | `services/backend/src/config/socket.js:14-87`<br>`services/backend/src/services/incidentService.js:125-163` | Socket.io server with JWT handshake auth, user/org/guardian room multiplexing, and `incident:new` broadcast on incident creation. |
| **Database RLS Policies** | **DONE** | `services/backend/sql/rls_policies.sql:1-710` | Row Level Security policies across all 10 core tables with security definer helper functions (`get_auth_org_id()`, `is_admin()`). |
| **Desktop Sensor Agent** | **DONE** | `services/guard-app/main.py:1-190` | Real and simulated OS socket flow capture forwarding to Gateway or ML engine directly. |

---

## 2. Codebase Annotations & Unfinished Logic

### 2.1 Explicit TODO Comments Found in Code

1. **`services/backend/src/controllers/authController.js:26`**
   ```javascript
   // TODO: Hash password using bcrypt, verify email uniqueness, and insert into database via User.create()
   ```
   *Impact:* Registration is completely disconnected from the database. Users cannot create real accounts.
2. **`services/backend/src/controllers/authController.js:54`**
   ```javascript
   // TODO: Query User.findByEmail(email), verify password hash with bcrypt.compare(), and return 401 if invalid
   ```
   *Impact:* Login allows arbitrary passwords and generates tokens with fixed mock IDs.
3. **`services/backend/src/controllers/authController.js:76`**
   ```javascript
   // TODO: Query User.findById(req.user.id) and return fresh database record
   ```
   *Impact:* `/auth/me` does not return database profile data or respect role updates in the DB.
4. **`services/backend/src/config/socket.js:16`**
   ```javascript
   // TODO: Restrict origin to actual frontend/mobile app origins before production deployment; intentionally open for local development only.
   ```
   *Impact:* Socket.io allows connections from any origin (`*`). Acceptable for local dev, dangerous in production.
5. **`services/ml-service/app/services/media_engine.py:8`**
   ```python
   # TODO: Load Vision Transformer (ViT) checkpoint for image boundary artifacts or ASVspoof audio anti-spoofing classifier for synthetic voice synthesis anomalies.
   ```
   *Impact:* Media deepfake inspection returns static mock data.

### 2.2 Commented-Out Logic & Enhancements
- **`services/backend/sql/rls_policies.sql:326-332`:** Commented-out policy snippet for direct client-side Supabase PostgREST access from mobile/web clients.
- **`services/backend/src/middlewares/rateLimiter.js:44-49`:** Note outlining future migration from IP-based rate limiting to authenticated `user_id` quota tracking.
- **`services/backend/src/services/incidentService.js:13-19`:** Hardcoded fallback score dictionary (`FALLBACK_SCORES = { critical: 90, high: 70, medium: 45, low: 20, safe: 5 }`) used whenever detection engines do not return explicit numeric risk scores.

---

## 3. Contract & Documentation Mismatches

| Specification in `docs/API_CONTRACT.md` | Actual Code Behavior | Affected Files | Severity |
|---|---|---|---|
| **Risk Level Enums:** Documented as TitleCase (`"Safe"`, `"Low"`, `"Medium"`, `"High"`, `"Critical"`). | Database and `GET /incidents` return lowercase (`"safe"`, `"low"`, etc.). FastAPI and check endpoints return TitleCase. | `Incident.js:19`, `incidentController.js:88-99`, `checkController.js:63-70` | **HIGH** |
| **Check Message Recommended Action:** Documented as singular string `recommended_action: string`. | Actually returns array of strings: `recommended_actions: string[]`. | `checkController.js:67`, `API_CONTRACT.md:173` | **MEDIUM** |
| **Action Items in Incidents:** Not explicitly detailed in check contracts. | In `GET /incidents`, actions are objects `[{ id, action_type, action_status, created_at }]`. In `POST /check/message`, actions are string arrays `["Do not click..."]`. | `checkController.js:67`, `incidentController.js:68-74` | **HIGH** |
| **Authentication Functionality:** Documented as a full PostgreSQL bcrypt persistence engine. | Implementation is an in-memory stub returning hardcoded UUIDs and dummy users. | `authController.js:27-40, 55-69` | **CRITICAL** |
| **Incident Status Update Roles:** Documented as "Admin-only for org-wide incidents". | Code applies `roleCheck(['admin'])` indiscriminately. Non-admins cannot update their own incidents. | `incidentRoutes.js:11` | **MEDIUM** |
| **Organization Table Naming:** `rls_policies.sql` and tests reference `organizations`. Model references `organisations`. | `Organization.js` uses British spelling `organisations`. Will fail if PostgreSQL table is named `organizations`. | `Organization.js:9,18,24,30`, `test_tenant_isolation.js:38` | **HIGH** |
| **User Organization Column:** `rls_policies.sql` uses `organization_id`. `User.js:11` inserts `org_id`. | `User.js` has legacy references to `org_id`. | `User.js:9-15, 28` | **MEDIUM** |

---

## 4. Frontend Risks & Bugs

### 4.1 Risk Level Casing Collision
- **Issue:** Depending on which endpoint the frontend calls, `risk_level` arrives as either TitleCase (`"Critical"`) or lowercase (`"critical"`).
- **Frontend Impact:** A strict conditional like `if (incident.risk_level === 'High')` will evaluate to `false` when parsing incidents from `GET /api/v1/incidents`.
- **Frontend Remedy:** The frontend must enforce `.toLowerCase()` on all incoming risk level strings:
  ```typescript
  const normalizedRisk = incident.risk_level.toLowerCase();
  ```

### 4.2 Inconsistent Response Envelope Shapes
- **Issue:** No standardized envelope exists:
  - `GET /api/v1/incidents` returns `{ total, limit, offset, incidents, data }`.
  - `GET /api/v1/guardian/alerts` returns an array `[...]`.
  - `GET /api/v1/analytics/trends` returns an array `[...]`.
  - `GET /api/v1/analytics/overview` returns an object with nested sub-objects.
  - `POST /api/v1/check/message` returns `{ id, risk_level, explanation, recommended_actions, signals }`.
- **Frontend Remedy:** API clients must not use a generic response unwrapper (e.g. `res.data.data`). Each endpoint requires its own explicit response mapping.

### 4.3 Guardian Link Revocation Flaw
- **Issue:** In `services/backend/src/controllers/guardianController.js` (lines 118–125), `declineGuardianLink` contains:
  ```javascript
  if (!link || link.dependent_user_id !== req.user?.id) {
    return res.status(404).json({ error: 'NOT_FOUND', message: 'Guardian link not found' });
  }
  ```
  And line 130 rejects any link whose status is not `'pending'`.
- **Frontend Impact:**
  1. A **guardian** who initiated a link cannot cancel it. If they call `POST /guardian/link/:id/revoke`, they receive `404 Not Found`.
  2. Once a link is `'active'`, neither party can revoke it via this endpoint (returns `400 Bad Request`).
- **Frontend Remedy:** Warn the user that guardian links are permanent once accepted until the backend team exposes a true deletion endpoint.

### 4.4 Lack of Multipart File Upload
- **Issue:** `POST /api/v1/check/media` only accepts `{ file_url, media_type }`. There is no endpoint in the Node gateway or Supabase driver to upload image or audio binaries.
- **Frontend Impact:** The frontend cannot provide a direct "Upload Image" form unless it uses an external cloud bucket (e.g. Cloudinary, AWS S3, or Supabase Storage direct client) and passes the resulting URL to the backend.

### 4.5 Lack of Real User Persistence in Auth
- **Issue:** Signing up with a new email does not create a database record in `users`.
- **Frontend Impact:** When testing multi-user flows (e.g. linking Guardian User A with Dependent User B), the frontend cannot rely on `POST /auth/signup` to generate distinct database UUIDs because both calls will return dummy ID `a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d`. Linking two accounts with identical IDs will fail with `400 INVALID_LINK` ("cannot link to self").

---

## 5. Security & Vulnerability Audit

1. **Authentication Bypass & Dummy Credentials (CRITICAL):**
   - In `authController.js`, password verification is omitted. Anyone can log in as any user without credentials.
   - JWT tokens are signed with dummy UUIDs, meaning multiple users share the same user ID if using the public auth endpoints.
2. **Hardcoded Secrets Fallback (HIGH):**
   - In `authController.js:3`, `JWT_SECRET` defaults to `'cyberguard-dev-secret-key'`. If `process.env.JWT_SECRET` is unset, tokens signed with this key are valid.
3. **Wildcard CORS in Sockets & Express (MEDIUM):**
   - `cors({ origin: '*' })` is active on both HTTP and WebSocket servers. In a production environment, this allows cross-site WebSocket hijacking (CSWSH) if cookies or local storage tokens are intercepted.
4. **IP-Based Rate Limiting Vulnerability (LOW-MEDIUM):**
   - Rate limiters track IP address rather than account ID. Users behind corporate NATs or mobile carrier CGNATs will share the 5-request login quota and 100-request check quota, potentially locking out entire offices.
5. **No Token Revocation / Blacklist (MEDIUM):**
   - Tokens have a 7-day lifetime. If a token is compromised, there is no blacklist table or Redis store to revoke it prior to expiration.
6. **Input Sanitization in ML Service (STRENGTH):**
   - `services/ml-service/app/prompts/phishing.py` enforces robust prompt injection defenses, XML boundary tag sandboxing, ASCII defanging, and strict output token caps (512 tokens).

---

## 6. Test Suite Coverage Analysis

### 6.1 Existing Backend Tests (`services/backend/`)
The backend contains 10 extensive test files using raw node scripts and the `pg` driver:
1. `test_phase5_e2e_and_security.js`: Validates JWT presence, expired tokens, forged signatures, malformed JSON, and live E2E check flows.
2. `test_tenant_isolation.js`: 591 lines verifying cross-tenant barriers between Org A and Org B across incidents, evidence, and actions.
3. `test_rate_limiting.js`: Verifies 429 response when throttling limits are exceeded.
4. `test_guardian_handshake.js`: Verifies link creation, dependent acceptance, decline, and dependent alert filtering.
5. `test_incident_management.js`: Tests incident status transitions, pagination, and sorting.
6. `test_incident_endpoints.js`: Tests scoped incident retrieval and 404 behavior for cross-tenant IDs.
7. `test_telemetry_persistence.js`: Tests insertion and resolution of foreign key devices in `login_events` and `telemetry_events`.
8. `test_mitre_integration.js`: Tests MITRE technique mapping persistence and aggregate queries.
9. `test_e2e_pipeline.js`: End-to-end check from Express to FastAPI.
10. `test_e2e_integration_p4.js`: Phase 4 pipeline verification.

### 6.2 Untested Areas
- **Real Database Authentication:** Because `authController.js` is stubbed, there are zero tests verifying password hashing, password comparisons, duplicate email rejections, or database user retrieval.
- **Client Disconnects & Reconnections:** Socket.io room re-subscription after network drops is not tested.
- **Mobile Push Notifications:** No tests for FCM push delivery or token registration.
- **Media File Parsing:** No tests verifying audio/image file corruption handling.

---

## 7. Missing Endpoints Needed by Frontend

A production-grade web or mobile frontend will require the following endpoints:

| Missing Endpoint | Method | Recommended Purpose | Priority |
|---|---|---|---|
| `/api/v1/auth/refresh` | `POST` | Exchanges an expiring JWT or refresh cookie for a new access token without re-entering credentials. | **Blocking** |
| `/api/v1/auth/logout` | `POST` | Invalidates current token session / clears HTTP cookies. | Non-blocking |
| `/api/v1/auth/forgot-password` | `POST` | Initiates password reset email flow. | Non-blocking |
| `/api/v1/users/me` | `PATCH` | Updates user display name, profile details, or avatar. | Non-blocking |
| `/api/v1/media/upload` | `POST` | Generates a presigned S3/Supabase upload URL or accepts `multipart/form-data` for deepfake media inspection. | **Blocking** |
| `/api/v1/guardian/links` | `GET` | Lists all active and pending guardian relationships for the current user. | **Blocking** |
| `/api/v1/guardian/link/:id` | `DELETE` | Allows a guardian or dependent to permanently delete an existing link. | Non-blocking |
| `/api/v1/devices` | `GET` | Lists all registered devices for the current user to display in security settings. | Non-blocking |
| `/api/v1/devices/:id` | `DELETE` | Revokes a device's trusted status or removes it from user profile. | Non-blocking |
| `/api/v1/audit-logs` | `GET` | Enterprise audit trail log for SOC analysts and compliance. | Non-blocking |

---

## 8. Frontend Handoff & Implementation Guide

### 8.1 Recommended Screens & Endpoint Mapping

#### Web Command Dashboard (`apps/web`)
1. **Login & Registration (`/login`, `/signup`):**
   - `POST /api/v1/auth/login`
   - `POST /api/v1/auth/signup`
2. **Executive Overview Dashboard (`/` or `/dashboard`):**
   - Metric Cards: `GET /api/v1/analytics/overview`
   - Trendline Chart: `GET /api/v1/analytics/trends`
   - MITRE ATT&CK Matrix: `GET /api/v1/analytics/mitre`
   - Real-Time Live Feed: Listen to Socket.io event `'incident:new'`
3. **Threat Inspection Scanner (`/scan`):**
   - Text Message Tab: `POST /api/v1/check/message`
   - Malicious URL Tab: `POST /api/v1/check/url`
   - Media Deepfake Tab: `POST /api/v1/check/media`
4. **Incident Triage Center (`/incidents`):**
   - Incident Table: `GET /api/v1/incidents?limit=25&offset=0&status=...&risk_level=...`
   - Incident Drawer / Modal: `GET /api/v1/incidents/:id`
   - Triage Action (Admin): `PATCH /api/v1/incidents/:id`
   - Remediation Checklist: `PATCH /api/v1/actions/:id`
5. **Guardian Management Hub (`/guardian`):**
   - Initiate Link: `POST /api/v1/guardian/link`
   - Dependent Security Alerts: `GET /api/v1/guardian/alerts`

#### Mobile Application (`apps/mobile`)
1. **Universal Message Checker (Share Sheet):**
   - `POST /api/v1/check/message` (supports read-aloud TTS of `explanation` and `recommended_actions`)
2. **QR Code / Link Scanner:**
   - `POST /api/v1/check/url`
3. **Guardian Mode Screen:**
   - Link Family Member: `POST /api/v1/guardian/link`
   - Incoming Requests: `POST /api/v1/guardian/link/:id/accept` and `/decline`
   - Dependent Alert Feed: `GET /api/v1/guardian/alerts`
4. **Push Notifications:**
   - Connect to Socket.io or FCM background handler for `'incident:new'` notifications.

---

### 8.2 Suggested API Client Implementation (TypeScript / Axios)

```typescript
// services/apiClient.ts
import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000,
});

// Request interceptor: attach Bearer token
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('cyberguard_token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor: handle 401 and normalized errors
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('cyberguard_token');
      window.location.href = '/login';
    }
    return Promise.reject(error.response?.data || error.message);
  }
);
```

---

### 8.3 Frontend Gotchas to Handle

1. **Case-Insensitive Risk Level Handling:**
   Always convert `risk_level` to lowercase before comparing:
   ```typescript
   const isHighRisk = incident.risk_level?.toLowerCase() === 'high';
   ```
2. **Handling Recommended Actions Divergence:**
   - When calling `POST /check/message`, actions arrive as strings: `["Quarantine email"]`.
   - When calling `GET /incidents`, actions arrive as objects: `[{ id, action_type, action_status }]`.
   - The UI renderer should support both:
     ```typescript
     const actionText = typeof action === 'string' ? action : action.action_type;
     ```
3. **Pagination Offsets:**
   The backend uses standard SQL `limit` and `offset` (not page numbers).
   - Page 1: `limit=25&offset=0`
   - Page 2: `limit=25&offset=25`
   - Page 3: `limit=25&offset=50`
4. **Socket.io Handshake Token:**
   Socket.io will reject the connection if the JWT token is missing or expired. Always pass `{ auth: { token } }` and listen to `connect_error`:
   ```javascript
   socket.on('connect_error', (err) => {
     console.error('Socket authentication failed:', err.message);
   });
   ```

---

## 9. Open Questions for the Backend Team

### 9.1 Blocking Questions (Must resolve to complete end-to-end frontend development)
1. **Database-Backed Authentication:** When will `authController.js` be connected to `User.create()` and `User.findByEmail()` with real `bcrypt` hashing, so distinct test users can be created in the database?
2. **File Upload Strategy:** How should the frontend handle image and audio uploads for `POST /api/v1/check/media`? Will the backend provide a `POST /upload` endpoint (or Supabase Storage presigned URL), or should the frontend upload directly to third-party storage?
3. **Listing Guardian Links:** What endpoint should the frontend call to list existing pending and active guardian links (`GET /guardian/links` is currently missing)?
4. **Guardian Link Revocation:** Can the `POST /guardian/link/:id/revoke` endpoint be updated so that:
   - A guardian can cancel their pending link request?
   - An active link can be revoked by either guardian or dependent?
5. **Database Table Name Resolution:** Does the production database use `organizations` or `organisations`? (`Organization.js` uses `organisations`, while `rls_policies.sql` and tests use `organizations`).

### 9.2 Non-Blocking Questions (Can proceed with mock or interim logic)
6. **Token Expiry & Refresh:** Is a refresh token workflow (`POST /auth/refresh`) planned, or will sessions strictly expire after 7 days?
7. **Per-User Rate Limiting:** When will rate limiting transition from IP-based keys to `user_id`-based keys to prevent shared NAT lockouts?
8. **ViT & ASVspoof Model Deployment:** What is the timeline for loading the actual PyTorch Vision Transformer and ASVspoof models in `services/ml-service` to replace the static media check stub?
9. **FCM Push Notification Dispatcher:** Will the Node Gateway dispatch Firebase Cloud Messaging push alerts automatically when `persistDetectionIncident` triggers, or should the mobile client rely entirely on Socket.io foreground events?
10. **Individual Incident Status Editing:** Should non-admin users be allowed to mark their own personal incidents as `resolved`, or is triage permanently restricted to the `admin` role?
