# Backend Development Branch Audit Report (`origin/dev`) — Audit #2

**Date:** 2026-10-03  
**Auditor:** Pair Programming Assistant (Antigravity AI)  
**Target Branch:** `origin/dev` (commit `ee397be`)  
**Comparison Baseline:** `feature/frontend-dashboard` (`API_REFERENCE.md`, `types.ts`, `apps/web/src/services/*`)  
**Scope:** Read-only verification of backend claims, implementation audits, schema drift, breaking contract changes, and risk evaluation.

---

## 1. Recent Commit History on `origin/dev` (Last 20 Commits)

Fetched via `git log origin/dev -20 --format="%h | %an | %ad | %s"`:

| Commit Hash | Author | Commit Date | Subject / Description |
|---|---|---|---|
| `ee397be` | Subha Sankar Sahu | 2026-10-03 | Merge branch 'dev' of https://github.com/teamvisioncraft875-netizen/CyberGuard into dev |
| `1d66353` | Subha Sankar Sahu | 2026-10-03 | docs: add project overview and system architecture documentation |
| `b077066` | Abhijit | 2026-10-03 | Merge pull request #25 from teamvisioncraft875-netizen/feature/live-execution |
| `6a93b35` | Abhijit | 2026-10-03 | Merge pull request #24 from teamvisioncraft875-netizen/feature/secret-detection |
| `4e9c6e5` | Abhijit | 2026-10-03 | Merge pull request #23 from teamvisioncraft875-netizen/feature/response-policy-engine |
| `3cf59d7` | Subha Sankar Sahu | 2026-10-03 | feat: execute endpoint for live action approval and triggering, with guardrails and audit logging |
| `80e6b26` | Subha Sankar Sahu | 2026-10-03 | chore: merge feature/response-policy-engine into feature/live-execution for Phase 2B endpoint wiring |
| `a2507ad` | Subha Sankar Sahu | 2026-10-03 | feat: execution service core with five executors (revoke, block IP/domain, suspend device, force password reset) and guardrails |
| `46ad2fe` | Subha Sankar Sahu | 2026-10-03 | feat: secret/credential exposure detection, scans for leaked env vars and API keys with severity scoring |
| `22375f5` | Subha Sankar Sahu | 2026-10-03 | feat: email notification service, sends alerts for shadow and proposed actions |
| `75c7c3c` | Subha Sankar Sahu | 2026-10-03 | feat: response policy engine in shadow mode, calculates and logs decisions without executing |
| `4da07d2` | Subha Sankar Sahu | 2026-10-02 | feat: append-only audit logging service, audit-logs endpoint, restore full schema and fix RLS helpers |
| `d719a4b` | Abhijit | 2026-10-02 | Merge pull request #22 from teamvisioncraft875-netizen/feature/full-system-sprint |
| `d58f2d2` | Subha Sankar Sahu | 2026-10-01 | docs: add enterprise security audit and next sprint recommendations documentation |
| `f830eca` | Subha Sankar Sahu | 2026-09-30 | feat: add Redis caching for external threat APIs and refresh tokens |
| `42d4b0d` | Subha Sankar Sahu | 2026-09-30 | implement dual-token authentication: 15-min access tokens, 7-day refresh tokens with rotation, logout revocation |
| `b1edbb0` | Subha Sankar Sahu | 2026-09-30 | feat: add backend API gateway, media upload service, database storage setup, and API contract documentation |
| `ecd787d` | Subha Sankar Sahu | 2026-09-30 | implement guardian mode gaps: list links, search users by email, revoke endpoint for either party |
| `bde1410` | Subha Sankar Sahu | 2026-09-30 | feat: real authentication, schema fixes, risk-level normalization, and mobile web setup |
| `417728c` | Abhijit | 2026-09-29 | Merge pull request #21 from teamvisioncraft875-netizen/feature/deepfake_media_engine |

---

## 2. Claim-by-Claim Verification Table

| Area | Audit Claim / Question | Status | Implementation Evidence (File & Line Numbers) | Key Architectural Details |
|---|---|---|---|---|
| **AUTH** | Signup/login querying real DB & hashing passwords with bcrypt (not returning hardcoded dummy)? | **DONE** | [`services/backend/src/controllers/authController.js:95-106`](../../services/backend/src/controllers/authController.js#L95-L106)<br>[`services/backend/src/controllers/authController.js:173-195`](../../services/backend/src/controllers/authController.js#L173-L195)<br>[`services/backend/src/models/User.js:9-37`](../../services/backend/src/models/User.js#L9-L37) | `bcrypt.hash(password, 10)` generates real hash. `User.create` and `User.findByEmail` execute parameterized SQL queries against `users` table. Hardcoded dummy UUID is completely eradicated. Returns real DB record with 201/200. |
| **AUTH** | Does `POST /auth/refresh` exist and actually work? | **DONE** | [`services/backend/src/routes/authRoutes.js:12`](../../services/backend/src/routes/authRoutes.js#L12)<br>[`services/backend/src/controllers/authController.js:266-347`](../../services/backend/src/controllers/authController.js#L266-L347)<br>[`services/backend/src/models/RefreshToken.js:68-145`](../../services/backend/src/models/RefreshToken.js#L68-L145) | Public endpoint, accepts `req.body.refreshToken` or `req.cookies.refreshToken`. Verifies SHA-256 token hash against Redis cache first, then PostgreSQL `refresh_tokens`. Validates non-revoked and non-expired state, then issues fresh 15-minute access token. Verified by 7-step test suite in `test_token_refresh.js`. |
| **AUTH** | Does `POST /auth/logout` exist? | **DONE** | [`services/backend/src/routes/authRoutes.js:16`](../../services/backend/src/routes/authRoutes.js#L16)<br>[`services/backend/src/controllers/authController.js:354-387`](../../services/backend/src/controllers/authController.js#L354-L387)<br>[`services/backend/src/models/RefreshToken.js:153-184`](../../services/backend/src/models/RefreshToken.js#L153-L184) | Protected route (`auth` middleware). Calls `RefreshToken.revokeByUserId(req.user.id)` updating DB `is_revoked = TRUE` and evicting all active user hashes from Redis. Clears the `refreshToken` HttpOnly cookie via `res.clearCookie('refreshToken', { path: '/' })`. Returns `{ message: 'Logged out' }`. |
| **AUTH** | What is the configured access token and refresh token expiry? | **DONE** | [`services/backend/src/controllers/authController.js:10,16`](../../services/backend/src/controllers/authController.js#L10)<br>[`services/backend/src/models/RefreshToken.js:5-6,35`](../../services/backend/src/models/RefreshToken.js#L5-L6) | **Access Token Expiry:** Exactly **`15m`** (15 minutes short-lived).<br>**Refresh Token Expiry:** Exactly **`7 days`** (`INTERVAL '7 days'`, cookie `maxAge: 7 * 24 * 60 * 60 * 1000`, Redis TTL `604,800` seconds). |
| **GUARDIAN** | Does `GET /guardian/links` exist and query real data? | **DONE** | [`services/backend/src/routes/guardianRoutes.js:8`](../../services/backend/src/routes/guardianRoutes.js#L8)<br>[`services/backend/src/controllers/guardianController.js:205-234`](../../services/backend/src/controllers/guardianController.js#L205-L234)<br>[`services/backend/src/models/GuardianLink.js:64-103`](../../services/backend/src/models/GuardianLink.js#L64-L103) | Protected route. Queries `guardian_links` joined with `users` (`ug` and `ud`) for real data. Scoped by user ID (or organization for admin). Supports `?status=active|pending|revoked|all` (defaults to hiding revoked links). Returns `{ links: [...] }`. |
| **GUARDIAN** | Is the guardian revoke bug fixed (initiating guardian unable to revoke their own pending link)? | **DONE** | [`services/backend/src/controllers/guardianController.js:253`](../../services/backend/src/controllers/guardianController.js#L253) | **Fixed:** Previously rejected if `link.dependent_user_id !== req.user.id`. Now checks: `if (!link \|\| (link.guardian_user_id !== req.user?.id && link.dependent_user_id !== req.user?.id))`. Either party (guardian or dependent) can now revoke pending or active links. |
| **GUARDIAN** | Does `GET /users/search?email=...` exist? | **DONE** | [`services/backend/src/routes/userRoutes.js:8`](../../services/backend/src/routes/userRoutes.js#L8)<br>[`services/backend/src/routes/guardianRoutes.js:14`](../../services/backend/src/routes/guardianRoutes.js#L14)<br>[`services/backend/src/controllers/guardianController.js:302-346`](../../services/backend/src/controllers/guardianController.js#L302-L346)<br>[`services/backend/src/models/User.js:50-72`](../../services/backend/src/models/User.js#L50-L72) | Mounted at both `GET /api/v1/users/search` and `GET /api/v1/guardian/users/search`. Protected route, rate-limited via `searchLimiter`. Queries `User.searchByEmail` with tenant/role scoping. Returns sanitized user data `{ users: [...], user: {...}, ...user }` without password hash. |
| **MEDIA** | Does `POST /media/upload-url` exist? | **DONE** | [`services/backend/src/routes/mediaRoutes.js:8`](../../services/backend/src/routes/mediaRoutes.js#L8)<br>[`services/backend/src/routes/checkRoutes.js:13`](../../services/backend/src/routes/checkRoutes.js#L13)<br>[`services/backend/src/controllers/mediaController.js:25-76`](../../services/backend/src/controllers/mediaController.js#L25-L76) | Mounted at `POST /api/v1/media/upload-url` and aliased at `POST /api/v1/check/media/upload-url`. Requires Bearer auth. Validates `media_type` ('image'/'audio') and enforces `file_size_bytes <= 50MB`. |
| **MEDIA** | Does it generate real Supabase signed URLs? | **DONE** | [`services/backend/src/config/storage.js:10-14,72-88`](../../services/backend/src/config/storage.js#L10-L14) | Uses `@supabase/supabase-js` storage client `supabase.storage.from(BUCKET_NAME).createSignedUploadUrl(filePath, { expiresIn: 3600 })`. Scopes file path to `uploads/${userId}/${timestamp}_${randomId}.${ext}`. Includes deterministic signed storage URL fallback for offline/development environments. |
| **MEDIA** | Has `/check/media` been updated to work with this new flow, or does it still only accept raw `file_url`? | **DONE** | [`services/backend/src/controllers/checkController.js:142-163`](../../services/backend/src/controllers/checkController.js#L142-L163)<br>[`services/backend/src/config/storage.js:104-134`](../../services/backend/src/config/storage.js#L104-L134) | **Updated:** Accepts **either** `file_path` (from upload-url response) or `file_url`. Enforces tenant isolation via `validateUserMediaOwnership`: rejects requests with 403 Forbidden if a user tries to analyze a file uploaded under another user's ID. Resolves internal storage paths to authenticated Supabase URLs before forwarding to FastAPI ML engine. |
| **INCIDENTS** | Response shape of `GET /incidents` and `GET /incidents/:id` verified? Risk-level casing inconsistency fixed? | **PARTIAL** | [`services/backend/src/controllers/incidentController.js:89-108,180-196`](../../services/backend/src/controllers/incidentController.js#L89-L108)<br>[`services/backend/src/controllers/checkController.js:68,126,211`](../../services/backend/src/controllers/checkController.js#L68)<br>[`services/backend/src/controllers/guardianController.js:382`](../../services/backend/src/controllers/guardianController.js#L382) | Exact response shapes confirmed (see Section 3).<br>**Casing Status:** `GET /incidents` and `GET /incidents/:id` return **lowercase** (`"safe"`, `"low"`, `"medium"`, `"high"`, `"critical"`). In addition, `POST /check/*` has now been normalized to **lowercase**.<br>**Remaining Inconsistency:** `GET /guardian/alerts` (line 382) STILL capitalizes `risk_level` to TitleCase (`"High"`, `"Critical"`). |
| **NEW ENDPOINTS** | Does `POST /check/secret` exist? | **DONE** | [`services/backend/src/routes/checkRoutes.js:16`](../../services/backend/src/routes/checkRoutes.js#L16)<br>[`services/backend/src/controllers/checkController.js:224-306`](../../services/backend/src/controllers/checkController.js#L224-L306)<br>[`services/backend/src/services/secretDetector.js:8-233`](../../services/backend/src/services/secretDetector.js#L8-L233) | Public endpoint, strictly rate-limited (`20 req / 15m`). Comprehensive pattern catalog detecting AWS credentials, Postgres/MySQL URLs, RSA/SSH private keys, GitHub/Stripe/Slack tokens, JWT secrets, and high-entropy API keys. Persists incident if credentials are leaked. |
| **ENTERPRISE / SCHEDULER** | Does Enterprise Agent / background scheduler expose or change any endpoint the frontend would call? | **NOT FOUND on `dev`** | [`origin/feature/background-scheduler`](../../services/backend/src/services/schedulerService.js) (unmerged) | The background scheduler (`schedulerService.js`) is **NOT merged into `origin/dev`**; it lives on branch `feature/background-scheduler`. On `dev`, the Response Policy Engine (`services/backend/src/services/PolicyEngine.js`) runs in shadow mode during incident ingestion. New admin endpoints (`/api/v1/admin/*` and `/api/v1/audit-logs`) exist for admins, but no existing frontend endpoints were changed. |
| **SOCKET.IO** | Confirm `'incident:new'` payload shape is unchanged or changed from before — list exact fields. | **DONE** (Unchanged) | [`services/backend/src/services/incidentService.js:152-163`](../../services/backend/src/services/incidentService.js#L152-L163) | Payload shape is **100% UNCHANGED** and matches `IncidentNewSocketPayload` in `types.ts` field-for-field (10 fields: `id`, `threat_type`, `source_type`, `risk_level`, `risk_score`, `explanation`, `status`, `created_at`, `recommended_actions`, `signals`). `risk_level` is lowercase. Emits to `user:<id>`, `org:<id>`, and `guardian:<id>`. |

---

## 3. Exact Response Shapes for Incidents Endpoints

### 3.1 `GET /api/v1/incidents`
Implemented in [`services/backend/src/controllers/incidentController.js:89-108`](../../services/backend/src/controllers/incidentController.js#L89-L108).

**Top-Level Response Shape:**
```json
{
  "total": 42,
  "limit": 25,
  "offset": 0,
  "incidents": [ ... ],
  "data": [ ... ]
}
```
*Note: `data` is an exact array alias of `incidents` provided for frontend convenience.*

**Each Incident Object Contains Exactly These 10 Fields:**
1. `id` *(string - UUID)*
2. `threat_type` *(string, e.g. `"phishing"`, `"malicious_url"`, `"deepfake"`)*
3. `source_type` *(string, e.g. `"email"`, `"url"`, `"image"`, `"audio"`)*
4. `risk_level` *(string, **strictly lowercase**: `"safe"`, `"low"`, `"medium"`, `"high"`, `"critical"`)*
5. `risk_score` *(number, 0 to 100)*
6. `explanation` *(string)*
7. `status` *(string: `"open"`, `"investigating"`, or `"resolved"`)*
8. `created_at` *(timestamp ISO 8601)*
9. `recommended_actions` *(array of objects)*:
   - `id` *(string - UUID)*
   - `action_type` *(string)*
   - `action_status` *(string: `"pending"`, `"taken"`, `"dismissed"`)*
   - `created_at` *(timestamp ISO 8601)*
10. `mitre_mappings` *(array of objects)*:
    - `id` *(string - UUID)*
    - `technique_id` *(string, e.g. `"T1566"`)*
    - `technique_name` *(string, e.g. `"Phishing"`)*

---

### 3.2 `GET /api/v1/incidents/:id`
Implemented in [`services/backend/src/controllers/incidentController.js:180-196`](../../services/backend/src/controllers/incidentController.js#L180-L196).

**Top-Level Response Shape (Single Object Directly Returned):**
Contains exactly these **16 fields**:
1. `id` *(string - UUID)*
2. `user_id` *(string - UUID)*
3. `organization_id` *(string - UUID or null)*
4. `threat_type` *(string)*
5. `source_type` *(string)*
6. `risk_level` *(string, **strictly lowercase**: `"safe"`, `"low"`, `"medium"`, `"high"`, `"critical"`)*
7. `risk_score` *(number, 0 to 100)*
8. `explanation` *(string)*
9. `status` *(string: `"open"`, `"investigating"`, `"resolved"`)*
10. `resolved_by` *(string - UUID or null)*
11. `resolved_at` *(timestamp ISO 8601 or null)*
12. `created_at` *(timestamp ISO 8601)*
13. `recommended_actions` *(array of objects, same 4 fields as in `listIncidents`)*
14. `mitre_mappings` *(array of objects: `id`, `technique_id`, `technique_name`)*
15. `detection_signals` *(array of objects)*:
    - `signal_name` *(string)*
    - `signal_value` *(string)*
    - `weight` *(number or null)*
16. `evidence` *(array of raw database rows from `incident_evidence` table)*

---

## 4. Breaking Changes vs. Frontend `API_REFERENCE.md`, `types.ts`, and `services/*.js`

This section details every discrepancy that will break or degrade the frontend if merged without code adjustments.

### 4.1 🚨 CRITICAL: Token Expiry Shortened to 15 Minutes without Client Refresh Handling
- **Backend Reality:** Access tokens now expire in **15 minutes** (`ACCESS_TOKEN_EXPIRY = '15m'` in `authController.js:10`). A 7-day refresh token is issued during login/signup and sent via both JSON body and HttpOnly cookie.
- **Frontend Current State:**
  - `apps/web/src/services/apiClient.js:43-57`: When Axios receives a `401`, it immediately deletes `localStorage.getItem('cyberguard_token')` and dispatches `cyberguard:unauthorized` to kick the user out to `/login`.
  - `apps/web/src/services/authService.js`: Has NO refresh method and does not store or forward `refreshToken`.
- **Breaking Impact:** After 15 minutes of user interaction, all subsequent API calls will fail with `401 TOKEN_EXPIRED`, unexpectedly logging out active users.
- **Frontend Action Required in `apps/web/src/services/apiClient.js` & `authService.js`:**
  1. Add an Axios response interceptor queue for `401` errors that attempts to call `POST /api/v1/auth/refresh` using the refresh token (or relying on `withCredentials: true` for the HttpOnly cookie).
  2. Update `authService.js` to store `refreshToken` upon login/signup and export a `refresh()` method.
  3. Wire `authService.logout()` to call `POST /api/v1/auth/logout` with Bearer auth to invalidate refresh tokens on the server instead of just client-side clearing.

---

### 4.2 ⚠️ BREAKING: Employee Signup Requires `organization_name` (Not `organization_id`)
- **Backend Reality:** In [`authController.js:56-61`](../../services/backend/src/controllers/authController.js#L56-L61):
  ```javascript
  if (effectiveRole === 'employee' && (!organization_name || typeof organization_name !== 'string' || !organization_name.trim())) {
    return res.status(400).json({ error: 'MISSING_ORGANIZATION_NAME', message: 'Organization name is required for employee registration' });
  }
  ```
- **Frontend Current State:**
  - In `types.ts:167`: `SignupRequest` defines `organization_id?: string;`.
  - In `apps/web/src/services/authService.js:13`: `signup(email, password, full_name, role = 'individual')` sends `{ email, password, full_name, role }`.
- **Breaking Impact:** Any user attempting to sign up as an `employee` through the frontend will receive `400 MISSING_ORGANIZATION_NAME`.
- **Frontend Action Required in `apps/web/src/services/authService.js` & `SignupPage.jsx`:**
  - Update `authService.signup(email, password, full_name, role, organization_name)` to pass `organization_name`.
  - In `SignupPage.jsx`, if the user selects the "Employee" role tab, display a required "Organization Name" text input.

---

### 4.3 ⚠️ BREAKING: Direct Admin Signup Is Rejected (`400 INVALID_ROLE`)
- **Backend Reality:** In [`authController.js:49-54`](../../services/backend/src/controllers/authController.js#L49-L54):
  Role must be `'individual'` or `'employee'` only. A request sending `role: 'admin'` receives `400 INVALID_ROLE`. Admin privileges are only granted by being the *first employee* of a newly created organization.
- **Frontend Current State:**
  - `types.ts:3` defines `UserRole = 'individual' | 'employee' | 'admin'`.
- **Frontend Action Required:** Ensure UI registration dropdowns only allow selecting "Individual" or "Employee/Enterprise".

---

### 4.4 ⚠️ SUBTLE BREAKING: Threat Check Risk Levels Normalized to Lowercase
- **Backend Reality:** In `checkController.js:68, 126, 211`, `risk_level` is converted to lowercase:
  `risk_level: (mlResult.risk_level || 'low').toLowerCase()`.
  Values returned are now: `'safe'`, `'low'`, `'medium'`, `'high'`, `'critical'`.
- **Frontend Current State:**
  - In `types.ts:192`: `CheckResponse` documented `risk_level: RiskLevelTitleCase | RiskLevel;`.
  - In `API_REFERENCE.md:73`, check examples showed `"risk_level": "High"`.
  - Any frontend badge or styling logic using strict comparison like `risk_level === 'High'` or `risk_level === 'Critical'` will fail to match.
- **Remaining Casing Inconsistency:**
  - `GET /api/v1/guardian/alerts` ([`guardianController.js:382`](../../services/backend/src/controllers/guardianController.js#L382)) explicitly capitalizes `risk_level` to TitleCase: `row.risk_level ? row.risk_level.charAt(0).toUpperCase() + row.risk_level.slice(1) : 'High'`.
- **Frontend Action Required across all UI components:**
  - Always normalize risk levels using `.toLowerCase()` (e.g. `String(risk_level).toLowerCase() === 'high'`).

---

### 4.5 💡 NEW CAPABILITY: Media Upload Flow (`apps/web/src/services/scanService.js`)
- **Backend Reality:**
  - Added `POST /api/v1/media/upload-url` (accepts `{ media_type, file_size_bytes, file_name }`, returns `{ upload_url, file_path, expiry_seconds }`).
  - Updated `POST /api/v1/check/media` to accept `{ file_path, media_type }`.
  - Enforced tenant validation: `validateUserMediaOwnership` rejects paths outside `uploads/<user_id>/` with `403 FORBIDDEN`.
- **Frontend Current State:**
  - `scanService.js:33-40`: `checkMedia({ file_url, media_type = 'image' })` only supports submitting an already hosted `file_url`.
- **Frontend Action Required in `scanService.js`:**
  - Add `getMediaUploadUrl({ media_type, file_size_bytes, file_name })`.
  - Update `checkMedia` to accept either `file_path` or `file_url`.
  - Implement direct two-step file upload in the UI:
    1. Call `/media/upload-url` to get signed URL.
    2. `PUT` raw file binary directly to Supabase storage URL.
    3. Call `/check/media` with `{ file_path, media_type }`.

---

### 4.6 💡 NEW ENDPOINTS: Missing in Frontend Services
The frontend does not yet take advantage of the following newly implemented backend endpoints:
1. `POST /api/v1/check/secret`:
   - Scans code/text for leaked API keys, tokens, and database credentials.
   - Frontend `scanService.js` needs a `checkSecret({ input, context })` function.
2. `GET /api/v1/guardian/links`:
   - List active and pending links for Guardian Mode.
   - Frontend needs a `guardianService.js` with `listLinks({ status })`, `linkDependent()`, `acceptLink()`, `revokeLink()`.
3. `GET /api/v1/users/search?email=...`:
   - Search user by email for Guardian Mode link invitations.
   - Frontend needs `searchUser(email)` in `guardianService.js`.
4. `GET /api/v1/audit-logs`:
   - Admin audit log query endpoint with pagination and event filtering.
5. `POST /api/v1/admin/actions/:id/execute`:
   - Live automated response trigger for admins.

---

## 5. Anything the Original Claims Got Wrong or Exaggerated

During code inspection on `origin/dev`, we identified three key areas where past commit messages or sprint notes exaggerated backend state:

### 1. The Background Scheduler is NOT on `dev`
- **Claim:** Commit logs and PR summaries suggested an Enterprise Agent / Background Scheduler integration was operating on `dev`.
- **Code Audit Fact:** The background scheduler (`services/backend/src/services/schedulerService.js`) is **completely absent from `origin/dev`**. It resides on an unmerged feature branch: `origin/feature/background-scheduler` (commits `8e0fc8a` and `bbb4c63`).
- What *did* land on `dev` is the Response Policy Engine core (`PolicyEngine.js`), which runs strictly in shadow mode during incident ingestion, and the live manual execution endpoint (`/admin/actions/:id/execute`). The recurring 60-second background cron and circuit breaker have NOT been merged into `dev`.

### 2. "Refresh Token Rotation" Was Exaggerated
- **Claim:** Commit `42d4b0d` claimed: *"implement dual-token authentication: 15-min access tokens, 7-day refresh tokens with rotation, logout revocation"*.
- **Code Audit Fact:** In [`services/backend/src/controllers/authController.js:336-339`](../../services/backend/src/controllers/authController.js#L336-L339), calling `POST /api/v1/auth/refresh` verifies the submitted refresh token and generates a new access token, but **returns only `{ token: accessToken, accessToken }`**. It does **not** invalidate the used refresh token, nor does it issue a new refresh token (no rolling rotation). The original refresh token remains valid in Redis/Postgres for the full 7-day duration until explicit logout or expiry.

### 3. Risk-Level Normalization Left Gaps
- **Claim:** Commit `bde1410` stated: *"risk-level normalization across endpoints"*.
- **Code Audit Fact:** While `POST /api/v1/check/*` was correctly updated to output lowercase strings (`(mlResult.risk_level).toLowerCase()`), [`services/backend/src/controllers/guardianController.js:382`](../../services/backend/src/controllers/guardianController.js#L382) explicitly still capitalizes `risk_level` to TitleCase:
  ```javascript
  risk_level: row.risk_level ? row.risk_level.charAt(0).toUpperCase() + row.risk_level.slice(1) : 'High'
  ```
  Therefore, cross-endpoint casing remains inconsistent between incidents/checks (lowercase) and guardian alerts (TitleCase).

---

## 6. Audit Conclusion & Recommendations

The backend on `origin/dev` has achieved significant functional maturity:
- Real database persistence and bcrypt authentication are fully functional and verified by automated integration suites.
- Dual-token lifecycle (`POST /auth/refresh`, `POST /auth/logout`) and Redis caching are active.
- Guardian Mode link listing, user search, and bidirectional revocation are operational.
- Supabase direct-to-storage signed uploads and media ownership checks are implemented.
- Secret exposure detection (`POST /check/secret`) is ready.

Before merging `origin/dev` into the frontend dashboard branch, the frontend pair must update:
1. `apiClient.js` to handle 15-minute token expirations with silent refresh.
2. `authService.js` and `SignupPage.jsx` to pass `organization_name` for employee signups.
3. String normalization (`.toLowerCase()`) across all risk level badges and filters.
4. New service modules for Guardian Mode (`guardianService.js`) and direct media upload orchestration (`scanService.js`).
