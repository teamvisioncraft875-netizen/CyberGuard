# CyberGuard Settings & Account Management API Contract

> **Scope**: Backend capability audit on `origin/dev` (merged into `feature/frontend-dashboard`).  
> **Target Audience**: Frontend engineers building `apps/web/src/pages/SettingsPage.jsx` and API developers extending user management.  
> **Status**: Verified against current backend implementation (`services/backend/src`).

---

## 1. Quick Reference Matrix

| Feature / Capability | Exists in Backend? | Endpoint & Method | Auth Requirement | Backend Behavior / Notes |
| :--- | :---: | :--- | :--- | :--- |
| **Change Password** | ❌ **No** | *None* | N/A | No route or controller logic exists. `User.js` model prohibits updating `password_hash`. |
| **Profile Update** (`full_name`, email, etc.) | ❌ **No** | *None* | N/A | `users` table lacks a `full_name` column. No `PATCH /users/me` endpoint exists. |
| **Logout (Current Session)** | ❌ **No** | *None* | N/A | Cannot selectively revoke only the current device's refresh token. |
| **Logout (All Sessions)** | ✅ **Yes** | `POST /api/v1/auth/logout` | `Bearer <accessToken>` | Unconditionally revokes **ALL** active refresh tokens in PostgreSQL & Redis for the user. |
| **User Preferences / Notification Settings** | ❌ **No** | *None* | N/A | No preferences or notification settings table exists in DB. `notificationService` is internal only. |
| **Employee Organization Editing** | ❌ **No** | *None* | N/A | Strictly **read-only**. Organization is set at signup; no endpoint exists to update or leave it. |
| **Get Current User Profile** | ✅ **Yes** | `GET /api/v1/auth/me` | `Bearer <accessToken>` | Returns sanitized user object (`id`, `email`, `role`, `organization_id`, `created_at`). |

---

## 2. Detailed Audit Findings

### 1. Change Password Endpoint
- **Status**: **DOES NOT EXIST**
- **Evidence**:
  - `services/backend/src/routes/authRoutes.js` (Lines 9–17) only defines `signup`, `login`, `refresh`, `me`, and `logout`.
  - `services/backend/src/controllers/authController.js` contains no password update or reset methods.
  - `services/backend/src/models/User.js` (Line 3):
    ```javascript
    const ALLOWED_UPDATE_FIELDS = Object.freeze(['role', 'organization_id']);
    ```
    `password_hash` is explicitly excluded from `ALLOWED_UPDATE_FIELDS`, meaning the model does not support password changes even if an update query was executed.
- **Frontend Impact**: Any "Change Password" form on the Settings page cannot function against the current backend without adding a new backend endpoint (e.g., `POST /api/v1/auth/change-password` with old password verification and bcrypt hashing).

---

### 2. Profile Update (`full_name`, etc.)
- **Status**: **DOES NOT EXIST**
- **Evidence**:
  - Database schema for `public.users` contains only:
    `id` (UUID), `organization_id` (UUID), `email` (VARCHAR), `password_hash` (VARCHAR), `role` (VARCHAR), `created_at` (TIMESTAMPTZ).
    There is no `full_name`, `name`, `phone_number`, or `avatar_url` column in the database.
  - `services/backend/src/routes/userRoutes.js` (Lines 7–10) only exposes:
    ```javascript
    // GET /api/v1/users/search?email=<email>
    router.get('/search', auth, guardianController.searchUserByEmail);
    ```
  - `services/backend/src/models/User.js` has a `User.update()` method, but it is not wired to any route or controller in `services/backend`.
- **Frontend Impact**: User profile information in the web app is limited to `email`, `role`, and `organization_id`. Editable profile inputs (name, bio, avatar) cannot be persisted on the server.

---

### 3. Logout & Session Revocation
- **Status**: **EXISTING (GLOBAL REVOCATION ONLY)**
- **Endpoint**: `POST /api/v1/auth/logout`
- **Method**: `POST`
- **Authentication**: `Bearer <accessToken>` (via `auth` middleware)
- **Request Body**: None (empty JSON `{}`)
- **Behavior & Evidence**:
  - `services/backend/src/controllers/authController.js` (Lines 354–379):
    ```javascript
    await RefreshToken.revokeByUserId(req.user.id);
    res.clearCookie('refreshToken', { path: '/' });
    ```
  - `services/backend/src/models/RefreshToken.js` (Lines 153–184):
    ```javascript
    async revokeByUserId(user_id) {
      // 1. Fetch all active token hashes for user
      // 2. UPDATE public.refresh_tokens SET is_revoked = TRUE WHERE user_id = $1 AND is_revoked = FALSE;
      // 3. Evict all active tokens from Redis cache
    }
    ```
- **Session Revocation Mechanics**:
  - **Single Session vs. All Sessions**: Calling `/auth/logout` unconditionally revokes **ALL** active refresh tokens across every device and session for that `user_id`.
  - **No Per-Session Option**: The endpoint does not accept a token hash or session identifier, so logging out on one device invalidates refresh capabilities for all other devices.
  - **Access Token Behavior**: The 15-minute JWT access token remains valid until its cryptographic expiry (stateless). However, no subsequent token refreshes (`POST /auth/refresh`) will succeed on any device.
  - **Active Session Listing**: There is **no endpoint** to list active devices, sessions, or login history for an individual user (e.g., `GET /api/v1/auth/sessions` does not exist).
- **Frontend Impact**: The Settings page can offer a "Log Out" or "Log Out Everywhere" action, but cannot provide a granular "Active Sessions" management table.

---

### 4. User Preferences & Notification Settings
- **Status**: **DOES NOT EXIST**
- **Evidence**:
  - There is no database table for user preferences, UI settings, or notification channels (e.g., no `user_preferences`, `notification_settings`, or `alert_subscriptions`).
  - Search across all routes in `services/backend/src/routes/` returns 0 endpoints for preferences.
  - `services/backend/src/services/notificationService.js` is an automated backend dispatcher (SendGrid / SMTP) triggered by `PolicyEngine.js` for high-severity incident responses. It only emails organization administrators upon automated threat mitigation approvals. It has no user-configurable settings or client-facing endpoints.
- **Frontend Impact**: Any UI preferences (theme toggles like Dark/Light mode, sound alerts, layout density) must be stored strictly in client-side storage (`localStorage`) on the frontend.

---

### 5. Employee Organization Info: Read-Only vs. Editable
- **Status**: **STRICTLY READ-ONLY**
- **Evidence**:
  - **Assignment**: An employee selects their organization during signup via `organization_name` (`services/backend/src/controllers/authController.js:48-90`).
  - **Retrieval**: `GET /api/v1/auth/me` returns `{ organization_id: "<uuid>" }` (or `null` for individuals).
  - **No Name Resolution Endpoint**: The backend does **not** expose an endpoint to retrieve the organization name from `organization_id` (e.g., `GET /api/v1/organizations/:id` does not exist).
  - **No Update Endpoints**: There are no routes in `services/backend/src/routes/` allowing an employee to:
    - Update the organization name
    - Change their organization affiliation
    - Leave an organization
    - Transfer to another organization
  - For admin users, organization management is also limited: admin capabilities are restricted to firewall rules, agent enrollment tokens, and response policies within their bound `organization_id`.
- **Frontend Impact**: On the Settings page, organization information for an `employee` or `admin` user should be rendered as read-only metadata badges (e.g., displaying the assigned role and Organization ID).

---

## 3. Existing Endpoints: Complete Contracts

### A. Get Current User Profile
Retrieves authentication and tenancy metadata for the currently authenticated user.

- **Path**: `GET /api/v1/auth/me`
- **Headers**:
  ```http
  Authorization: Bearer <accessToken>
  ```
- **Request Body**: None
- **Response `200 OK`**:
  ```json
  {
    "id": "c1f7b0e2-89a3-4871-bdf6-2e11e3b33333",
    "organization_id": "a9e223b1-4091-4560-8431-727c9d924151",
    "email": "employee@defensecorp.com",
    "role": "employee",
    "created_at": "2026-10-04T08:30:00.000Z"
  }
  ```
  *(Note: `password_hash` is stripped by the controller before responding).*
- **Response `401 Unauthorized`**:
  ```json
  {
    "error": "UNAUTHORIZED",
    "message": "Authentication required"
  }
  ```

---

### B. User Logout (Global Session Revocation)
Revokes all refresh tokens belonging to the user and clears the HTTP-only `refreshToken` cookie.

- **Path**: `POST /api/v1/auth/logout`
- **Headers**:
  ```http
  Authorization: Bearer <accessToken>
  ```
- **Request Body**: None (`{}`)
- **Response `200 OK`**:
  ```json
  {
    "message": "Logged out"
  }
  ```
- **Response `401 Unauthorized`**:
  ```json
  {
    "error": "UNAUTHORIZED",
    "message": "Authentication required"
  }
  ```

---

### C. Token Refresh
Exchanges a valid refresh token for a new 15-minute access token.

- **Path**: `POST /api/v1/auth/refresh`
- **Headers**:
  ```http
  Content-Type: application/json
  ```
- **Request Body** *(Optional if sent via HTTP-only cookie)*:
  ```json
  {
    "refreshToken": "<hex_refresh_token_string>"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "accessToken": "eyJhbGciOiJIUzI1NiIsIn...",
    "expiresIn": 900
  }
  ```
- **Response `401 Unauthorized`**:
  ```json
  {
    "error": "UNAUTHORIZED",
    "message": "Invalid or expired refresh token"
  }
  ```

---

### D. User Search (Email Discovery)
Used by Guardian linking and admin directory search. Not a general user profile update endpoint.

- **Path**: `GET /api/v1/users/search?email=<email>`
- **Headers**:
  ```http
  Authorization: Bearer <accessToken>
  ```
- **Query Parameters**:
  - `email` (string, required): Full email address to match.
- **Response `200 OK`**:
  ```json
  [
    {
      "id": "e2f1b0e2-89a3-4871-bdf6-2e11e3b55555",
      "email": "target@example.com",
      "role": "employee",
      "organization_id": "a9e223b1-4091-4560-8431-727c9d924151",
      "created_at": "2026-10-04T08:30:00.000Z"
    }
  ]
  ```

---

## 4. UI Recommendations for `SettingsPage.jsx`

Given the current backend capabilities, `SettingsPage.jsx` should be designed around **real, verifiable state** rather than stubbed forms that will fail on submit:

1. **Account Overview Card (Real Data via `GET /api/v1/auth/me`)**:
   - **Account Email**: Display `user.email` (read-only).
   - **Account Role**: Display `user.role` with a badge (`Admin`, `Employee`, `Individual`).
   - **Account ID**: Display `user.id` (UUID format, with copy button).
   - **Member Since**: Display formatted date from `user.created_at`.

2. **Organization Card (Read-Only)**:
   - For `employee` and `admin` roles, display Organization ID (`user.organization_id`).
   - Explicitly indicate that organization affiliation is managed by system administrators.

3. **Session & Security Card**:
   - **Logout Action**: Provide a prominent "Log Out of All Devices" button connected to `POST /api/v1/auth/logout`.
   - **Password Section**: Display a notice: *"Password management is currently provisioned by your system administrator"* or render the change-password form with a clear badge/tooltip indicating backend support is pending.

4. **Client-Side Preferences (Persistent in `localStorage`)**:
   - **Theme**: Dark Mode / Cyber Theme selector.
   - **Notification Sound Effects**: Toggle for live audio cues on critical incident alerts.
   - **Auto-Refresh Rate**: Configurable interval for dashboard polling/fallback.
