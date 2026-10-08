# CYBERGUARD — Guardian Mode API Contract Specification

**Document Status:** Authoritative Backend Contract  
**Source Code Baseline:** `feature/frontend-dashboard` (post-PRs #26–#31 merge with `origin/dev`)  
**Scope:** Read-only inspection of the real Node.js Gateway implementation (`services/backend/`)  
**Target Consumer:** Web Dashboard (`apps/web/`), Mobile Guardian App (`apps/mobile/`)

---

## 1. Executive Summary & Architecture Overview

Guardian Mode protects non-technical, vulnerable family members (dependents) by streaming their high-risk and critical security alerts in real-time to designated guardians.

The backend implements a **two-step bidirectional handshake**:
1. **Initiation:** Either party (guardian or dependent) proposes a link via `POST /api/v1/guardian/link`. The link is created with status `'pending'`.
2. **Acceptance/Rejection:** Only the designated `dependent_user_id` can accept (`/accept`) or decline (`/decline`) the pending invitation.
3. **Revocation:** Once created (whether pending or active), **either** the guardian or the dependent can revoke the relationship via `POST /api/v1/guardian/link/:id/revoke`.
4. **Alerts Dispatch:** Active guardians receive high and critical alerts for their active dependents via `GET /api/v1/guardian/alerts` and WebSocket room `guardian:<user_id>`.

---

## 2. Endpoint Specifications

### 2.1 `GET /api/v1/guardian/links` — List Guardian Links

Retrieves all guardian relationships involving the authenticated user, covering both directions and excluding revoked links by default.

- **HTTP Method:** `GET`
- **Path:** `/api/v1/guardian/links` (mounted on `v1Router` at `services/backend/src/index.js:71` and `services/backend/src/routes/guardianRoutes.js:8`)
- **Controller & Model Evidence:**
  - Controller: [`services/backend/src/controllers/guardianController.js:203-234`](../../services/backend/src/controllers/guardianController.js#L203-L234)
  - Query Model: [`services/backend/src/models/GuardianLink.js:64-103`](../../services/backend/src/models/GuardianLink.js#L64-L103)
- **Authentication:** Mandatory Bearer JWT (`auth` middleware at `services/backend/src/middlewares/auth.js:15-37`).
- **Query Parameters:**
  - `status` (*optional string*): One of `'active'`, `'pending'`, `'revoked'`, `'all'`.
  - **Default when omitted:** Excludes revoked links (`gl.status != 'revoked'`). Returns **both `pending` and `active` links**.
  - If an invalid status string is provided, returns `400 Bad Request`.

#### Directionality & Filtering Rules
- **Standard Users (`individual` / `employee`):** Queries `(gl.guardian_user_id = $userId OR gl.dependent_user_id = $userId)`. Returns links in **both directions** in the same response:
  - Where the caller is the guardian (`guardian_user_id === req.user.id`).
  - Where the caller is the dependent (`dependent_user_id === req.user.id`).
- **Tenant Admins (`admin` with `organization_id`):** Queries `(ug.organization_id = $orgId OR ud.organization_id = $orgId)`, scoping links across their entire enterprise organization.

#### Request Headers
```http
GET /api/v1/guardian/links HTTP/1.1
Host: localhost:5000
Authorization: Bearer <jwt_token>
```

#### Success Response (`200 OK`)
Payload is wrapped in an object `{ links: [...] }`:
```json
{
  "links": [
    {
      "id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
      "link_id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
      "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
      "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
      "status": "pending",
      "created_at": "2026-10-04T12:00:00.000Z",
      "guardian_email": "guardian@example.com",
      "dependent_email": "dependent@example.com"
    }
  ]
}
```

#### Response Field Reference
| Field | Type | Nullable | Description |
|---|---|---|---|
| `id` | `string` (UUIDv4) | No | Primary key identifier of the link record. |
| `link_id` | `string` (UUIDv4) | No | Database alias matching `id` for backwards compatibility. |
| `guardian_user_id` | `string` (UUIDv4) | No | User ID of the guardian receiving telemetry. |
| `dependent_user_id` | `string` (UUIDv4) | No | User ID of the protected dependent. |
| `status` | `string` | No | Link state: `'pending'`, `'active'`, or `'revoked'`. |
| `created_at` | `string` (ISO 8601) | No | Timestamp when link was initiated. |
| `guardian_email` | `string` | No | Email address of the guardian (joined from `users ug`). |
| `dependent_email` | `string` | No | Email address of the dependent (joined from `users ud`). |

#### Error Responses
- **`400 Bad Request` — Invalid status parameter:**
  ```json
  {
    "error": "INVALID_STATUS",
    "message": "Status filter must be one of: 'active', 'pending', 'revoked', 'all'"
  }
  ```
- **`401 Unauthorized` — Missing or expired token:**
  ```json
  {
    "error": "UNAUTHORIZED",
    "message": "Authentication required"
  }
  ```
- **`500 Internal Server Error` — Database failure:**
  ```json
  {
    "error": "DB_ERROR",
    "message": "Failed to retrieve guardian links"
  }
  ```

#### UX Implications for Frontend
- **Response Wrapper:** The client must read `response.links` (an array). It is not returned as a raw top-level array.
- **Direction Partitioning:** Because both outgoing (I am guardian) and incoming (I am dependent) links are returned in one list, the frontend UI must partition `links` by checking `link.guardian_user_id === currentUser.id`:
  - **"My Dependents" Tab:** `link.guardian_user_id === currentUser.id`. If `status === 'pending'`, show "Awaiting acceptance" + "Cancel/Revoke" button. If `status === 'active'`, show "Active" + "Revoke" button.
  - **"My Guardians" Tab:** `link.dependent_user_id === currentUser.id`. If `status === 'pending'`, render **"Accept"** and **"Decline"** buttons. If `status === 'active'`, render "Revoke Protection" button.
- **Default Inclusion of Pending:** The UI does not need to pass `?status=pending` or `?status=active` to display current relationships; the default `GET /guardian/links` fetches all current (non-revoked) items.

---

### 2.2 `POST /api/v1/guardian/link` — Propose / Initiate Link

Initiates a guardian relationship between two users in `'pending'` state.

- **HTTP Method:** `POST`
- **Path:** `/api/v1/guardian/link` (`services/backend/src/routes/guardianRoutes.js:9`)
- **Controller & Model Evidence:**
  - Controller: [`services/backend/src/controllers/guardianController.js:15-74`](../../services/backend/src/controllers/guardianController.js#L15-L74)
  - Query Model: [`services/backend/src/models/GuardianLink.js:7-17`](../../services/backend/src/models/GuardianLink.js#L7-L17)
- **Authentication:** Mandatory Bearer JWT.
- **Authorization Check:** Caller's `req.user.id` must match either `guardian_user_id` or `dependent_user_id`. Attempting to link two other parties returns `403 Forbidden`.

#### Request Headers & Body
```http
POST /api/v1/guardian/link HTTP/1.1
Host: localhost:5000
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `guardian_user_id` | `string` (UUIDv4) | Yes | User ID of the proposed guardian. |
| `dependent_user_id` | `string` (UUIDv4) | Yes | User ID of the proposed dependent. |

#### Database Conflict Handling (Re-Linking)
In `GuardianLink.create`:
```sql
INSERT INTO guardian_links (guardian_user_id, dependent_user_id, status, created_at)
VALUES ($1, $2, $3, NOW())
ON CONFLICT (guardian_user_id, dependent_user_id) DO UPDATE
SET status = EXCLUDED.status
RETURNING id as link_id, id, guardian_user_id, dependent_user_id, status, created_at;
```
If a link between the pair previously existed (e.g. was previously `'revoked'`), `ON CONFLICT` automatically resets the status back to `'pending'`. It does **not** fail or return 409 Conflict.

#### Success Response (`201 Created`)
```json
{
  "link_id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
  "status": "pending",
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "created_at": "2026-10-04T12:00:00.000Z"
}
```

#### Error Responses
- **`400 Bad Request` — Missing either ID:**
  ```json
  {
    "error": "INVALID_PAYLOAD",
    "message": "Both guardian_user_id and dependent_user_id are required"
  }
  ```
- **`400 Bad Request` — Self-link attempted:**
  ```json
  {
    "error": "INVALID_LINK",
    "message": "A user cannot link to themselves as a dependent"
  }
  ```
- **`403 Forbidden` — Third-party linkage:**
  ```json
  {
    "error": "FORBIDDEN",
    "message": "You can only link your own account as either guardian or dependent"
  }
  ```
- **`500 Internal Server Error` — Non-existent user ID (Foreign Key Violation):**
  If `guardian_user_id` or `dependent_user_id` does not exist in the `users` table, PostgreSQL triggers FK constraint violation `23503`, caught by the controller:
  ```json
  {
    "error": "DB_ERROR",
    "message": "Failed to create guardian link"
  }
  ```

#### UX Implications for Frontend
- **Two-Step Linking Flow:** The UI cannot prompt for raw UUIDs. The user flow must first search for the dependent by email via `GET /users/search?email=...`, obtain their verified `id`, and pass that `id` into `dependent_user_id`.
- **Pre-flight Self Check:** Prevent users from selecting their own email in the UI before submitting, avoiding unnecessary 400 roundtrips.

---

### 2.3 `POST /api/v1/guardian/link/:id/accept` — Accept Invitation

Transitions a pending guardian invitation to `'active'`.

- **HTTP Method:** `POST`
- **Path:** `/api/v1/guardian/link/:id/accept` (`services/backend/src/routes/guardianRoutes.js:10`)
- **Controller & Model Evidence:**
  - Controller: [`services/backend/src/controllers/guardianController.js:79-137`](../../services/backend/src/controllers/guardianController.js#L79-L137)
  - Query Model: [`services/backend/src/models/GuardianLink.js:53-62`](../../services/backend/src/models/GuardianLink.js#L53-L62)
- **Path Parameter:** `:id` — Link UUID. Must match UUID regex (`services/backend/src/controllers/guardianController.js:6`).
- **Authentication & Authorization Requirement:**
  - Mandatory Bearer JWT.
  - **STRICT DEPENDENT CHECK:** Lines 93-98 enforce:
    ```javascript
    if (!link || link.dependent_user_id !== req.user?.id) {
      return res.status(404).json({ error: 'NOT_FOUND', message: 'Guardian link not found' });
    }
    ```
    Only the assigned `dependent_user_id` is authorized to accept. If the guardian or an unrelated user attempts to accept, the API returns `404 Not Found` (anti-enumeration).
- **Status Pre-Condition:** `link.status === 'pending'`. If link is already `'active'` or `'revoked'`, returns `400 Bad Request`.

#### Success Response (`200 OK`)
```json
{
  "link_id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
  "status": "active",
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "created_at": "2026-10-04T12:00:00.000Z"
}
```

#### Error Responses
- **`404 Not Found` — Invalid UUID syntax or link does not exist:**
  ```json
  {
    "error": "NOT_FOUND",
    "message": "Guardian link not found"
  }
  ```
- **`404 Not Found` — Caller is NOT the dependent:**
  Returned when `req.user.id !== link.dependent_user_id` (even if caller is the guardian).
- **`400 Bad Request` — Non-pending link status:**
  ```json
  {
    "error": "INVALID_STATUS",
    "message": "Cannot accept guardian link with status 'active'"
  }
  ```
- **`500 Internal Server Error` — Database failure:**
  ```json
  {
    "error": "DB_ERROR",
    "message": "Failed to accept guardian link"
  }
  ```

#### UX Implications for Frontend
- Render the "Accept" action **only** when `currentUser.id === link.dependent_user_id` and `link.status === 'pending'`.
- Immediately upon accepting, update local state or invalidate the links query so the button is disabled, preventing accidental double-clicks that trigger a `400 INVALID_STATUS`.

---

### 2.4 `POST /api/v1/guardian/link/:id/decline` — Decline Invitation

Declines a pending invitation, transitioning status to `'revoked'`.

- **HTTP Method:** `POST`
- **Path:** `/api/v1/guardian/link/:id/decline` (`services/backend/src/routes/guardianRoutes.js:11`)
- **Controller Evidence:** [`services/backend/src/controllers/guardianController.js:142-200`](../../services/backend/src/controllers/guardianController.js#L142-L200)
- **Path Parameter:** `:id` — Link UUID.
- **Authentication & Authorization Requirement:**
  - Mandatory Bearer JWT.
  - **STRICT DEPENDENT CHECK:** Lines 156-161 enforce that only `dependent_user_id` can decline. Other users receive `404 Not Found`.
- **Status Pre-Condition:** `link.status === 'pending'`.

#### Success Response (`200 OK`)
```json
{
  "link_id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
  "status": "revoked",
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "created_at": "2026-10-04T12:00:00.000Z"
}
```

#### Error Responses
- **`404 Not Found` — Link not found or caller not dependent:**
  ```json
  {
    "error": "NOT_FOUND",
    "message": "Guardian link not found"
  }
  ```
- **`400 Bad Request` — Non-pending link status:**
  ```json
  {
    "error": "INVALID_STATUS",
    "message": "Cannot decline guardian link with status 'revoked'"
  }
  ```

#### UX Implications for Frontend
- Render "Decline" side-by-side with "Accept" for pending incoming requests.
- Declining removes the link from the default `GET /guardian/links` view.

---

### 2.5 `POST /api/v1/guardian/link/:id/revoke` — Revoke Relationship

Cancels a pending invitation OR terminates an active guardian relationship.

- **HTTP Method:** `POST`
- **Path:** `/api/v1/guardian/link/:id/revoke` (`services/backend/src/routes/guardianRoutes.js:12`)
- **Controller Evidence:** [`services/backend/src/controllers/guardianController.js:237-290`](../../services/backend/src/controllers/guardianController.js#L237-L290)
- **Path Parameter:** `:id` — Link UUID.
- **Authentication & Authorization Requirement:**
  - Mandatory Bearer JWT.
  - **CONFIRMED FIX — BOTH PARTIES AUTHORIZED:** Lines 252-258 enforce:
    ```javascript
    if (!link || (link.guardian_user_id !== req.user?.id && link.dependent_user_id !== req.user?.id)) {
      return res.status(404).json({ error: 'NOT_FOUND', message: 'Guardian link not found' });
    }
    ```
    **Either the guardian OR the dependent can revoke the link at any time.**
- **Status Rules:**
  - Can revoke while `'pending'` (e.g. guardian cancels invitation before dependent accepts).
  - Can revoke while `'active'` (e.g. either party severs the link).
  - Does **not** require link to be in `'pending'` or `'active'` status (idempotently sets status to `'revoked'`).

#### Success Response (`200 OK`)
Includes both `"id"` and `"link_id"`:
```json
{
  "id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
  "link_id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
  "status": "revoked",
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "created_at": "2026-10-04T12:00:00.000Z"
}
```

#### Error Responses
- **`404 Not Found` — Caller is neither guardian nor dependent (or bad UUID):**
  ```json
  {
    "error": "NOT_FOUND",
    "message": "Guardian link not found"
  }
  ```
- **`500 Internal Server Error` — Database failure:**
  ```json
  {
    "error": "DB_ERROR",
    "message": "Failed to revoke guardian link"
  }
  ```

#### UX Implications for Frontend
- Both guardians and dependents can be presented with a "Revoke Link" or "Cancel Invitation" button.
- Revoking instantly stops live telemetry streaming to the guardian.

---

### 2.6 `GET /api/v1/users/search?email=...` — User Lookup by Email

Looks up a registered CyberGuard user by their exact email address.

- **HTTP Method:** `GET`
- **Paths:**
  - Canonical: `/api/v1/users/search?email=<email>` (`services/backend/src/routes/userRoutes.js:8`)
  - Route Alias: `/api/v1/guardian/users/search?email=<email>` (`services/backend/src/routes/guardianRoutes.js:14`)
- **Controller & Model Evidence:**
  - Controller: [`services/backend/src/controllers/guardianController.js:300-346`](../../services/backend/src/controllers/guardianController.js#L300-L346)
  - Query Model: [`services/backend/src/models/User.js:50-72`](../../services/backend/src/models/User.js#L50-L72)
- **Authentication:** Mandatory Bearer JWT.
- **Query Parameter:** `email` (*required string*).

#### Matching Behavior & Tenant Scoping
- **Exact Match Only:** The SQL query uses `LOWER(email) = LOWER($1)`. This is a **case-insensitive exact match**, NOT a prefix or partial substring search (`LIKE`).
- **Role & Tenant Filter:**
  - When called by an `individual` user:
    ```sql
    WHERE LOWER(email) = LOWER($1) AND role = 'individual' AND organization_id IS NULL;
    ```
    Only discovers other individual users. Protects enterprise employees and admins from being targeted by individual guardian links.
  - When called by an `admin` or `employee` with `organizationId`:
    ```sql
    WHERE LOWER(email) = LOWER($1) AND organization_id = $2;
    ```
    Only discovers users inside their own organization tenant.

#### Success Response (`200 OK`)
Sanitizes `password_hash`. Exposes array `users`, object `user`, and flattens fields at root:
```json
{
  "users": [
    {
      "id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
      "email": "grandpa@example.com",
      "role": "individual",
      "organization_id": null
    }
  ],
  "user": {
    "id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
    "email": "grandpa@example.com",
    "role": "individual",
    "organization_id": null
  },
  "id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "email": "grandpa@example.com",
  "role": "individual",
  "organization_id": null
}
```

#### Error Responses
- **`400 Bad Request` — Missing or empty email param:**
  ```json
  {
    "error": "BAD_REQUEST",
    "message": "email query parameter is required"
  }
  ```
- **`404 Not Found` — User does not exist or outside tenant scope:**
  ```json
  {
    "error": "NOT_FOUND",
    "message": "User not found"
  }
  ```

#### UX Implications for Frontend
- **Lookup Action, Not Auto-Complete:** Because matching is exact, do **not** bind this endpoint to an `onChange` live-filtering list. Implement it as an explicit "Verify Email" or "Lookup" button triggered on full email entry.
- **Calm 404 Handling:** A 404 indicates "No registered CyberGuard user with this email". Show a gentle inline warning: *"No user found with this email address. Please make sure your family member has signed up for CyberGuard."*

---

### 2.7 `GET /api/v1/guardian/alerts` — Dependent Threat Alerts Feed

Retrieves threat incidents flagged for active dependents.

- **HTTP Method:** `GET`
- **Path:** `/api/v1/guardian/alerts` (`services/backend/src/routes/guardianRoutes.js:13`)
- **Controller & Model Evidence:**
  - Controller: [`services/backend/src/controllers/guardianController.js:349-394`](../../services/backend/src/controllers/guardianController.js#L349-L394)
  - Scoping Query: [`services/backend/src/models/GuardianLink.js:29-39`](../../services/backend/src/models/GuardianLink.js#L29-L39)
- **Authentication:** Mandatory Bearer JWT.

#### Scoping & Filtering Rules
1. Finds dependents where `guardian_user_id = req.user.id AND status = 'active'`. (Pending or revoked dependents produce 0 alerts).
2. If no active dependents exist, returns `200 OK` with an empty array `[]`.
3. Filters incidents strictly where `risk_level IN ('high', 'critical')`. (Safe, low, and medium threats are suppressed).
4. Formats `risk_level` in **TitleCase** (`services/backend/src/controllers/guardianController.js:382`):
   ```javascript
   risk_level: row.risk_level ? row.risk_level.charAt(0).toUpperCase() + row.risk_level.slice(1) : 'High'
   ```

#### Success Response (`200 OK`)
Top-level JSON array of alert records:
```json
[
  {
    "alert_id": "f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
    "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
    "dependent_name": "grandpa",
    "risk_level": "Critical",
    "threat_type": "phishing",
    "explanation": "Critical Risk: Urgent SMS claiming bank card suspension with fraudulent verification link.",
    "recommended_action": "Review threat details and contact dependent immediately.",
    "timestamp": "2026-10-04T11:45:00.000Z"
  }
]
```

#### Response Field Reference
| Field | Type | Description |
|---|---|---|
| `alert_id` | `string` (UUIDv4) | Incident ID from `incidents.id`. |
| `dependent_user_id` | `string` (UUIDv4) | User ID of the affected dependent. |
| `dependent_name` | `string` | Dependent email prefix or email. |
| `risk_level` | `string` (`"High"` \| `"Critical"`) | **TitleCase** formatted risk severity. |
| `threat_type` | `string` | Categorical threat type (`phishing`, `deepfake`, etc.). |
| `explanation` | `string` | Plain-English AI detection rationale. |
| `recommended_action` | `string` | Imperative remediation advisory. |
| `timestamp` | `string` (ISO 8601) | Incident creation timestamp. |

#### UX Implications for Frontend
- **Array Root:** Returned directly as a JSON array `[...]`, not wrapped in `{ alerts: [...] }`.
- **TitleCase Normalization:** `risk_level` is `"High"` or `"Critical"`. The frontend must call `normalizeRisk(alert.risk_level)` before using standard CSS or UI badge variants.
- **Empty State:** If the user has no active dependents or no high-risk incidents, it returns `[]`. Render an empty state clarifying that protection is active and no severe threats have been flagged.

---

## 3. Discrepancy & Drift Audit vs. `types.ts`

Cross-checking the real backend implementation against [`types.ts`](../../types.ts) reveals the following discrepancies:

| Topic / Entity | `types.ts` Declaration | Real Backend Implementation | Impact & Required Action |
|---|---|---|---|
| **`GuardianLink` Emails** | `GuardianLink` interface has no email fields. | `GET /guardian/links` returns `guardian_email` and `dependent_email` joined from `users`. | **Drift:** UI needs dependent and guardian emails to display names/identities without making separate user fetch calls. |
| **`GET /guardian/links` Wrapper** | No response DTO declared. | Returns `{ links: GuardianLink[] }`, an object wrapper. | **Drift:** If client code expects `GuardianLink[]` directly, it will fail to read the list. |
| **`POST /guardian/link` Response** | No response DTO declared. | Returns `{ link_id, status: 'pending', guardian_user_id, dependent_user_id, created_at }`. | Missing type definition in `types.ts`. |
| **Accept/Decline Response** | No response DTO declared. | Returns `{ link_id, status: 'active' \| 'revoked', guardian_user_id, dependent_user_id, created_at }`. | Missing type definition in `types.ts`. |
| **Revoke Response** | No response DTO declared. | Returns `{ id, link_id, status: 'revoked', guardian_user_id, dependent_user_id, created_at }`. | Missing type definition in `types.ts`. |
| **User Search Response** | No search DTO declared. | Returns `{ users: [...], user: {...}, id, email, role, organization_id }`. | Missing type definition in `types.ts`. |
| **`GuardianAlert` Risk Level** | `risk_level: RiskLevelTitleCase \| string;` | Returns `"High"` or `"Critical"` (TitleCase). | **Aligned:** `types.ts` correctly anticipates TitleCase for `GuardianAlert`. |
| **`LinkDependentRequest`** | Declared with `guardian_user_id` and `dependent_user_id`. | Exactly matches `POST /guardian/link` body. | **Aligned.** |

---

## 4. Recommended TypeScript Interface Updates

When types are updated in the next frontend phase, incorporate these authoritative definitions:

```typescript
// Enriched Guardian Link with joined emails from GET /guardian/links
export interface GuardianLinkItem {
  id: string;
  link_id: string;
  guardian_user_id: string;
  dependent_user_id: string;
  guardian_email: string;
  dependent_email: string;
  status: 'pending' | 'active' | 'revoked';
  created_at: string;
}

export interface GuardianLinksResponse {
  links: GuardianLinkItem[];
}

export interface GuardianLinkActionResponse {
  id?: string;
  link_id: string;
  status: 'pending' | 'active' | 'revoked';
  guardian_user_id: string;
  dependent_user_id: string;
  created_at: string;
}

export interface UserSearchResponse {
  id: string;
  email: string;
  role: string;
  organization_id: string | null;
  user: {
    id: string;
    email: string;
    role: string;
    organization_id: string | null;
  };
  users: Array<{
    id: string;
    email: string;
    role: string;
    organization_id: string | null;
  }>;
}
```
