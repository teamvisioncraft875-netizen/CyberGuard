# CYBERGUARD — Unified API Contract

> **CRITICAL NOTICE: SINGLE SOURCE OF TRUTH**  
> This document is the authoritative specification for all communication contracts between:
> 1. **Client Frontends** (`apps/web`, `apps/mobile`) and **API Gateway** (`services/backend`).
> 2. **Telemetry Collector** (Guard App) and **API Gateway** (`services/backend`).
> 3. **API Gateway** (`services/backend`) and **AI/ML Service** (`services/ml-service`).
>
> **Enforcement Rule:** Any change to an endpoint route, request payload, response schema, or status code **must update this file in the exact same Pull Request**. Never implement or alter endpoints without synchronizing this contract first.

---

## Standard Types & Conventions

### Risk Levels
All detection and incident endpoints use the standard 5-tier calibrated risk level:
- `"Safe"`: Score 0–19. Benign / verified origin.
- `"Low"`: Score 20–39. Minor anomaly without malicious intent.
- `"Medium"`: Score 40–69. Suspicious cues; review advised.
- `"High"`: Score 70–89. Strong threat indicators; proactive alert.
- `"Critical"`: Score 90–100. Confirmed active attack; immediate intervention.

### Authentication Headers
For endpoints requiring authentication:
```http
Authorization: Bearer <jwt_token>
```

### Redis Caching Policies
To maintain sub-second response times and preserve external threat intelligence quotas:
- **External Threat Intelligence APIs:** API calls to external services are cached for 24 hours to reduce quota usage (Key format: `api_cache:<service>:<identifier>`, TTL: 86,400s).
- **Session Refresh Tokens:** Refresh tokens are cached for 7 days for faster validation (Key format: `refresh_token:<tokenHash>`, TTL: 604,800s). In the event of logout or revocation, cache entries are immediately invalidated.

---

## 1. Authentication Endpoints

### 1.1 User Signup
Register a new user as an individual, employee, or organization admin.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/auth/signup` *(also available at `/api/auth/signup`)* |
| **Auth Requirement** | Public |
| **Description** | Creates user account, generates short-lived access token (15m), issues long-lived refresh token (7d), and sets HTTP-only `refreshToken` cookie. |

**Request Body:**
```json
{
  "email": "analyst@enterprise.com",
  "password": "SecurePassword123!",
  "role": "individual", // Enum: "individual" | "employee"
  "organization_name": "Acme Corp" // Required if role is "employee"
}
```

**Response (`201 Created`):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "a9b8c7d6e5f4...64-char-hex...",
  "user": {
    "id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "email": "analyst@enterprise.com",
    "role": "individual",
    "organization_id": null,
    "created_at": "2026-09-09T08:00:00Z"
  }
}
```
*Note: Also sets an HTTP-only, Secure, SameSite=Strict cookie named `refreshToken` with 7 days expiration.*

**Errors:**
- `400 Bad Request`: Malformed email, weak password (<8 characters), or missing organization name for employees.
- `409 Conflict`: Email already registered (`{ "error": "EMAIL_ALREADY_EXISTS" }`).

---

### 1.2 User Login
Authenticate user credentials and receive access and refresh tokens.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/auth/login` *(also available at `/api/auth/login`)* |
| **Auth Requirement** | Public |
| **Description** | Validates email and bcrypt password hash; returns short-lived access token (15m), issues long-lived refresh token (7d), and sets HTTP-only `refreshToken` cookie. |

**Request Body:**
```json
{
  "email": "analyst@enterprise.com",
  "password": "SecurePassword123!"
}
```

**Response (`200 OK`):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "a9b8c7d6e5f4...64-char-hex...",
  "user": {
    "id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "email": "analyst@enterprise.com",
    "role": "admin",
    "organization_id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
    "created_at": "2026-09-09T08:00:00Z"
  }
}
```
*Note: Also sets an HTTP-only, Secure, SameSite=Strict cookie named `refreshToken` with 7 days expiration.*

**Errors:**
- `400 Bad Request`: Missing email or password (`{ "error": "MISSING_CREDENTIALS" }`).
- `401 Unauthorized`: Invalid email or password (`{ "error": "INVALID_CREDENTIALS" }`).

---

### 1.3 Refresh Access Token (`POST /api/v1/auth/refresh`)
Obtain a new short-lived access token without requiring the user to re-enter credentials.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/auth/refresh` *(also available at `/api/auth/refresh`)* |
| **Auth Requirement** | Public (no Bearer token needed; authenticated via refresh token) |
| **Description** | Validates SHA-256 hashed refresh token from HTTP-only cookie or request body. If valid and not expired/revoked, returns a new 15-minute access token. |

**Request Body (optional if cookie is present):**
```json
{
  "refreshToken": "a9b8c7d6e5f4...64-char-hex..." // Optional: web clients send via HTTP-only cookie
}
```

**Response (`200 OK`):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Errors:**
- `401 Unauthorized`: Refresh token missing, invalid, revoked, or expired (`{ "error": "REFRESH_TOKEN_INVALID", "message": "Please login again" }`).

---

### 1.4 User Logout (`POST /api/v1/auth/logout`)
Terminate the user session, revoke all refresh tokens in the database, and clear cookies.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/auth/logout` *(also available at `/api/auth/logout`)* |
| **Auth Requirement** | Requires JWT (`Authorization: Bearer <access_token>`) |
| **Description** | Revokes all refresh tokens belonging to the authenticated user and clears the `refreshToken` HTTP-only cookie. |

**Request Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Response (`200 OK`):**
```json
{
  "message": "Logged out"
}
```

**Errors:**
- `401 Unauthorized`: Missing or invalid bearer token.

---

### 1.5 Get Current User Profile (`GET /api/v1/auth/me`)
Retrieve authenticated user profile and organizational context.

| Property | Specification |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/v1/auth/me` *(also available at `/api/auth/me`)* |
| **Auth Requirement** | Requires JWT (`Authorization: Bearer <jwt_token>`) |
| **Description** | Returns profile of the user identified by the Bearer token. |

**Request Headers:**
```http
Authorization: Bearer <jwt_token>
```

**Request Body:** None

**Response (`200 OK`):**
```json
{
  "id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "email": "analyst@enterprise.com",
  "role": "admin",
  "organization_id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "created_at": "2026-09-09T08:00:00Z"
}
```

**Errors:**
- `401 Unauthorized`: Missing, expired, or invalid token (`{ "error": "TOKEN_EXPIRED", "message": "Please call POST /auth/refresh to get a new access token" }`).

---

## 2. Detection Checks (Client → Gateway → FastAPI)

These endpoints are called by Web and Mobile clients, ingested by the Node.js Gateway, proxied internally to FastAPI detection engines, logged to PostgreSQL, and returned.

### 2.1 Check Suspicious Message
Analyze text content from emails, SMS, or social direct messages.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/check/message` |
| **Auth Requirement** | Requires JWT |
| **Description** | Evaluates message text for phishing intent, social engineering, urgency cues, and spoofing. |

**Request Body:**
```json
{
  "text": "URGENT: Your Chase account is locked. Verify identity at http://chase-security-update.xyz within 1 hour.",
  "source_type": "email" // Enum: "email" | "sms" | "social"
}
```

**Response (`200 OK`):**
```json
{
  "risk_level": "High", // Enum: "Safe" | "Low" | "Medium" | "High" | "Critical"
  "explanation": "High Risk: Message exhibits extreme urgency cues demanding credential verification and contains an unverified typo-squatted link.",
  "recommended_action": "Do not click any links. Report and delete the message immediately."
}
```

**Errors:**
- `400 Bad Request`: Empty text or invalid `source_type`.
- `502 Bad Gateway`: Internal ML service unavailable.

---

### 2.2 Check Suspicious URL
Evaluate a website URL for brand impersonation, deceptive registration, and malware domain reputation.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/check/url` |
| **Auth Requirement** | Requires JWT |
| **Description** | Analyzes URL using domain age, look-alike scoring, and threat intelligence lookups. |

**Request Body:**
```json
{
  "url": "https://secure-login-alert-paypal.top/verify"
}
```

**Response (`200 OK`):**
```json
{
  "risk_level": "Critical", // Enum: "Safe" | "Low" | "Medium" | "High" | "Critical"
  "explanation": "Critical Risk: Domain registered 2 days ago mimics PayPal brand name and is flagged on active phishing blacklists.",
  "recommended_action": "Block domain network-wide and revoke any credentials entered on this site."
}
```

**Errors:**
- `400 Bad Request`: Malformed or invalid URL string.

---

### 2.3 Check Suspicious Media (Image / Audio Deepfake)
Analyze an uploaded image or audio file for synthetic manipulation, generative artifacts, or voice cloning. In production, clients upload media directly to Supabase Storage via a signed upload URL obtained from `POST /api/v1/media/upload-url` and supply the resulting `file_path` (or resolved `file_url`).

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/check/media` *(also available at `/api/check/media`)* |
| **Auth Requirement** | Requires JWT |
| **Description** | Evaluates image/audio using Vision Transformer (ViT) or voice anti-spoofing models. Validates that the requested `file_path` resides strictly within the authenticated user's isolated upload directory (`uploads/<user_id>/*`). |

**Request Body:**
```json
{
  "file_path": "uploads/a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d/1727670000000_a1b2c3.wav", // Preferred: path returned by /media/upload-url
  "file_url": "https://<supabase-project>.supabase.co/storage/v1/object/authenticated/cyberguard-media/uploads/a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d/1727670000000_a1b2c3.wav", // Optional if file_path is provided
  "media_type": "audio" // Enum: "image" | "audio"
}
```

**Response (`200 OK`):**
```json
{
  "id": "inc_1727670005000",
  "risk_level": "High", // Enum: "Safe" | "Low" | "Medium" | "High" | "Critical"
  "risk_score": 85,
  "explanation": "High Risk: Acoustic spectral analysis indicates synthetic voice cloning artifacts consistent with generative voice models.",
  "recommended_actions": [
    "Verify speaker identity via a secondary known channel before taking financial or sensitive action."
  ],
  "confidence_score": 0.89, // Float between 0.0 and 1.0
  "signals": {
    "spectral_centroid": 2450.5,
    "pitch_jitter_pct": 2.8
  }
}
```

**Errors:**
- `400 Bad Request`: Missing file reference or unsupported `media_type`.
- `401 Unauthorized`: Missing or invalid bearer token.
- `403 Forbidden`: `file_path` or `file_url` belongs to another user (`{ "error": "FORBIDDEN", "message": "Access denied: cannot check media belonging to another user" }`).
- `404 Not Found`: Media file could not be accessed at storage URL.
- `502 Bad Gateway`: Internal ML service unavailable.

---

### 2.4 Generate Signed Media Upload URL (`POST /api/v1/media/upload-url`)
Generates a pre-signed, time-limited direct upload URL to Supabase Storage bucket `cyberguard-media`. Clients upload their raw image/audio binary directly to Supabase, bypassing backend gateway bandwidth limits, and subsequently pass the returned `file_path` to `POST /api/v1/check/media`.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/media/upload-url` *(also available at `/api/media/upload-url` and `/api/check/media/upload-url`)* |
| **Auth Requirement** | Requires JWT (`Authorization: Bearer <jwt_token>`) |
| **Description** | Issues pre-signed upload URL for Supabase Storage restricted to the authenticated user's isolated path `uploads/<user_id>/<timestamp>_<random_id>.<ext>`. |

**Request Body:**
```json
{
  "media_type": "image", // Enum: "image" | "audio" (required)
  "file_size_bytes": 1048576, // Positive integer <= 50MB (52,428,800 bytes) (required)
  "file_name": "suspect_profile.png" // Optional original filename for extension extraction
}
```

**Response (`200 OK`):**
```json
{
  "upload_url": "https://awjehrhtxhbugocwqeao.supabase.co/storage/v1/object/upload/sign/cyberguard-media/uploads/a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d/1727670000000_9f2a1b.png?token=663ae704c563decf35c09a9ad1a1ee8f",
  "file_path": "uploads/a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d/1727670000000_9f2a1b.png",
  "expiry_seconds": 3600
}
```

**Errors:**
- `400 Bad Request`: Invalid `media_type` (`"media_type must be 'image' or 'audio'"`), missing or non-positive `file_size_bytes`, or `file_size_bytes` exceeds 50MB limit (`{ "error": "FILE_TOO_LARGE" }`).
- `401 Unauthorized`: Missing or invalid bearer token.
- `500 Internal Server Error`: Storage provider failure.

---

## 3. Login & System Telemetry Ingestion (Guard App → Gateway)

These endpoints are called by the desktop sensor agent ("Guard App") to report login activity and operating system behavioral anomalies.

### 3.1 Report Login Event (`POST /api/v1/telemetry/login-event`)
Ingest authentication attempt telemetry from user endpoints.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/telemetry/login-event` *(also available at `/api/telemetry/login-event`)* |
| **Auth Requirement** | Requires JWT (`Authorization: Bearer <jwt_token>`) |
| **Description** | Reports login attempt metadata to detect credential stuffing and account takeover anomalies. |

**Request Body:**
```json
{
  "user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "timestamp": "2026-09-09T08:15:30Z",
  "location": "Moscow, RU",
  "device_id": "macbook-air-m2-0941",
  "failed_attempts": 4
}
```

**Response (`201 Created`):**
```json
{
  "status": "recorded",
  "anomaly_detected": true,
  "risk_level": "High"
}
```

**Errors:**
- `400 Bad Request`: Missing required telemetry fields.
- `401 Unauthorized`: Missing or invalid bearer token.

---

### 3.2 Report System Event (`POST /api/v1/telemetry/system-event`)
Ingest host operating system and network behavioral anomalies.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/telemetry/system-event` *(also available at `/api/telemetry/system-event`)* |
| **Auth Requirement** | Requires JWT (`Authorization: Bearer <jwt_token>`) |
| **Description** | Ingests process spikes and abnormal outbound network connections from Guard App. |

**Request Body:**
```json
{
  "user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "timestamp": "2026-09-09T08:16:00Z",
  "event_type": "network_spike", // e.g. "network_spike" | "unusual_process" | "file_modification"
  "details": {
    "process_name": "unknown_daemon.exe",
    "remote_ip": "194.26.29.112",
    "outbound_bytes": 104857600
  }
}
```

**Response (`201 Created`):**
```json
{
  "status": "recorded",
  "anomaly_detected": true,
  "risk_level": "Medium"
}
```

**Errors:**
- `400 Bad Request`: Malformed event payload.
- `401 Unauthorized`: Missing or invalid bearer token.

---

## 4. Incidents (Command Dashboard)

Endpoints used by the React Command Dashboard to query, filter, and triage incidents.

### 4.1 List Incidents
Retrieve incident history with pagination and optional filtering. Scoped strictly to the authenticated user's records (for individuals/employees) or organization records (for admins).

| Property | Specification |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/v1/incidents` *(also available at `/api/incidents`)* |
| **Auth Requirement** | Requires JWT (`Authorization: Bearer <jwt_token>`) |
| **Description** | Returns paginated array of incidents with batch-joined recommended actions, MITRE mappings, and a top-level total count. |

**Query Parameters:**
- `limit` *(optional, integer)*: Number of records per page (default: `25`, max: `100`).
- `offset` *(optional, integer)*: Number of records to skip (default: `0`).
- `risk_level` *(optional)*: Filter by `Safe` \| `Low` \| `Medium` \| `High` \| `Critical`
- `category` / `threat_type` *(optional)*: Filter by `phishing` \| `deepfake` \| `impersonation` \| `account_takeover` \| `malicious_url` \| `system_anomaly`
- `status` *(optional)*: Filter by `open` \| `investigating` \| `resolved`

**Response (`200 OK`):**
```json
{
  "total": 42,
  "limit": 25,
  "offset": 0,
  "data": [
    {
      "id": "f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
      "threat_type": "phishing",
      "source_type": "email",
      "risk_level": "high",
      "risk_score": 82,
      "explanation": "High Risk: Message demands immediate credential verification under threat of suspension.",
      "status": "open",
      "created_at": "2026-09-09T08:10:00Z",
      "recommended_actions": [
        {
          "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
          "action_type": "Quarantine email and block sender domain.",
          "action_status": "pending",
          "created_at": "2026-09-09T08:10:00Z"
        }
      ],
      "mitre_mappings": [
        {
          "id": "2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e",
          "technique_id": "T1566",
          "technique_name": "Phishing"
        }
      ]
    }
  ]
}
```

**Errors:**
- `401 Unauthorized`: Missing or invalid bearer token.

---

### 4.2 Get Incident Details
Retrieve complete details, technical detection signals, and forensic evidence for a specific incident.

| Property | Specification |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/v1/incidents/:id` *(also available at `/api/incidents/:id`)* |
| **Auth Requirement** | Requires JWT (`Authorization: Bearer <jwt_token>`) |
| **Description** | Returns full incident record with `detection_signals` and `evidence` arrays. Tenant-isolated (returns 404 for cross-tenant access to prevent resource discovery). |

**Path Parameters:**
- `id` *(required, UUID)*: Primary key UUID of the incident.

**Response (`200 OK`):**
```json
{
  "id": "f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
  "user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "organization_id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "threat_type": "phishing",
  "source_type": "email",
  "risk_level": "high",
  "risk_score": 82,
  "explanation": "High Risk: Message demands immediate credential verification under threat of suspension.",
  "status": "open",
  "resolved_by": null,
  "resolved_at": null,
  "created_at": "2026-09-09T08:10:00Z",
  "recommended_actions": [
    {
      "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
      "action_type": "Quarantine email and block sender domain.",
      "action_status": "pending",
      "created_at": "2026-09-09T08:10:00Z"
    }
  ],
  "mitre_mappings": [
    {
      "id": "2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e",
      "technique_id": "T1566",
      "technique_name": "Phishing"
    }
  ],
  "detection_signals": [
    {
      "signal_name": "urgency_score",
      "signal_value": "0.92",
      "weight": 0.8
    },
    {
      "signal_name": "credential_solicitation",
      "signal_value": "true",
      "weight": 0.9
    }
  ],
  "evidence": []
}
```

**Errors:**
- `401 Unauthorized`: Missing or invalid bearer token.
- `404 Not Found`: Incident ID does not exist, is invalid, or belongs to another tenant/user (`{ "error": "NOT_FOUND", "message": "Incident not found" }`).

---

### 4.3 Update Incident Status
Update an incident's triage lifecycle state.

| Property | Specification |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/incidents/:id` |
| **Auth Requirement** | Requires JWT (Admin-only for org-wide incidents) |
| **Description** | Updates incident status to open, investigating, or resolved. |

**Path Parameters:**
- `id` *(required)*: UUID or ID of the incident.

**Request Body:**
```json
{
  "status": "resolved" // Enum: "open" | "investigating" | "resolved"
}
```

**Response (`200 OK`):**
```json
{
  "id": "inc_f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
  "status": "resolved",
  "resolved_by": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "updated_at": "2026-09-09T08:20:00Z"
}
```

**Errors:**
- `400 Bad Request`: Invalid status value.
- `403 Forbidden`: Insufficient permissions to modify enterprise incidents.
- `404 Not Found`: Incident ID does not exist.

---

## 5. Actions (Triage Operations)

Endpoints used to mark incident-recommended actions as taken or dismissed during threat remediation workflows.

### 5.1 Update Action Status (`PATCH /api/v1/actions/:id`)
Update the execution status of a recommended remediation action.

| Property | Specification |
|---|---|
| **Method** | `PATCH` |
| **Path** | `/api/v1/actions/:id` *(also available at `/api/actions/:id`)* |
| **Auth Requirement** | Requires JWT (`Authorization: Bearer <jwt_token>`) |
| **Description** | Updates a recommended action status to `taken` or `dismissed`. Scoped to the authenticated user's incidents (for individuals/employees) or organization incidents (for admins). Returns 404 for cross-tenant access. |

**Path Parameters:**
- `id` *(required, UUID)*: Primary key UUID of the recommended action.

**Request Body:**
```json
{
  "action_status": "taken" // Enum: "taken" | "dismissed"
}
```

**Response (`200 OK`):**
```json
{
  "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "incident_id": "f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
  "action_type": "Quarantine email and block sender domain.",
  "action_status": "taken",
  "created_at": "2026-09-09T08:10:00Z"
}
```

**Errors:**
- `400 Bad Request`: `action_status` missing or not equal to `"taken"` or `"dismissed"` (`{ "error": "INVALID_STATUS", "message": "action_status must be either 'taken' or 'dismissed'" }`).
- `401 Unauthorized`: Missing or invalid bearer token.
- `404 Not Found`: Action ID does not exist, is invalid, or belongs to an incident not accessible to the user (`{ "error": "NOT_FOUND", "message": "Recommended action not found" }`).

---

## 6. Guardian Linking (Mobile)

Endpoints supporting "Guardian Mode", enabling users to link accounts with family members or dependents to supervise security alerts.

### 6.1 Link Dependent Account
Initiate a guardian-dependent relationship. Creates a pending link awaiting confirmation from the dependent.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/guardian/link` |
| **Auth Requirement** | Requires JWT |
| **Description** | Initiates a link request between a guardian account and a dependent account. The authenticated user must be either the guardian or the dependent. Link is initialized with status `pending`. |

**Request Body:**
```json
{
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f"
}
```

**Response (`201 Created`):**
```json
{
  "link_id": "lnk_3821f92a",
  "status": "pending",
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "created_at": "2026-09-09T08:25:00Z"
}
```

**Errors:**
- `400 Bad Request`: Missing IDs (`INVALID_PAYLOAD`) or self-linking (`INVALID_LINK`).
- `403 Forbidden`: Authenticated user is neither the guardian nor the dependent (`FORBIDDEN`).

---

### 6.2 Accept Guardian Link
Accept a pending guardian link request.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/guardian/link/:id/accept` |
| **Auth Requirement** | Requires JWT |
| **Description** | Confirms and activates a pending guardian link. Only the designated dependent user (`dependent_user_id`) can accept. Transitions status to `active`. |

**Request Body:** None

**Response (`200 OK`):**
```json
{
  "link_id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "status": "active",
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "created_at": "2026-09-09T08:25:00Z"
}
```

**Errors:**
- `400 Bad Request`: Link is not in `pending` status (`INVALID_STATUS`).
- `404 Not Found`: Link does not exist or caller is not the designated dependent (`NOT_FOUND`).

---

### 6.3 Decline Guardian Link
Decline a pending guardian link request.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/guardian/link/:id/decline` |
| **Auth Requirement** | Requires JWT |
| **Description** | Declines a pending guardian link. Only the designated dependent user (`dependent_user_id`) can decline. Transitions status to `revoked`. |

**Request Body:** None

**Response (`200 OK`):**
```json
{
  "link_id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "status": "revoked",
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "created_at": "2026-09-09T08:25:00Z"
}
```

**Errors:**
- `400 Bad Request`: Link is not in `pending` status (`INVALID_STATUS`).
- `404 Not Found`: Link does not exist or caller is not the designated dependent (`NOT_FOUND`).

---

### 6.4 Get Dependent Alerts
Retrieve high-priority security alerts across all active linked dependents.

| Property | Specification |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/v1/guardian/alerts` |
| **Auth Requirement** | Requires JWT |
| **Description** | Returns alert feed for all active (`status = 'active'`) dependents linked to the requesting guardian. |

**Request Body:** None

**Response (`200 OK`):**
```json
[
  {
    "alert_id": "alt_847192",
    "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
    "dependent_name": "Grandpa Joe",
    "risk_level": "Critical",
    "threat_type": "phishing",
    "explanation": "Critical Risk: Urgent SMS claiming bank card suspension with fraudulent verification link.",
    "recommended_action": "Contact Grandpa Joe immediately to ensure no card details were entered.",
    "timestamp": "2026-09-09T08:15:00Z"
  }
]
```

**Errors:**
- `401 Unauthorized`: Missing or invalid bearer token.

---

### 6.5 List Guardian Links
Retrieve all guardian-dependent relationships associated with the authenticated user or organization.

| Property | Specification |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/v1/guardian/links` |
| **Auth Requirement** | Requires JWT (`Authorization: Bearer <jwt_token>`) |
| **Description** | Returns all guardian links where caller is either guardian or dependent. Admins see all links within their organization. By default, returns active and pending links (excludes revoked unless requested). |

**Query Parameters:**
- `status` *(optional, string)*: Filter links by status (`active`, `pending`, `revoked`, `all`).

**Response (`200 OK`):**
```json
{
  "links": [
    {
      "id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
      "link_id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
      "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
      "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
      "status": "pending",
      "guardian_email": "guardian@family.org",
      "dependent_email": "dependent@family.org",
      "created_at": "2026-09-09T08:25:00Z"
    }
  ]
}
```

**Errors:**
- `400 Bad Request`: Invalid status filter query parameter (`INVALID_STATUS`).
- `401 Unauthorized`: Missing or invalid bearer token.

---

### 6.6 Revoke Guardian Link
Terminate an active or pending guardian-dependent link.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/guardian/link/:id/revoke` |
| **Auth Requirement** | Requires JWT (`Authorization: Bearer <jwt_token>`) |
| **Description** | Allows either the guardian or the dependent to immediately revoke a link. Transitions status to `revoked`. Dependent alerts stop broadcasting to the guardian. |

**Path Parameters:**
- `id` *(required, UUID)*: Primary key UUID of the guardian link.

**Request Body:** None

**Response (`200 OK`):**
```json
{
  "id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "link_id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "status": "revoked",
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "created_at": "2026-09-09T08:25:00Z"
}
```

**Errors:**
- `401 Unauthorized`: Missing or invalid bearer token.
- `404 Not Found`: Link not found, invalid UUID, or caller is not a participant on this link (`NOT_FOUND`).

---

### 6.7 Search User by Email
Find a user by email to establish a guardian-dependent relationship.

| Property | Specification |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/v1/users/search` *(also `/api/v1/guardian/users/search`)* |
| **Auth Requirement** | Requires JWT (`Authorization: Bearer <jwt_token>`) |
| **Description** | Searches for a registered user by email before creating a guardian link. Scoped to same organization for enterprise callers, or across individuals for consumer callers. Password hashes and credentials strictly excluded. Rate limited at 30 req / 15 min. |

**Query Parameters:**
- `email` *(required, string)*: Email address to search for.

**Response (`200 OK`):**
```json
{
  "id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "email": "dependent@family.org",
  "role": "individual",
  "organization_id": null
}
```

**Errors:**
- `400 Bad Request`: Missing or empty `email` query parameter (`BAD_REQUEST`).
- `401 Unauthorized`: Missing or invalid bearer token.
- `404 Not Found`: No user found matching the email address within authorized scope (`NOT_FOUND`).
- `429 Too Many Requests`: Search rate limit exceeded (`RATE_LIMIT_EXCEEDED`).

---

## 7. Internal Detection Services (Node.js Gateway → FastAPI ML Service)

> **RESTRICTED:** Internal private network only. Never exposed directly to the public web or client applications.

All internal FastAPI detection endpoints receive engine-specific payloads and **must return the standardized risk shape**:
`{ risk_level, explanation, recommended_action, confidence_score }`.

---

### 7.1 Detect Phishing
Evaluates text and metadata for social engineering and phishing indicators.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/internal/detect/phishing` |
| **Auth Requirement** | Internal Service (Internal Network / API Secret Key) |
| **Description** | Natural language analysis using few-shot LLM with offline TF-IDF/XGBoost fallback. |

**Request Body:**
```json
{
  "text": "Your account has been restricted. Click here to confirm identity: http://secure-verify.xyz",
  "source_type": "email" // "email" | "sms" | "social"
}
```

**Response (`200 OK`):**
```json
{
  "risk_level": "High", // Enum: "Safe" | "Low" | "Medium" | "High" | "Critical"
  "explanation": "High Risk: Deceptive language mimicking banking security alerts with high urgency and suspicious domain.",
  "recommended_action": "Quarantine email and block domain.",
  "confidence_score": 0.94
}
```

---

### 7.2 Detect Deepfake
Evaluates media for generative AI artifacts, facial inconsistencies, or synthetic voice cloning.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/internal/detect/deepfake` |
| **Auth Requirement** | Internal Service (Internal Network / API Secret Key) |
| **Description** | Vision Transformer (ViT) image classifier or ASVspoof audio anti-spoofing detector. |

**Request Body:**
```json
{
  "file_url": "https://storage.cyberguard.internal/uploads/sample.png",
  "media_type": "image" // "image" | "audio"
}
```

**Response (`200 OK`):**
```json
{
  "risk_level": "High", // Enum: "Safe" | "Low" | "Medium" | "High" | "Critical"
  "explanation": "High Risk: Vision Transformer detected facial boundary artifacts consistent with synthetic generation.",
  "recommended_action": "Flag media as potentially manipulated and require secondary verification.",
  "confidence_score": 0.88
}
```

---

### 7.3 Detect Anomaly
Evaluates login metadata or system execution behavior against baseline patterns.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/internal/detect/anomaly` |
| **Auth Requirement** | Internal Service (Internal Network / API Secret Key) |
| **Description** | Isolation Forest model evaluating multi-dimensional telemetry features. |

**Request Body:**
```json
{
  "event_type": "login_attempt", // "login_attempt" | "network_spike" | "process_spike"
  "telemetry_data": {
    "user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "failed_attempts": 5,
    "location": "Unknown",
    "device_is_new": true,
    "time_of_day_anomaly": true
  }
}
```

**Response (`200 OK`):**
```json
{
  "risk_level": "High", // Enum: "Safe" | "Low" | "Medium" | "High" | "Critical"
  "explanation": "High Risk: 5 consecutive failed logins from an unrecognised device and location during unusual hours.",
  "recommended_action": "Require multi-factor authentication challenge and temporarily lock session.",
  "confidence_score": 0.91
}
```

---

## 8. Internal Threat Analysis Engines (Node Gateway → FastAPI ML Service)

All `/internal/analyze/*` endpoints enforce the unified ML detection schema:
- **Shared Response Shape:** `{ "risk_level": "Safe"|"Low"|"Medium"|"High"|"Critical", "risk_score": 0..100, "explanation": string, "signals": object, "recommended_actions": string[], "confidence_score": 0.0..1.0 }`

### 8.1 Analyze Message (`POST /internal/analyze/message`)
- **Request Body:** `{ "text": string, "source_type": "email" | "sms" | "social" }`
- **Response Shape (`200 OK`):**
  ```json
  {
    "risk_level": "High",
    "risk_score": 82,
    "explanation": "Message exhibits extreme urgency cues demanding credential verification and contains an unverified typo-squatted link.",
    "signals": {
      "urgency_score": 0.92,
      "credential_solicitation": true,
      "brand_targeted": "chase",
      "model_type": "nlp_hybrid_transformer"
    },
    "recommended_actions": [
      "Do not click any embedded links",
      "Quarantine message and flag domain to enterprise gateway"
    ],
    "confidence_score": 0.94
  }
  ```

### 8.2 Analyze URL (`POST /internal/analyze/url`)
- **Request Body:** `{ "url": string }`
- **Response Shape (`200 OK`):**
  ```json
  {
    "risk_level": "Critical",
    "risk_score": 95,
    "explanation": "Domain mimics PayPal brand name, was registered within the last 48 hours, and matches active phishing blacklists.",
    "signals": {
      "levenshtein_distance": 2,
      "target_brand": "paypal",
      "domain_age_days": 2,
      "ssl_issuer_untrusted": true
    },
    "recommended_actions": [
      "Block domain network-wide",
      "Revoke active sessions for credentials entered"
    ],
    "confidence_score": 0.98
  }
  ```

### 8.3 Analyze Media (`POST /internal/analyze/media`)
- **Request Body:** `{ "file_url": string, "media_type": "image" | "audio" }`
- **Response Shape (`200 OK`):**
  ```json
  {
    "risk_level": "High",
    "risk_score": 87,
    "explanation": "Acoustic spectral analysis indicates synthetic voice cloning artifacts consistent with generative voice models.",
    "signals": {
      "synthetic_prob": 0.89,
      "spectral_discontinuity": 0.74,
      "model_type": "asv_spoof_detector"
    },
    "recommended_actions": [
      "Require secondary verification over an authenticated channel before taking sensitive action"
    ],
    "confidence_score": 0.89
  }
  ```

### 8.4 Analyze Login (`POST /internal/analyze/login`)
- **Request Body:** `{ "user_id": string, "timestamp": string, "location": string, "device_id": string, "failed_attempts": integer }`
- **Response Shape (`200 OK`):**
  ```json
  {
    "risk_level": "High",
    "risk_score": 85,
    "explanation": "Multiple consecutive failed logins from an unrecognized device and geographical anomaly.",
    "signals": {
      "impossible_travel": true,
      "failed_count": 4,
      "device_known": false,
      "isolation_forest_score": -0.76
    },
    "recommended_actions": [
      "Trigger mandatory MFA verification",
      "Temporarily lock authentication session"
    ],
    "confidence_score": 0.91
  }
  ```

### 8.5 Analyze System (`POST /internal/analyze/system`)
- **Request Body:** `{ "user_id": string, "timestamp": string, "event_type": string, "details": object }`
- **Response Shape (`200 OK`):**
  ```json
  {
    "risk_level": "Medium",
    "risk_score": 58,
    "explanation": "Sudden outbound traffic surge to an unknown external IP address unaccompanied by recognized application processes.",
    "signals": {
      "bytes_transferred": 104857600,
      "ip_reputation_score": 45,
      "unrecognized_process": true
    },
    "recommended_actions": [
      "Inspect host process tree",
      "Temporarily isolate endpoint connection"
    ],
    "confidence_score": 0.82
  }
  ```

---

## 9. Dashboard Analytics Endpoints

These endpoints power the React Command Dashboard overview charts, threat distribution statistics, and MITRE ATT&CK coverage maps.

### 9.1 Analytics Overview (`GET /api/v1/analytics/overview`)
- **Auth Requirement:** Requires JWT (Admin/Enterprise scope)
- **Response (`200 OK`):**
  ```json
  {
    "total_incidents": 142,
    "active_threats": 8,
    "resolved_threats": 134,
    "risk_breakdown": {
      "Safe": 45,
      "Low": 32,
      "Medium": 35,
      "High": 22,
      "Critical": 8
    },
    "category_breakdown": {
      "phishing": 54,
      "malicious_url": 38,
      "deepfake": 16,
      "account_takeover": 21,
      "system_anomaly": 13
    }
  }
  ```

### 9.2 Analytics Trends (`GET /api/v1/analytics/trends`)
- **Auth Requirement:** Requires JWT
- **Response (`200 OK`):**
  ```json
  [
    { "date": "2026-09-03", "incidents": 12, "high_critical": 2 },
    { "date": "2026-09-04", "incidents": 18, "high_critical": 5 },
    { "date": "2026-09-05", "incidents": 9,  "high_critical": 1 },
    { "date": "2026-09-06", "incidents": 24, "high_critical": 8 },
    { "date": "2026-09-07", "incidents": 31, "high_critical": 7 },
    { "date": "2026-09-08", "incidents": 19, "high_critical": 3 },
    { "date": "2026-09-09", "incidents": 29, "high_critical": 4 }
  ]
  ```

### 9.3 MITRE ATT&CK Breakdown (`GET /api/v1/analytics/mitre`)
- **Auth Requirement:** Requires JWT
- **Response (`200 OK`):**
  ```json
  [
    { "technique_id": "T1566", "technique_name": "Phishing", "incident_count": 54 },
    { "technique_id": "T1110", "technique_name": "Brute Force / Credential Stuffing", "incident_count": 21 },
    { "technique_id": "T1204", "technique_name": "User Execution - Malicious URL", "incident_count": 38 },
    { "technique_id": "T1585", "technique_name": "Establish Accounts / Impersonation", "incident_count": 16 },
    { "technique_id": "T1071", "technique_name": "Application Layer Protocol Anomaly", "incident_count": 13 }
  ]
  ```

---

## 10. Audit Logging Endpoints

Append-only, immutable audit trail for security compliance, administrative review, and automated response actions.

### 10.1 List Audit Logs
Retrieve paginated audit log events strictly scoped to the authenticated admin's organization.

| Property | Specification |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/v1/audit-logs` *(also available at `/api/audit-logs`)* |
| **Auth Requirement** | Bearer JWT (Admin role only: `roleCheck(['admin'])`) |
| **Rate Limit** | General limiter (100 req / 15m) |
| **Description** | Returns an append-only sequence of audit log entries for the caller's organization. Admins without an organization receive an empty array with total 0. Sensitive fields are redacted and strings longer than 500 characters are truncated. |

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `action` | String | No | — | Filter by audit action (e.g., `auth:login_success`, `incident:status_updated`) |
| `resource_type` | String | No | — | Filter by resource type (e.g., `incident`, `action`, `user`, `guardian_link`) |
| `user_id` | UUID | No | — | Filter by the target or actor user ID |
| `from` | ISO8601 String | No | — | Lower bound created_at timestamp |
| `to` | ISO8601 String | No | — | Upper bound created_at timestamp |
| `limit` | Integer | No | `25` | Maximum number of records to return (capped at 100) |
| `offset` | Integer | No | `0` | Number of records to skip |

**Response (`200 OK`):**
```json
{
  "total": 1,
  "limit": 25,
  "offset": 0,
  "logs": [
    {
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
      "user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
      "actor_type": "admin",
      "action": "incident:status_updated",
      "resource_type": "incident",
      "resource_id": "3c8340d8-118e-4a69-9da8-7cfa8c95029e",
      "details": {
        "previous_status": "open",
        "new_status": "investigating"
      },
      "ip_address": "127.0.0.1",
      "created_at": "2026-10-02T11:00:00.000Z"
    }
  ]
}
```

**Errors:**
- `401 Unauthorized`: Missing, expired, or invalid JWT token (`{ "error": "UNAUTHORIZED" }`).
- `403 Forbidden`: Authenticated user lacks `admin` role (`{ "error": "FORBIDDEN" }`).
- `429 Too Many Requests`: General rate limit exceeded.
- `500 Internal Server Error`: Database query failure (`{ "error": "INTERNAL_SERVER_ERROR" }`).

---

## 11. Automated Response Layer Endpoints (Phase 1B: Shadow Mode)

Automated response orchestration and policy management. In Phase 1B, the policy engine operates in strict **Shadow Mode**: proposed actions are evaluated, matched against tenant policies, guardrailed, and logged to `response_actions` with `status='proposed'` and `action_mode='shadow'`. No disruptive actions are executed.

### 11.1 List Response Actions
Retrieve paginated response actions (proposed, pending approval, executed, etc.) scoped to the authenticated admin's organization.

| Property | Specification |
|---|---|
| **Method** | `GET` |
| **Path** | `/api/v1/admin/response-actions` |
| **Auth Requirement** | Bearer JWT (Admin role only: `roleCheck(['admin'])`) |
| **Rate Limit** | General limiter (100 req / 15m) |
| **Description** | Returns proposed or executed response actions for the caller's organization with optional status and incident filters. |

**Query Parameters:**
| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `incident_id` | UUID | No | — | Filter by specific incident ID |
| `status` | String | No | — | Filter by status (`proposed`, `pending_approval`, `approved`, `rejected`, `executed`, `failed`, `expired`, `rolled_back`) |
| `from` | ISO8601 String | No | — | Lower bound created_at timestamp |
| `to` | ISO8601 String | No | — | Upper bound created_at timestamp |
| `limit` | Integer | No | `25` | Maximum number of records to return (capped at 100) |
| `offset` | Integer | No | `0` | Number of records to skip |

**Response (`200 OK`):**
```json
{
  "success": true,
  "total": 1,
  "limit": 25,
  "offset": 0,
  "actions": [
    {
      "id": "e47ac10b-58cc-4372-a567-0e02b2c3d480",
      "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
      "incident_id": "3c8340d8-118e-4a69-9da8-7cfa8c95029e",
      "policy_id": "8d09bf3c-4e89-48ce-8dbe-268e24c2cecb",
      "action_type": "notify_admin",
      "action_mode": "shadow",
      "status": "proposed",
      "requested_by_id": null,
      "approved_by_id": null,
      "approved_at": null,
      "target": {
        "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
        "incident_id": "3c8340d8-118e-4a69-9da8-7cfa8c95029e"
      },
      "result": null,
      "created_at": "2026-10-03T00:30:00.000Z",
      "scheduled_at": null,
      "executed_at": null,
      "expires_at": null
    }
  ]
}
```

**Errors:**
- `401 Unauthorized`: Missing or invalid JWT (`{ "error": "UNAUTHORIZED" }`).
- `403 Forbidden`: Authenticated user lacks `admin` role or organization membership (`{ "error": "FORBIDDEN" }`).
- `500 Internal Server Error`: Server failure retrieving actions.

---

### 11.2 Create Response Policy
Create a new automated response policy for the authenticated administrator's organization.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/admin/response-policies` |
| **Auth Requirement** | Bearer JWT (Admin role only: `roleCheck(['admin'])`) |
| **Rate Limit** | General limiter (100 req / 15m) |
| **Description** | Configures automated evaluation rules for incoming incidents based on threat type, risk score threshold, and optional target filters. |

**Request Body:**
```json
{
  "name": "High Severity Phishing Response Policy",
  "enabled": true,
  "rules": [
    {
      "threat_type": "phishing",
      "min_score": 70,
      "action_type": "notify_admin",
      "action_mode": "shadow",
      "requires_approval": false,
      "auto_execute_after_mins": 0,
      "target_filter": {
        "user_roles": ["employee", "admin"]
      }
    }
  ]
}
```

**Response (`201 Created`):**
```json
{
  "success": true,
  "policy": {
    "id": "8d09bf3c-4e89-48ce-8dbe-268e24c2cecb",
    "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
    "name": "High Severity Phishing Response Policy",
    "enabled": true,
    "created_by_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "rules": [
      {
        "threat_type": "phishing",
        "min_score": 70,
        "action_type": "notify_admin",
        "action_mode": "shadow",
        "requires_approval": false,
        "auto_execute_after_mins": 0,
        "target_filter": {
          "user_roles": ["employee", "admin"]
        }
      }
    ],
    "created_at": "2026-10-03T00:30:00.000Z",
    "updated_at": "2026-10-03T00:30:00.000Z"
  }
}
```

**Errors:**
- `400 Bad Request`: Missing policy name or invalid rules format (`{ "error": "VALIDATION_ERROR", "message": "..." }`).
- `401 Unauthorized`: Missing or invalid JWT.
- `403 Forbidden`: Authenticated user lacks `admin` role or organization membership.
- `500 Internal Server Error`: Failed to create policy in database.

---

### 11.3 Approve or Reject Response Action
Allows organization administrators to approve or reject a proposed or pending response action.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/admin/actions/:id/approve` *(also available at `/api/v1/admin/response-actions/:id/approve`)* |
| **Auth Requirement** | Bearer JWT (Admin role only: `roleCheck(['admin'])`) |
| **Rate Limit** | General limiter (100 req / 15m) |
| **Description** | Updates the response action status to `'approved'` or `'rejected'`, sets `approved_by_id` and `approved_at`, emits an append-only audit log entry, and dispatches a confirmation email to the approver. |

**Request Body:**
```json
{
  "approved": true // boolean: true to approve, false to reject
}
```

**Response (`200 OK`):**
```json
{
  "success": true,
  "action": {
    "id": "e47ac10b-58cc-4372-a567-0e02b2c3d480",
    "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
    "incident_id": "3c8340d8-118e-4a69-9da8-7cfa8c95029e",
    "policy_id": "8d09bf3c-4e89-48ce-8dbe-268e24c2cecb",
    "action_type": "notify_admin",
    "action_mode": "shadow",
    "status": "approved",
    "requested_by_id": null,
    "approved_by_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "approved_at": "2026-10-03T01:15:00.000Z",
    "target": {
      "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
      "incident_id": "3c8340d8-118e-4a69-9da8-7cfa8c95029e"
    },
    "result": null,
    "created_at": "2026-10-03T00:30:00.000Z",
    "scheduled_at": null,
    "executed_at": null,
    "expires_at": null
  }
}
```

**Errors:**
- `400 Bad Request`: Missing or non-boolean `approved` field (`{ "error": "VALIDATION_ERROR" }`).
- `401 Unauthorized`: Missing or invalid JWT.
---

### 11.4 Execute Response Action (`POST /api/v1/admin/actions/:id/execute`)
Triggers immediate live execution of an approved or scheduled response action.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/v1/admin/actions/:id/execute` *(also available at `/api/v1/admin/response-actions/:id/execute`)* |
| **Auth Requirement** | Bearer JWT (Admin role only: `roleCheck(['admin'])`) |
| **Rate Limit** | General limiter (100 req / 15m) |
| **Description** | Executes a live response action (session revocation, IP block, domain block, device suspension, or forced password reset). Updates action status to `'executed'`, sets `executed_at`, increments attempts, persists execution output in `result`, and emits an append-only audit log entry. |

**Guardrails Enforced:**
1. **Approval Status**: Action status must be `'approved'` or `'scheduled'`. Any other status (`'proposed'`, `'executed'`, `'failed'`) is rejected with `400 Bad Request`.
2. **Live Execution Mode**: Action mode must be `'live'`. Actions in `'shadow'` mode are strictly prohibited from live execution and rejected with `400 Bad Request`.
3. **Protected Targets**: Target IPs or domains in protected infrastructure ranges (e.g. `127.0.0.1`, RFC 1918 private subnets, internal hostnames) cannot be blocked; rejected with `400 Bad Request`.
4. **Retry Limit Cap**: Maximum of 3 execution attempts. Exceeded retries are capped and rejected.
5. **Strict Tenant Isolation**: Admins can only execute actions within their own organization. Cross-tenant access returns `404 Not Found` (never `403`) to avoid resource existence enumeration.

**Request Body:** None (or empty `{}`)

**Response (`200 OK`):**
```json
{
  "success": true,
  "action": {
    "id": "e47ac10b-58cc-4372-a567-0e02b2c3d480",
    "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
    "incident_id": "3c8340d8-118e-4a69-9da8-7cfa8c95029e",
    "policy_id": "8d09bf3c-4e89-48ce-8dbe-268e24c2cecb",
    "action_type": "revoke_session",
    "action_mode": "live",
    "status": "executed",
    "requested_by_id": null,
    "approved_by_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "approved_at": "2026-10-03T01:15:00.000Z",
    "target": {
      "user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
    },
    "result": {
      "revoked_tokens": 2,
      "user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
    },
    "created_at": "2026-10-03T00:30:00.000Z",
    "scheduled_at": null,
    "executed_at": "2026-10-03T02:00:00.000Z",
    "expires_at": null
  },
  "result": {
    "revoked_tokens": 2,
    "user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d"
  }
}
```

**Errors:**
- `400 Bad Request`: Execution guardrail rejected (`{ "error": "EXECUTION_GUARD_REJECTED", "message": "Cannot execute action in 'shadow' mode. Only 'live' mode actions can be executed." }`).
- `401 Unauthorized`: Missing or invalid JWT.
- `403 Forbidden`: Authenticated user lacks `admin` role (`{ "error": "FORBIDDEN" }`).
- `404 Not Found`: Response action does not exist or belongs to another organization (`{ "error": "NOT_FOUND", "message": "Response action not found" }`).
- `500 Internal Server Error`: Execution failed unexpectedly (`{ "error": "EXECUTION_FAILED", "message": "..." }`).





