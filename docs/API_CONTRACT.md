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

---

## 1. Authentication Endpoints

### 1.1 User Signup
Register a new user as an individual, employee, or organization admin.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/signup` |
| **Auth Requirement** | Public |
| **Description** | Creates user account and returns authentication token with initial profile. |

**Request Body:**
```json
{
  "email": "analyst@enterprise.com",
  "password": "SecurePassword123!",
  "full_name": "Jane Doe",
  "role": "individual", // Enum: "individual" | "employee" | "admin"
  "organization_id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c" // UUID, optional (required for employees)
}
```

**Response (`201 Created`):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "email": "analyst@enterprise.com",
    "full_name": "Jane Doe",
    "role": "individual",
    "organization_id": null,
    "created_at": "2026-09-09T08:00:00Z"
  }
}
```

**Errors:**
- `400 Bad Request`: Malformed email, weak password, or duplicate account (`{ "error": "EMAIL_EXISTS", "message": "Email already registered" }`).

---

### 1.2 User Login
Authenticate user credentials and receive a JWT session token.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/auth/login` |
| **Auth Requirement** | Public |
| **Description** | Validates email and password; generates JWT bearer token. |

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
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "email": "analyst@enterprise.com",
    "full_name": "Jane Doe",
    "role": "admin",
    "organization_id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c"
  }
}
```

**Errors:**
- `401 Unauthorized`: Invalid email or password (`{ "error": "INVALID_CREDENTIALS", "message": "Invalid email or password" }`).

---

### 1.3 Get Current User Profile (`GET /api/v1/auth/me`)
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
  "full_name": "Jane Doe",
  "role": "admin",
  "organization_id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "created_at": "2026-09-09T08:00:00Z"
}
```

**Errors:**
- `401 Unauthorized`: Missing, expired, or invalid token (`{ "error": "UNAUTHORIZED" | "TOKEN_EXPIRED" | "INVALID_TOKEN", "message": "..." }`).

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
Analyze an uploaded image or audio file for synthetic manipulation, generative artifacts, or voice cloning.

| Property | Specification |
|---|---|
| **Method** | `POST` |
| **Path** | `/api/check/media` |
| **Auth Requirement** | Requires JWT |
| **Description** | Evaluates image/audio using Vision Transformer (ViT) or voice anti-spoofing models. |

**Request Body:**
```json
{
  "file_url": "https://storage.cyberguard.internal/uploads/sample-voice-clip.wav",
  "media_type": "audio" // Enum: "image" | "audio"
}
```

**Response (`200 OK`):**
```json
{
  "risk_level": "High", // Enum: "Safe" | "Low" | "Medium" | "High" | "Critical"
  "explanation": "High Risk: Acoustic spectral analysis indicates synthetic voice cloning artifacts consistent with generative voice models.",
  "recommended_action": "Verify speaker identity via a secondary known channel before taking financial or sensitive action.",
  "confidence_score": 0.89 // Float between 0.0 and 1.0
}
```

**Errors:**
- `400 Bad Request`: Invalid file URL or unsupported `media_type`.
- `422 Unprocessable Entity`: Media file corrupt or unparseable.

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

