# CYBERGUARD — Quick API Reference & Integration Cheat Sheet

> **Base URL:** `http://localhost:5000/api/v1` *(also mirrored at `/api`)*  
> **WebSocket URL:** `ws://localhost:5000` (Socket.io v4)  
> **ML Service URL:** `http://localhost:8000` (FastAPI Internal)  

---

## 1. Quick Route Index

| Method | Endpoint Path | Auth Required | Purpose |
|---|---|---|---|
| `GET` | `/health` | None | Gateway health & uptime probe |
| `POST` | `/api/v1/auth/signup` | Public (5/15m) | Register user profile & receive JWT |
| `POST` | `/api/v1/auth/login` | Public (5/15m) | Authenticate credentials & receive JWT |
| `GET` | `/api/v1/auth/me` | Bearer JWT | Retrieve current user profile |
| `POST` | `/api/v1/check/message` | Bearer JWT (100/15m) | Inspect message text for phishing / prompt injection |
| `POST` | `/api/v1/check/url` | Bearer JWT (100/15m) | Inspect URL for typosquatting / malware |
| `POST` | `/api/v1/check/media` | Bearer JWT (100/15m) | Inspect image / audio URL for synthetic deepfake |
| `POST` | `/api/v1/telemetry/login-event` | Bearer JWT | Ingest login telemetry from Guard App sensor |
| `POST` | `/api/v1/telemetry/system-event`| Bearer JWT | Ingest host process / network telemetry from Guard App |
| `GET` | `/api/v1/incidents` | Bearer JWT | List paginated incidents (tenant / user scoped) |
| `GET` | `/api/v1/incidents/:id` | Bearer JWT | Get full incident details with forensic signals & evidence |
| `PATCH`| `/api/v1/incidents/:id` | **`admin` only** | Update incident triage state (`open`, `investigating`, `resolved`) |
| `PATCH`| `/api/v1/actions/:id` | Bearer JWT | Update recommended action status (`taken`, `dismissed`) |
| `POST` | `/api/v1/guardian/link` | Bearer JWT | Create pending guardian-dependent link |
| `POST` | `/api/v1/guardian/link/:id/accept` | Dependent JWT | Accept pending guardian link (transitions to `active`) |
| `POST` | `/api/v1/guardian/link/:id/decline`| Dependent JWT | Decline pending guardian link (transitions to `revoked`) |
| `POST` | `/api/v1/guardian/link/:id/revoke` | Dependent JWT | Alias to decline endpoint |
| `GET` | `/api/v1/guardian/alerts` | Guardian JWT | Get high & critical alerts for active dependents |
| `GET` | `/api/v1/analytics/overview` | Bearer JWT | Aggregated KPI counts & category breakdowns |
| `GET` | `/api/v1/analytics/trends` | Bearer JWT | Time-series incident trendline data |
| `GET` | `/api/v1/analytics/mitre` | Bearer JWT | MITRE ATT&CK technique distribution counts |

---

## 2. Authentication & Authorization

All authenticated endpoints expect the following header:
```http
Authorization: Bearer <jwt_token>
```

### 2.1 Register (`POST /api/v1/auth/signup`)
```bash
curl -X POST http://localhost:5000/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "analyst@enterprise.com",
    "password": "SecurePassword123!",
    "full_name": "Jane Doe",
    "role": "individual"
  }'
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
    "created_at": "2026-09-28T10:00:00.000Z"
  }
}
```

---

### 2.2 Login (`POST /api/v1/auth/login`)
```bash
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@enterprise.com",
    "password": "SecurePassword123!"
  }'
```
**Response (`200 OK`):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "email": "admin@enterprise.com",
    "full_name": "Jane Doe",
    "role": "admin",
    "organization_id": "b3b2c1a0-4d5e-6f7a-8b9c-0d1e2f3a4b5c"
  }
}
```

---

### 2.3 Profile (`GET /api/v1/auth/me`)
```bash
curl -X GET http://localhost:5000/api/v1/auth/me \
  -H "Authorization: Bearer <jwt_token>"
```
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

---

## 3. Threat Detection Checks

### 3.1 Check Message (`POST /api/v1/check/message`)
```bash
curl -X POST http://localhost:5000/api/v1/check/message \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "text": "URGENT: Your bank account is locked. Verify at http://fakebank-update.xyz",
    "source_type": "email"
  }'
```
**Response (`200 OK`):**
```json
{
  "id": "f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
  "risk_level": "High",
  "explanation": "High Risk: Message exhibits extreme urgency cues demanding credential verification and contains an unverified typo-squatted link.",
  "recommended_actions": [
    "Do not click any links. Report and delete the message immediately."
  ],
  "signals": {
    "urgency_score": 0.92,
    "credential_solicitation": true,
    "brand_targeted": "chase",
    "model_type": "nlp_hybrid_transformer"
  }
}
```

---

### 3.2 Check URL (`POST /api/v1/check/url`)
```bash
curl -X POST http://localhost:5000/api/v1/check/url \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://secure-login-alert-paypal.top/verify"
  }'
```
**Response (`200 OK`):**
```json
{
  "id": "c82b4a12-87f1-4c12-9844-32b0a1d82f71",
  "risk_level": "Critical",
  "explanation": "Domain mimics PayPal brand patterns, utilizes high-risk TLD or raw IP, and matches active phishing structural signatures.",
  "recommended_actions": [
    "Block domain network-wide and revoke any credentials entered on this site."
  ],
  "signals": {
    "target_brand": "paypal",
    "is_suspicious_tld": true,
    "has_suspicious_keyword": true,
    "entropy": 3.84
  }
}
```

---

### 3.3 Check Media (`POST /api/v1/check/media`)
```bash
curl -X POST http://localhost:5000/api/v1/check/media \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "file_url": "https://cdn.example.com/audio/voice-sample.wav",
    "media_type": "audio"
  }'
```
**Response (`200 OK`):**
```json
{
  "id": "d71a8e23-74b2-4d1a-82c1-92b1a8f94e22",
  "risk_level": "High",
  "explanation": "Acoustic spectral analysis indicates synthetic voice cloning artifacts consistent with generative voice models.",
  "recommended_actions": [
    "Verify speaker identity via a secondary known channel before taking financial or sensitive action."
  ],
  "confidence_score": 0.89,
  "signals": {
    "file_url": "https://cdn.example.com/audio/voice-sample.wav",
    "media_type": "audio",
    "synthetic_prob": 0.89,
    "spectral_anomaly_score": 0.74,
    "model_type": "asv_spoof_detector"
  }
}
```

---

## 4. Incidents & Triage

### 4.1 List Incidents (`GET /api/v1/incidents`)
**Query Parameters:**
- `limit`: Page size (default `25`, max `100`).
- `offset`: Offset count (default `0`).
- `risk_level`: Filter by `safe`, `low`, `medium`, `high`, `critical`.
- `status`: Filter by `open`, `investigating`, `resolved`.
- `threat_type`: Filter by threat type.

```bash
curl -X GET "http://localhost:5000/api/v1/incidents?limit=10&offset=0&status=open" \
  -H "Authorization: Bearer <jwt_token>"
```
**Response (`200 OK`):**
```json
{
  "total": 42,
  "limit": 10,
  "offset": 0,
  "incidents": [
    {
      "id": "f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
      "threat_type": "phishing",
      "source_type": "email",
      "risk_level": "high",
      "risk_score": 82,
      "explanation": "High Risk: Message demands immediate credential verification under threat of suspension.",
      "status": "open",
      "created_at": "2026-09-28T08:10:00.000Z",
      "recommended_actions": [
        {
          "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
          "action_type": "Quarantine email and block sender domain.",
          "action_status": "pending",
          "created_at": "2026-09-28T08:10:00.000Z"
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
  ],
  "data": [ /* same array as incidents */ ]
}
```

---

### 4.2 Update Incident Status (`PATCH /api/v1/incidents/:id`)
*Requires `role: 'admin'`*.
```bash
curl -X PATCH http://localhost:5000/api/v1/incidents/f72a19b4-3c81-49e0-81f3-241b2c1a89d2 \
  -H "Authorization: Bearer <admin_jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "resolved"
  }'
```
**Response (`200 OK`):**
```json
{
  "id": "f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
  "status": "resolved",
  "resolved_by": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "updated_at": "2026-09-28T10:15:00.000Z"
}
```

---

### 4.3 Update Recommended Action Status (`PATCH /api/v1/actions/:id`)
*Callable by all authenticated users*.
```bash
curl -X PATCH http://localhost:5000/api/v1/actions/1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "action_status": "taken"
  }'
```
**Response (`200 OK`):**
```json
{
  "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
  "incident_id": "f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
  "action_type": "Quarantine email and block sender domain.",
  "action_status": "taken",
  "created_at": "2026-09-28T08:10:00.000Z"
}
```

---

## 5. Guardian Mode Endpoints

### 5.1 Initiate Link (`POST /api/v1/guardian/link`)
```bash
curl -X POST http://localhost:5000/api/v1/guardian/link \
  -H "Authorization: Bearer <jwt_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f"
  }'
```
**Response (`201 Created`):**
```json
{
  "link_id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
  "status": "pending",
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "created_at": "2026-09-28T10:20:00.000Z"
}
```

---

### 5.2 Accept Link (`POST /api/v1/guardian/link/:id/accept`)
*Callable strictly by `dependent_user_id`*.
```bash
curl -X POST http://localhost:5000/api/v1/guardian/link/9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e/accept \
  -H "Authorization: Bearer <dependent_jwt_token>"
```
**Response (`200 OK`):**
```json
{
  "link_id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
  "status": "active",
  "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
  "created_at": "2026-09-28T10:20:00.000Z"
}
```

---

### 5.3 Dependent Alerts Feed (`GET /api/v1/guardian/alerts`)
*Callable by active guardians*.
```bash
curl -X GET http://localhost:5000/api/v1/guardian/alerts \
  -H "Authorization: Bearer <guardian_jwt_token>"
```
**Response (`200 OK`):**
```json
[
  {
    "alert_id": "f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
    "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
    "dependent_name": "Grandpa Joe",
    "risk_level": "Critical",
    "threat_type": "phishing",
    "explanation": "Critical Risk: Urgent SMS claiming bank card suspension with fraudulent verification link.",
    "recommended_action": "Review threat details and contact dependent immediately.",
    "timestamp": "2026-09-28T08:15:00.000Z"
  }
]
```

---

## 6. Dashboard Analytics

### 6.1 Analytics Overview (`GET /api/v1/analytics/overview`)
```bash
curl -X GET http://localhost:5000/api/v1/analytics/overview \
  -H "Authorization: Bearer <jwt_token>"
```
**Response (`200 OK`):**
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

---

### 6.2 Analytics Trends (`GET /api/v1/analytics/trends`)
```bash
curl -X GET http://localhost:5000/api/v1/analytics/trends \
  -H "Authorization: Bearer <jwt_token>"
```
**Response (`200 OK`):**
```json
[
  { "date": "2026-09-22", "incidents": 12, "high_critical": 2 },
  { "date": "2026-09-23", "incidents": 18, "high_critical": 5 },
  { "date": "2026-09-24", "incidents": 9,  "high_critical": 1 },
  { "date": "2026-09-25", "incidents": 24, "high_critical": 8 },
  { "date": "2026-09-26", "incidents": 31, "high_critical": 7 },
  { "date": "2026-09-27", "incidents": 19, "high_critical": 3 },
  { "date": "2026-09-28", "incidents": 29, "high_critical": 4 }
]
```

---

### 6.3 MITRE Breakdown (`GET /api/v1/analytics/mitre`)
```bash
curl -X GET http://localhost:5000/api/v1/analytics/mitre \
  -H "Authorization: Bearer <jwt_token>"
```
**Response (`200 OK`):**
```json
[
  { "technique_id": "T1566", "technique_name": "Phishing", "incident_count": 54 },
  { "technique_id": "T1204", "technique_name": "User Execution - Malicious URL", "incident_count": 38 },
  { "technique_id": "T1110", "technique_name": "Brute Force / Credential Stuffing", "incident_count": 21 },
  { "technique_id": "T1585", "technique_name": "Establish Accounts / Impersonation", "incident_count": 16 },
  { "technique_id": "T1071", "technique_name": "Application Layer Protocol Anomaly", "incident_count": 13 }
]
```

---

## 7. Socket.io Real-Time Client Setup

```javascript
import { io } from 'socket.io-client';

const socket = io('http://localhost:5000', {
  auth: {
    token: localStorage.getItem('cyberguard_token')
  }
});

// Successful connection
socket.on('connect', () => {
  console.log('Connected to CyberGuard real-time socket feed. Socket ID:', socket.id);
});

// Receive live threat incidents
socket.on('incident:new', (incident) => {
  console.log('Live Security Incident Broadcast:', incident);
  // Example UI action: Toast alert, increment badge count, insert to feed
});

// Authentication error
socket.on('connect_error', (error) => {
  console.error('Socket authentication failed:', error.message);
});
```
