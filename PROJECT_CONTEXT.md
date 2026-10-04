# CYBERGUARD — Comprehensive Project Context & Frontend Handoff Guide

> **Document Version:** 1.0.0  
> **Target Audience:** Frontend Development Team & AI Coding Agents  
> **Source Workspace:** `/Users/pritee/CyberGuard`  
> **Status:** Backend Codebase Complete & Audited  
> **Author:** Antigravity AI Architecture Team  

---

## 1. Project Overview

### 1.1 Product Purpose
**CYBERGUARD** is an AI-powered cyber threat intelligence, scam detection, and automated incident response platform. It is architected to defend individuals, enterprises, and vulnerable family members against modern AI-augmented social engineering and digital threats, including:
- **Phishing & Deceptive Messaging:** Natural language inspection of emails, SMS (smishing), and social direct messages.
- **Malicious & Typo-Squatted URLs:** Detection of brand impersonation, spoofed login portals, and zero-day malicious domains.
- **Deepfakes & Synthetic Media:** Analysis of synthetic facial manipulation (images) and voice cloning (audio).
- **Account Takeover (ATO) & Login Anomalies:** Behavioral authentication analysis detecting credential stuffing, impossible travel, and device anomalies.
- **Host & System Telemetry Deviations:** Endpoint behavioral monitoring tracking process abnormalities and outbound network traffic spikes via a lightweight desktop sensor daemon ("Guard App").
- **Incident Triage & Response Orchestration:** Centralized Command Dashboard with automated MITRE ATT&CK mapping, plain-English explanations, prescriptive remediation actions, and real-time WebSocket alerts.
- **Guardian Mode:** Protective supervisory relationship allowing guardians to monitor security incidents and receive real-time critical alerts for linked at-risk dependents (e.g., elderly family members).

---

### 1.2 Target User Personas
The system enforces Role-Based Access Control (RBAC) across four operational user personas:
1. **`individual`:** Everyday consumers using the mobile or web application to inspect suspicious messages/URLs/media, monitor personal security health, and link dependent accounts.
2. **`employee`:** Corporate workforce members affiliated with an organization. Their client telemetry and security checks feed into enterprise aggregate analytics, while their personal data remains isolated from other employees.
3. **`admin`:** Enterprise Security Operations Center (SOC) analysts and organization administrators. Admins possess tenant-wide visibility across all users, devices, telemetry events, and incidents within their assigned `organization_id`. Admins are authorized to triage and transition incident states (`open` → `investigating` → `resolved`).
4. **`guardian`:** A supervisory mode for `individual` accounts linked to one or more `dependent` accounts via `guardian_links`. Guardians receive real-time incident broadcasts and dedicated alert feeds when their dependents encounter `High` or `Critical` threats.

---

### 1.3 Core Features
- **Multi-Modal Threat Inspection:** Unified check endpoints for text messages, URLs, and uploaded media URLs.
- **Explainable AI (XAI):** Every detection returns a normalized risk score (0–100), a 5-tier calibrated risk level, a plain-English human-readable rationale, and technical detection signals.
- **MITRE ATT&CK Mapping:** Automated technique tagging (e.g., `T1566` Phishing, `T1204` Malicious URL, `T1110` Brute Force, `T1586.002` Deepfake Persona, `T1071` Protocol Anomaly).
- **Two-Step Guardian Handshake:** Asymmetric link workflow (`pending` → `active` or `revoked`) ensuring consent before alert sharing.
- **Real-Time Push & Socket Feeds:** Socket.io gateway broadcasting new threats instantly to targeted personal, guardian, and enterprise rooms.
- **Executive & SOC Analytics:** Dashboard metrics displaying active threats, resolution rates, 7-day threat trendlines, and MITRE coverage distribution.

---

### 1.4 Business Rules Inferred from Code
1. **Calibrated 5-Tier Risk Classification:**
   - `"Safe"`: Score 0–19. Benign / verified origin.
   - `"Low"`: Score 20–39. Minor anomaly without malicious intent.
   - `"Medium"`: Score 40–69. Suspicious cues; review advised.
   - `"High"`: Score 70–89. Strong threat indicators; proactive alert.
   - `"Critical"`: Score 90–100. Confirmed active attack; immediate intervention.
2. **Automated Incident Creation Threshold:**
   - In `services/backend/src/controllers/telemetryController.js` (lines 7, 150–154, 264–268), an incident is persisted and dispatched to SOC / Guardians **only** when the detected risk level is in `['medium', 'high', 'critical']`. Low and Safe events are logged to raw audit/telemetry tables without generating active incident tickets.
   - In `services/backend/src/controllers/checkController.js` (lines 48–54, 104–110, 168–175), every user-initiated check persists an incident row.
3. **Tenant & Scoping Isolation:**
   - Non-admin users (`individual`, `employee`) can **only** query and view records where `user_id == req.user.id`.
   - Admin users are restricted to records matching `organization_id == req.user.organization_id`. Admins cannot access data belonging to other organizations.
   - If a client requests a record outside their tenant boundary, the server returns `404 Not Found` (rather than `403 Forbidden`) to prevent resource enumeration attacks (`services/backend/src/controllers/incidentController.js:123-149`).
4. **Role Privileges for Incident Lifecycle:**
   - Only `admin` users can transition incident triage status (`open`, `investigating`, `resolved`) via `PATCH /api/v1/incidents/:id` (`services/backend/src/routes/incidentRoutes.js:11`). Non-admins receive `403 FORBIDDEN`.
   - Any authenticated user can mark individual recommended remediation actions as `taken` or `dismissed` on incidents they own (`services/backend/src/routes/actionRoutes.js:8`).
5. **Guardian Consent Boundary:**
   - A guardian cannot link themselves as their own dependent (`services/backend/src/controllers/guardianController.js:23-28`).
   - Links start in `pending` state and can **only** be accepted or declined by the designated `dependent_user_id` (`guardianController.js:74-78, 120-124`).
   - Guardians only receive alerts for dependents whose link status is strictly `'active'` (`guardianController.js:163-170`).

---

## 2. Tech Stack & Dependencies

### 2.1 Backend API Gateway (`services/backend`)
- **Runtime & Language:** Node.js (v18.x or v20.x), CommonJS JavaScript.
- **Web Framework:** Express.js `^4.19.2` (`services/backend/package.json`).
- **HTTP Server:** Native Node.js `http.createServer`.
- **Database Client:** PostgreSQL connection pool via `pg` `^8.11.5` (`services/backend/src/config/db.js`).
- **Authentication & Security:** `jsonwebtoken` `^9.0.2`, `bcrypt` `^5.1.1`, `cors` `^2.8.5`.
- **Rate Limiting:** `express-rate-limit` `^8.7.0` (`services/backend/src/middlewares/rateLimiter.js`).
- **Real-Time WebSockets:** `socket.io` `^4.7.5` (`services/backend/src/config/socket.js`).
- **Environment Management:** `dotenv` `^16.4.5`.
- **Development Tooling:** `nodemon` `^3.1.0`.

### 2.2 AI/ML Microservice (`services/ml-service`)
- **Runtime & Language:** Python 3.10+ / 3.11+.
- **Web Framework:** FastAPI `>=0.110.0` with Starlette ASGI.
- **ASGI Server:** Uvicorn (standard) `>=0.28.0`.
- **Data Validation:** Pydantic v2 (BaseModel, Field, Enum).
- **Machine Learning & Modeling:** `scikit-learn>=1.4.0`, `joblib>=1.3.0`, `pandas>=2.0.0`, `pyarrow>=14.0.0`.
- **Database Driver:** `psycopg2-binary>=2.9.9`.
- **LLM Integrations (Optional/Dynamic):** OpenAI Python SDK (`openai`), Groq Python SDK (`groq`).

### 2.3 Desktop Endpoint Sensor ("Guard App" — `services/guard-app`)
- **Runtime:** Python 3.10+.
- **System Telemetry:** Native OS socket polling and `/proc` interface telemetry adapter.

### 2.4 Frontend Applications (`apps/web` & `apps/mobile`)
- **Web Application (`apps/web`):** React `^18.3.1`, Vite `^5.2.11`, Tailwind CSS `^3.4.3`, PostCSS `^8.4.38`, Lucide React `^0.378.0`, GSAP `^3.12.7`, `@gsap/react` `^2.1.2`.
- **Mobile Application (`apps/mobile`):** Expo SDK `~51.0.0`, React `18.2.0`, React Native `0.74.1`.

---

## 3. Repository Structure

```
CyberGuard/
├── .agents/                               # Antigravity IDE skills, workflows, and task configs
├── .env.example                           # Root template for environment variables
├── README.md                              # High-level architecture and developer onboarding
├── package.json                           # Root monorepo npm workspace definition
├── apps/                                  # Frontend client applications
│   ├── web/                               # React Command Dashboard (Vite + Tailwind + GSAP)
│   │   ├── index.html                     # Web entry HTML
│   │   ├── package.json                   # Web dependencies (React 18, Vite 5, GSAP 3)
│   │   ├── tailwind.config.js             # Tailwind design tokens and utility config
│   │   ├── vite.config.js                 # Vite bundling configuration
│   │   └── src/
│   │       ├── App.jsx                    # Root React component
│   │       ├── main.jsx                   # React DOM hydration root
│   │       ├── index.css                  # Tailwind directives and CSS variables
│   │       ├── components/                # Reusable UI components (buttons, cards, tables)
│   │       ├── hooks/                     # Custom React hooks (auth, sockets, queries)
│   │       ├── pages/                     # Routed view containers (Dashboard, Triage, Settings)
│   │       └── services/                  # Frontend API client modules
│   └── mobile/                            # React Native (Expo) mobile client
│       ├── App.js                         # Root Expo mobile component
│       ├── app.json                       # Expo configuration manifest
│       ├── package.json                   # Mobile dependencies (Expo 51, RN 0.74)
│       └── src/
│           ├── components/                # Mobile interface elements
│           ├── hooks/                     # Mobile hooks (push notifications, speech TTS)
│           ├── screens/                   # Mobile screens (Scan, Guardian Mode, Alerts)
│           └── services/                  # Mobile API clients
├── datasets/                              # Training datasets (CTU-13 network flows, Cowrie logs)
├── docs/                                  # Architecture, technical specs, and API contracts
│   ├── API_CONTRACT.md                    # Primary API specification across services
│   ├── LOGIN_ENGINE_PHASE_A.md            # Account takeover modeling design
│   ├── LOGIN_ENGINE_PHASE_B.md            # Feature engineering specifications
│   ├── LOGIN_ENGINE_PHASE_C.md            # Anomaly forest benchmark evaluations
│   └── LOGIN_ENGINE_PHASE_D.md            # Gateway integration & e2e specifications
└── services/                              # Backend microservices & daemons
    ├── backend/                           # Node.js / Express API Gateway & Orchestration
    │   ├── package.json                   # Express, pg, bcrypt, jsonwebtoken, socket.io
    │   ├── .env.example                   # Backend-specific environment variables
    │   ├── sql/
    │   │   └── rls_policies.sql           # PostgreSQL Row Level Security (RLS) policies
    │   ├── src/
    │   │   ├── index.js                   # Express server entry point, CORS, routing, sockets
    │   │   ├── config/
    │   │   │   ├── index.js               # Centralized config loader & secret verification
    │   │   │   ├── db.js                  # PostgreSQL pg.Pool connection & transaction helper
    │   │   │   └── socket.js              # Socket.io initialization, JWT auth, room routing
    │   │   ├── controllers/
    │   │   │   ├── actionController.js    # PATCH /actions/:id (taken/dismissed)
    │   │   │   ├── analyticsController.js # Overview cards, trend lines, MITRE aggregates
    │   │   │   ├── authController.js      # Signup, login, and getMe profile endpoints
    │   │   │   ├── checkController.js     # Threat check dispatchers (message, url, media)
    │   │   │   ├── guardianController.js  # Guardian linking handshake and dependent alert feeds
    │   │   │   ├── incidentController.js  # Incident triage, filtering, pagination, status update
    │   │   │   └── telemetryController.js # Guard App telemetry ingestion (login, system events)
    │   │   ├── middlewares/
    │   │   │   ├── auth.js                # JWT Bearer token authentication middleware
    │   │   │   ├── rateLimiter.js         # IP-based rate limiters (auth, check, general)
    │   │   │   └── roleCheck.js           # Role-Based Access Control (RBAC) middleware
    │   │   ├── models/
    │   │   │   ├── Action.js / RecommendedAction.js # CRUD for recommended remediation steps
    │   │   │   ├── AuditLog.js            # Ingestion audit trail logger
    │   │   │   ├── DetectionSignal.js     # Forensic detection signals and weights
    │   │   │   ├── Device.js              # Registered user devices and fingerprints
    │   │   │   ├── GuardianLink.js        # Guardian-dependent relationship states
    │   │   │   ├── Incident.js            # Core incident table queries and scoped filters
    │   │   │   ├── IncidentEvidence.js    # Raw threat payloads and media references
    │   │   │   ├── LoginEvent.js          # Authentication logs and failed attempt tracking
    │   │   │   ├── MitreMapping.js        # MITRE ATT&CK technique lookups and aggregations
    │   │   │   ├── Organization.js        # Multi-tenant enterprise accounts
    │   │   │   ├── TelemetryEvent.js      # Host process and network telemetry logs
    │   │   │   └── User.js                # User profiles and credentials
    │   │   ├── routes/                    # Express router bindings (/auth, /check, etc.)
    │   │   ├── services/
    │   │   │   └── incidentService.js     # Atomic transaction persistence & WebSocket dispatch
    │   │   └── utils/
    │   │       ├── mlClient.js            # Internal HTTP fetch client calling FastAPI engine
    │   │       └── testDbConnection.js    # DB connectivity probe CLI utility
    │   └── test_*.js                      # 10 integration and security test suites
    ├── guard-app/                         # Desktop Host Sensor Daemon
    │   ├── main.py                        # Collector CLI and background agent daemon
    │   ├── collector.py                   # Socket and interface traffic sampler
    │   └── telemetry_adapter.py           # Formatter converting raw OS metrics to API schemas
    └── ml-service/                        # Python FastAPI Threat Detection Engine
        ├── requirements.txt               # FastAPI, scikit-learn, joblib, pandas
        ├── evaluate.py                    # Model benchmarking CLI
        ├── app/
        │   ├── main.py                    # FastAPI server entry point, CORS, routes
        │   ├── models/                    # Serialized model weights (*.joblib, *.json)
        │   ├── prompts/                   # Sanitization & versioned prompts (phishing.py)
        │   ├── routers/                   # API routers (/internal/analyze/*)
        │   ├── schemas/                   # Pydantic schemas (requests, responses, enums)
        │   ├── services/                  # Inference engines (message, url, media, login, system)
        │   └── utils/                     # Preprocessors (CTU-13, Cowrie, URL feature extractor)
        └── tests/                         # 23 Unit, integration, and security test files
```

---

## 4. How to Run Locally

### 4.1 Environment Variables
Configure `.env` in the project root or duplicate `.env.example`:

| Variable Name | Required | Default / Example | Purpose |
|---|---|---|---|
| `PORT` | Optional | `5000` | Port for the Node.js API Gateway |
| `NODE_ENV` | Optional | `development` | Environment mode (`development`, `test`, `production`) |
| `JWT_SECRET` | **YES** | `[secret-32-chars-min]` | HMAC-SHA256 signing secret for JWT access tokens. Gateway throws fatal error if omitted (`config/index.js:22`). |
| `SUPABASE_DB_URL` | **YES** | `postgresql://postgres:password@localhost:5432/cyberguard` | PostgreSQL database connection string (Supabase or local PostgreSQL instance) |
| `ML_SERVICE_URL` | Optional | `http://localhost:8000` | Base URL of upstream Python FastAPI detection engine (`src/utils/mlClient.js`) |
| `ML_SERVICE_TIMEOUT_MS` | Optional | `10000` | Timeout in milliseconds for ML engine calls |
| `FCM_SERVER_KEY` | Optional | `[key]` | Firebase Cloud Messaging server key for mobile push alerts |
| `DEBUG_SQL` | Optional | `false` | When set to `true`, logs SQL queries and durations to stdout |
| `OPENAI_API_KEY` | Optional | `sk-...` | Optional API key for LLM phishing inference in `ml-service` |
| `GROQ_API_KEY` | Optional | `gsk_...` | Alternative LLM key for Groq Cloud inference |

---

### 4.2 Start Commands

#### Method A: Monorepo Root Scripts (`package.json`)
```bash
# Install root and workspace dependencies
npm install

# Run Node.js API Gateway (Port 5000)
npm run dev:backend

# Run React Web Dashboard (Port 5173)
npm run dev:web

# Run Mobile Expo Client (Port 8081)
npm run dev:mobile
```

#### Method B: Manual Service-by-Service Execution
```bash
# Terminal 1: Backend API Gateway
cd services/backend
npm install
npm run dev
# -> Server listening on port 5000

# Terminal 2: AI/ML Microservice
cd services/ml-service
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
# -> Application startup complete. Uvicorn running on http://0.0.0.0:8000

# Terminal 3: React Web Frontend
cd apps/web
npm install
npm run dev
# -> Local: http://localhost:5173/

# Terminal 4 (Optional): Guard App Sensor Daemon
cd services/guard-app
python3 main.py --once --simulate
```

---

### 4.3 Database Setup & Migrations
1. **Database Schema:** Create a PostgreSQL database (locally or on Supabase).
2. **Apply Security Policies & Schema:** Execute `services/backend/sql/rls_policies.sql` in the PostgreSQL query editor.
3. **Verify Connectivity:** Run the built-in diagnostic tool from `services/backend`:
   ```bash
   node src/utils/testDbConnection.js
   ```

### 4.4 Base URLs & API Documentation Links
- **API Gateway Base URL:** `http://localhost:5000`
- **Gateway Versioned Prefix:** `http://localhost:5000/api/v1` (Note: `/api` is mirrored as an alias)
- **Gateway WebSocket Endpoint:** `ws://localhost:5000` (Socket.io)
- **FastAPI ML Service Base URL:** `http://localhost:8000`
- **FastAPI Interactive Swagger UI:** `http://localhost:8000/docs`
- **FastAPI ReDoc Documentation:** `http://localhost:8000/redoc`

---

## 5. Authentication & Authorization

### 5.1 Token Specifications
- **Token Type:** JSON Web Token (JWT), signed using `HS256`.
- **Transmission:** HTTP Request Header:
  ```http
  Authorization: Bearer <jwt_token>
  ```
- **Socket.io Handshake Transmission:** Handshake `auth` object or handshake headers:
  ```javascript
  const socket = io('http://localhost:5000', {
    auth: { token: '<jwt_token>' }
  });
  ```
- **Token Expiry:** Configured for `7d` in `authController.js` (lines 28, 58).
- **Token Storage Recommendation for Frontend:**
  - **Web:** Store in memory or secure HTTP-only cookies where possible; otherwise `sessionStorage` / `localStorage`.
  - **Mobile:** Store in hardware-backed secure storage via `expo-secure-store`.

### 5.2 Token Payload Shape (`req.user`)
Decoded by `services/backend/src/middlewares/auth.js` (lines 43–48):
```typescript
interface DecodedTokenPayload {
  id: string;              // User UUID
  role: 'individual' | 'employee' | 'admin';
  organization_id: string | null;
  email: string;
  iat: number;
  exp: number;
}
```

### 5.3 Endpoint Role Matrix

| Endpoint | Method | Path | Allowed Roles | Description |
|---|---|---|---|---|
| Health Check | `GET` | `/health`, `/api/v1/health` | Public | Unauthenticated liveness probe |
| Signup | `POST` | `/api/v1/auth/signup` | Public | Account registration |
| Login | `POST` | `/api/v1/auth/login` | Public | Account authentication |
| Current User | `GET` | `/api/v1/auth/me` | All authenticated | Retrieves current user profile |
| Check Message | `POST` | `/api/v1/check/message` | All authenticated | Evaluates message for phishing |
| Check URL | `POST` | `/api/v1/check/url` | All authenticated | Evaluates domain/URL |
| Check Media | `POST` | `/api/v1/check/media` | All authenticated | Evaluates image/audio deepfake |
| Login Telemetry | `POST` | `/api/v1/telemetry/login-event` | All authenticated | Reports login attempt telemetry |
| System Telemetry| `POST` | `/api/v1/telemetry/system-event` | All authenticated | Reports system behavior telemetry |
| List Incidents | `GET` | `/api/v1/incidents` | All authenticated | Tenant/user-isolated incident list |
| Get Incident | `GET` | `/api/v1/incidents/:id` | All authenticated | Scoped full incident details |
| Update Status | `PATCH` | `/api/v1/incidents/:id` | **`admin` only** | Updates status (`open`, `investigating`, `resolved`) |
| Update Action | `PATCH` | `/api/v1/actions/:id` | All authenticated | Updates remediation status (`taken`, `dismissed`) |
| Link Dependent | `POST` | `/api/v1/guardian/link` | All authenticated | Creates pending guardian link |
| Accept Link | `POST` | `/api/v1/guardian/link/:id/accept` | Dependent user only | Accepts and activates link |
| Decline Link | `POST` | `/api/v1/guardian/link/:id/decline`| Dependent user only | Declines and revokes link |
| Revoke Link | `POST` | `/api/v1/guardian/link/:id/revoke` | Dependent user only | Revokes link relationship |
| Guardian Alerts| `GET` | `/api/v1/guardian/alerts` | Active guardians | Alerts for active dependents |
| Analytics Overview | `GET` | `/api/v1/analytics/overview` | All authenticated | Summary cards (scoped) |
| Analytics Trends | `GET` | `/api/v1/analytics/trends` | All authenticated | 7-day incident trendline |
| MITRE Matrix | `GET` | `/api/v1/analytics/mitre` | All authenticated | MITRE ATT&CK frequency counts |

---

## 6. Complete Data Models & Database Schema

All database models reside in `services/backend/src/models/` and are defined in `services/backend/sql/rls_policies.sql`.

### 6.1 `users`
Represents user identities across individual, corporate employee, and administrator tiers.
- `id` (`uuid`, Primary Key, default `gen_random_uuid()`): Unique user ID.
- `email` (`varchar(255)`, Unique, Required): User email address.
- `password_hash` (`varchar(255)`, Required): Bcrypt salted hash.
- `full_name` (`varchar(255)`, Optional): User's full display name.
- `role` (`varchar(50)`, Required, Enum: `'individual' | 'employee' | 'admin'`): Access tier.
- `organization_id` / `org_id` (`uuid`, Nullable, Foreign Key → `organizations.id`): Associated corporate tenant ID.
- `created_at` (`timestamptz`, Default `NOW()`): Timestamp of user creation.
- `updated_at` (`timestamptz`, Default `NOW()`): Timestamp of last profile update.

### 6.2 `organizations` / `organisations`
Multi-tenant enterprise organizations.
- `id` (`uuid`, Primary Key): Organization ID.
- `name` (`text`, Required): Company or organization name.
- `domain` (`text`, Nullable): Enterprise email domain (e.g., `acme.corp`).
- `created_at` (`timestamptz`, Default `NOW()`): Registration timestamp.

### 6.3 `devices`
Workstations and mobile endpoints associated with user accounts.
- `id` (`uuid`, Primary Key): Internal device UUID.
- `user_id` (`uuid`, Required, FK → `users.id`): Device owner.
- `device_id` (`text`, Unique, Required): Hardware fingerprint or client-generated UUID.
- `device_name` (`text`, Default `'Unknown Device'`): Friendly hostname (e.g. "MacBook Pro M2").
- `platform` (`text`, Default `'desktop'`): Operating system / platform (`desktop`, `mobile`, `server`).
- `device_fingerprint` (`text`, Nullable): Hardware hash identifier.
- `is_trusted` (`boolean`, Default `true`): Trust status for risk evaluation.
- `last_seen_at` (`timestamptz`, Default `NOW()`): Timestamp of latest communication.
- `created_at` (`timestamptz`, Default `NOW()`): Initial registration timestamp.

### 6.4 `login_events`
Authentication logs ingested from endpoints and web logins.
- `id` (`uuid`, Primary Key): Event ID.
- `user_id` (`uuid`, Required, FK → `users.id`): User being authenticated.
- `device_id` (`uuid`, Nullable, FK → `devices.id`): Resolved device ID.
- `ip_address` (`text`, Nullable): Client IP address.
- `location` (`text`, Nullable): City/country or geographic tag.
- `success` (`boolean`, Required): Whether login succeeded.
- `failed_attempt_count` (`integer`, Default `0`): Consecutive failed counter.
- `created_at` (`timestamptz`, Default `NOW()`): Login timestamp.

### 6.5 `telemetry_events`
Raw host metrics ingested from the Guard App daemon.
- `id` (`uuid`, Primary Key): Event ID.
- `user_id` (`uuid`, Required, FK → `users.id`): Monitored user.
- `device_id` (`uuid`, Nullable, FK → `devices.id`): Monitored device.
- `event_type` (`telemetry_event_type`, Enum: `'process' | 'network' | 'api'`): Event category.
- `payload` (`jsonb`, Required): Raw metrics (process names, bytes sent, remote IPs, ports).
- `created_at` (`timestamptz`, Default `NOW()`): Observation timestamp.

### 6.6 `incidents`
Core security incidents created from detection engines or telemetry triggers.
- `id` (`uuid`, Primary Key): Incident UUID.
- `user_id` (`uuid`, Nullable, FK → `users.id`): Affected user.
- `organization_id` (`uuid`, Nullable, FK → `organizations.id`): Tenant organization.
- `threat_type` (`text`, Required): Category: `'phishing'`, `'malicious_url'`, `'deepfake'`, `'impersonation'`, `'account_takeover'`, `'technical_threat'`, `'system_anomaly'`.
- `source_type` (`text`, Required): Channel origin: `'email'`, `'sms'`, `'social'`, `'url'`, `'image'`, `'audio'`, `'video'`, `'login'`, `'system'`.
- `risk_level` (`text`, Required): Risk tier stored in lowercase: `'safe'`, `'low'`, `'medium'`, `'high'`, `'critical'`.
- `risk_score` (`numeric`, Required): Score from 0 to 100.
- `explanation` (`text`, Required): Plain-English explanation.
- `status` (`incident_status`, Enum: `'open' | 'investigating' | 'resolved'`, Default `'open'`): Triage state.
- `resolved_by` (`uuid`, Nullable, FK → `users.id`): Admin who marked incident resolved.
- `resolved_at` (`timestamptz`, Nullable): Resolution timestamp.
- `created_at` (`timestamptz`, Default `NOW()`): Incident creation timestamp.

### 6.7 `incident_evidence`
Forensic payloads attached to an incident.
- `id` (`uuid`, Primary Key): Evidence UUID.
- `incident_id` (`uuid`, Required, FK → `incidents.id`): Parent incident.
- `evidence_type` (`text`, Required): Content type (e.g. `'raw_email'`, `'pcap_snippet'`, `'image_frame'`).
- `raw_payload` (`jsonb`, Nullable): Extracted JSON metadata.
- `file_url` (`text`, Nullable): Media or artifact URL.
- `metadata` (`jsonb`, Nullable): Forensic parameters.
- `created_at` (`timestamptz`, Default `NOW()`): Ingestion timestamp.

### 6.8 `detection_signals`
Granular indicators extracted by the AI/ML models.
- `id` (`uuid`, Primary Key): Signal UUID.
- `incident_id` (`uuid`, Required, FK → `incidents.id`): Parent incident.
- `signal_name` (`text`, Required): Indicator key (e.g., `'urgency_score'`, `'synthetic_prob'`).
- `signal_value` (`text`, Nullable): Extracted value.
- `weight` (`numeric`, Nullable): Feature importance weight (0.0 to 1.0).

### 6.9 `recommended_actions`
Prescriptive response actions generated for an incident.
- `id` (`uuid`, Primary Key): Action UUID.
- `incident_id` (`uuid`, Required, FK → `incidents.id`): Parent incident.
- `action_type` (`text`, Required): Action text description (e.g., "Quarantine email and block domain").
- `action_status` (`action_status`, Enum: `'pending' | 'taken' | 'dismissed'`, Default `'pending'`): Status.
- `created_at` (`timestamptz`, Default `NOW()`): Creation timestamp.

### 6.10 `mitre_mappings`
MITRE ATT&CK technique tags mapped to incidents.
- `id` (`uuid`, Primary Key): Mapping UUID.
- `incident_id` (`uuid`, Required, FK → `incidents.id`): Parent incident.
- `technique_id` (`text`, Required): Technique ID (e.g., `'T1566'`).
- `technique_name` (`text`, Required): Technique label (e.g., `'Phishing'`).

### 6.11 `guardian_links`
Protective links connecting a guardian to an at-risk dependent.
- `id` (`uuid`, Primary Key): Link UUID (also aliased as `link_id`).
- `guardian_user_id` (`uuid`, Required, FK → `users.id`): Guardian's user ID.
- `dependent_user_id` (`uuid`, Required, FK → `users.id`): Dependent's user ID.
- `status` (`text`, Required, Enum: `'pending' | 'active' | 'revoked'`, Default `'pending'`): State.
- `created_at` (`timestamptz`, Default `NOW()`): Request timestamp.
- *Constraint:* Unique composite index on `(guardian_user_id, dependent_user_id)`.

### 6.12 `audit_logs`
SOC audit log of system interactions and state changes.
- `id` (`uuid`, Primary Key): Audit log UUID.
- `user_id` (`uuid`, Required, FK → `users.id`): Actor performing action.
- `action` (`text`, Required): Action name (e.g., `'INCIDENT_RESOLVED'`, `'GUARDIAN_LINKED'`).
- `resource_type` (`text`, Required): Entity affected (`incident`, `action`, `user`).
- `resource_id` (`text`, Nullable): Target ID.
- `details` (`jsonb`, Nullable): Before/after delta or parameters.
- `ip_address` (`text`, Nullable): Request IP.
- `created_at` (`timestamptz`, Default `NOW()`): Timestamp.

---

## 7. Complete API Inventory

All Gateway routes are mounted under both `/api/v1` and `/api` (`services/backend/src/index.js:59-60`).

### 7.1 Module: Health & Readiness

#### 7.1.1 Service Liveness Check
- **Method & Path:** `GET /health` *(Aliases: `/api/health`, `/api/v1/health`)*
- **Purpose:** Verifies Node.js API Gateway liveness.
- **Auth Required:** None (Public).
- **Request:** Headers: None. Params: None. Body: None.
- **Success Response (`200 OK`):**
  ```json
  {
    "status": "ok",
    "service": "cyberguard-backend",
    "timestamp": "2026-09-28T10:00:00.000Z",
    "uptime": 142.35
  }
  ```
- **Error Responses:** None.

---

### 7.2 Module: Authentication & Profile

#### 7.2.1 Register New User
- **Method & Path:** `POST /api/v1/auth/signup`
- **Purpose:** Registers user and returns JWT token with profile.
- **Auth Required:** None (Rate-limited: 5 req / 15 min per IP).
- **Request Headers:** `Content-Type: application/json`
- **Request Body Schema:**
  ```typescript
  {
    email: string;            // Required, valid email string containing '@'
    password: string;         // Required, minimum 6 characters
    full_name: string;        // Required, non-empty string
    role?: 'individual' | 'employee' | 'admin'; // Optional, default: 'individual'
    organization_id?: string; // Optional, UUID string
  }
  ```
- **Success Response (`201 Created`):**
  ```json
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
      "email": "analyst@enterprise.com",
      "full_name": "Jane Doe",
      "role": "individual",
      "organization_id": null,
      "created_at": "2026-09-28T10:05:00.000Z"
    }
  }
  ```
- **Error Responses:**
  - `400 Bad Request`:
    ```json
    { "error": "INVALID_EMAIL", "message": "A valid email address is required" }
    ```
    ```json
    { "error": "WEAK_PASSWORD", "message": "Password must be at least 6 characters" }
    ```
    ```json
    { "error": "INVALID_NAME", "message": "Full name is required" }
    ```
  - `429 Too Many Requests`:
    ```json
    { "error": "RATE_LIMIT_EXCEEDED", "message": "Too many requests, please try again later." }
    ```

#### 7.2.2 User Login
- **Method & Path:** `POST /api/v1/auth/login`
- **Purpose:** Authenticates credentials and returns JWT bearer token.
- **Auth Required:** None (Rate-limited: 5 req / 15 min per IP).
- **Request Headers:** `Content-Type: application/json`
- **Request Body Schema:**
  ```typescript
  {
    email: string;    // Required
    password: string; // Required
  }
  ```
- **Success Response (`200 OK`):**
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
- **Error Responses:**
  - `400 Bad Request`:
    ```json
    { "error": "MISSING_CREDENTIALS", "message": "Email and password are required" }
    ```
  - `429 Too Many Requests`: Rate limit exceeded.

#### 7.2.3 Get Current User Profile
- **Method & Path:** `GET /api/v1/auth/me`
- **Purpose:** Returns authenticated user profile and session identity.
- **Auth Required:** Bearer JWT (`req.user`).
- **Request Headers:** `Authorization: Bearer <token>`
- **Request Body:** None.
- **Success Response (`200 OK`):**
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
- **Error Responses:**
  - `401 Unauthorized`:
    ```json
    { "error": "UNAUTHORIZED", "message": "Authentication token is missing" }
    ```
    ```json
    { "error": "TOKEN_EXPIRED", "message": "Authentication token has expired" }
    ```

---

### 7.3 Module: Threat Detection Checks

#### 7.3.1 Check Message (Phishing / Scam)
- **Method & Path:** `POST /api/v1/check/message`
- **Purpose:** Evaluates text for phishing, urgent credential lures, and adversarial prompt injections. Persists incident and emits real-time WebSocket alert.
- **Auth Required:** Bearer JWT (Rate-limited: 100 req / 15 min per IP).
- **Request Headers:** `Authorization: Bearer <token>`, `Content-Type: application/json`
- **Request Body Schema:**
  ```typescript
  {
    text: string;                             // Required, non-empty
    source_type: 'email' | 'sms' | 'social';  // Required
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "id": "e93a7d18-91b4-4b5c-b1d6-8430b8d72111",
    "risk_level": "High",
    "explanation": "High Risk: Message demands immediate credential verification under threat of suspension.",
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
- **Error Responses:**
  - `400 Bad Request`:
    ```json
    { "error": "INVALID_TEXT", "message": "Non-empty message text is required" }
    ```
    ```json
    { "error": "INVALID_SOURCE_TYPE", "message": "source_type must be one of: 'email', 'sms', 'social'" }
    ```
  - `502 Bad Gateway`:
    ```json
    { "error": "DETECTION_ENGINE_UNAVAILABLE", "message": "Detection engine unavailable" }
    ```

#### 7.3.2 Check URL
- **Method & Path:** `POST /api/v1/check/url`
- **Purpose:** Inspects domain URL for typosquatting, look-alike patterns, and suspicious TLDs.
- **Auth Required:** Bearer JWT (Rate-limited: 100 req / 15 min per IP).
- **Request Headers:** `Authorization: Bearer <token>`, `Content-Type: application/json`
- **Request Body Schema:**
  ```typescript
  {
    url: string; // Required, must start with 'http'
  }
  ```
- **Success Response (`200 OK`):**
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
- **Error Responses:**
  - `400 Bad Request`:
    ```json
    { "error": "INVALID_URL", "message": "A valid http/https URL string is required" }
    ```
  - `502 Bad Gateway`: Detection engine unavailable.

#### 7.3.3 Check Media (Deepfake Image / Audio)
- **Method & Path:** `POST /api/v1/check/media`
- **Purpose:** Inspects accessible media URL for synthetic manipulation or voice cloning.
- **Auth Required:** Bearer JWT (Rate-limited: 100 req / 15 min per IP).
- **Request Headers:** `Authorization: Bearer <token>`, `Content-Type: application/json`
- **Request Body Schema:**
  ```typescript
  {
    file_url: string;             // Required, publicly accessible URL string
    media_type: 'image' | 'audio'; // Required
  }
  ```
- **Success Response (`200 OK`):**
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
      "file_url": "https://storage.cyberguard.internal/uploads/sample.wav",
      "media_type": "audio",
      "synthetic_prob": 0.89,
      "spectral_anomaly_score": 0.74,
      "model_type": "asv_spoof_detector"
    }
  }
  ```
- **Error Responses:**
  - `400 Bad Request`:
    ```json
    { "error": "INVALID_FILE_URL", "message": "A valid file_url string is required" }
    ```
    ```json
    { "error": "INVALID_MEDIA_TYPE", "message": "media_type must be 'image' or 'audio'" }
    ```
  - `502 Bad Gateway`: Detection engine unavailable.

---

### 7.4 Module: Guard App Sensor Telemetry

#### 7.4.1 Ingest Login Event Telemetry
- **Method & Path:** `POST /api/v1/telemetry/login-event`
- **Purpose:** Ingests authentication telemetry from Guard App sensors. Persists raw `login_events` row and generates incident if anomalous.
- **Auth Required:** Bearer JWT.
- **Request Headers:** `Authorization: Bearer <token>`, `Content-Type: application/json`
- **Request Body Schema:**
  ```typescript
  {
    timestamp: string;          // Required, valid ISO 8601 string
    device_id: string;          // Required, device identifier
    failed_attempts: number;    // Required, integer >= 0
    location?: string;          // Optional string
    ip_address?: string;        // Optional string
    user_id?: string;           // Optional UUID (Only accepted for 'admin' role)
  }
  ```
- **Success Response (`201 Created`):**
  ```json
  {
    "status": "recorded",
    "anomaly_detected": true,
    "risk_level": "High",
    "risk_score": 85,
    "explanation": "Multiple consecutive failed logins from an unrecognized device and geographical anomaly.",
    "recommended_actions": [
      "Terminate active sessions and force password reset for compromised user account.",
      "Enforce multi-factor authentication (MFA)."
    ],
    "signals": {
      "impossible_travel": true,
      "failed_count": 4,
      "isolation_forest_score": -0.76
    },
    "incident_id": "b182f4c9-63a1-4e7a-9c3f-8419b21a8d02"
  }
  ```
- **Error Responses:**
  - `400 Bad Request`: Missing or invalid fields (`timestamp`, `device_id`, or `failed_attempts`).
  - `403 Forbidden`: Admin attempts to report telemetry for user outside their organization.

#### 7.4.2 Ingest System Event Telemetry
- **Method & Path:** `POST /api/v1/telemetry/system-event`
- **Purpose:** Ingests workstation network flow or process behavior anomalies from Guard App.
- **Auth Required:** Bearer JWT.
- **Request Headers:** `Authorization: Bearer <token>`, `Content-Type: application/json`
- **Request Body Schema:**
  ```typescript
  {
    timestamp: string;          // Required, valid ISO 8601 string
    event_type: string;         // Required (e.g. 'network_spike', 'network_flow_telemetry')
    details: Record<string, any>; // Required JSON object of flow/process metrics
    device_id?: string;         // Optional string
    user_id?: string;           // Optional UUID (Admin only)
  }
  ```
- **Success Response (`201 Created`):**
  ```json
  {
    "status": "recorded",
    "anomaly_detected": true,
    "risk_level": "Medium",
    "risk_score": 58,
    "explanation": "Sudden outbound traffic surge to an unknown external IP address unaccompanied by recognized application processes.",
    "signals": {
      "bytes_transferred": 104857600,
      "ip_reputation_score": 45,
      "unrecognized_process": true
    },
    "incident_id": "a9284f11-73c2-4a9b-98b4-9218c3b281f9"
  }
  ```

---

### 7.5 Module: Incident Triage & Management

#### 7.5.1 List Incidents (Paginated & Filtered)
- **Method & Path:** `GET /api/v1/incidents`
- **Purpose:** Retrieves paginated incident list scoped by tenant. Non-admin gets their own incidents; Admin gets all org incidents.
- **Auth Required:** Bearer JWT.
- **Query Parameters:**
  - `limit` (integer, default `25`, max `100`): Page size.
  - `offset` (integer, default `0`): Skip count.
  - `risk_level` (string, optional): Filter by `safe`, `low`, `medium`, `high`, `critical`.
  - `status` (string, optional): Filter by `open`, `investigating`, `resolved`.
  - `threat_type` / `category` (string, optional): Filter by `phishing`, `malicious_url`, `deepfake`, `account_takeover`, `technical_threat`, etc.
- **Success Response (`200 OK`):**
  ```json
  {
    "total": 42,
    "limit": 25,
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
    "data": [ /* Identical array to incidents for compatibility */ ]
  }
  ```

#### 7.5.2 Get Incident Details
- **Method & Path:** `GET /api/v1/incidents/:id`
- **Purpose:** Retrieves complete incident record including signals, forensic evidence, actions, and MITRE mapping.
- **Auth Required:** Bearer JWT (Strictly tenant/user-scoped).
- **Path Parameters:** `id` (UUID format required).
- **Success Response (`200 OK`):**
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
    ],
    "detection_signals": [
      {
        "signal_name": "urgency_score",
        "signal_value": "0.92",
        "weight": 0.8
      }
    ],
    "evidence": []
  }
  ```
- **Error Responses:**
  - `404 Not Found`: Non-existent ID, malformed UUID, or cross-tenant incident (`{ "error": "NOT_FOUND", "message": "Incident not found" }`).

#### 7.5.3 Update Incident Status
- **Method & Path:** `PATCH /api/v1/incidents/:id`
- **Purpose:** Updates incident lifecycle state. Automatically records `resolved_by = req.user.id` and `resolved_at = NOW()` when status is `'resolved'`.
- **Auth Required:** Bearer JWT with **`role: 'admin'`** strictly required.
- **Request Headers:** `Authorization: Bearer <token>`, `Content-Type: application/json`
- **Request Body Schema:**
  ```typescript
  {
    status: 'open' | 'investigating' | 'resolved'; // Required
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "id": "f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
    "status": "resolved",
    "resolved_by": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "updated_at": "2026-09-28T10:15:00.000Z"
  }
  ```
- **Error Responses:**
  - `400 Bad Request`: Status not in `['open', 'investigating', 'resolved']`.
  - `403 Forbidden`: Caller lacks `admin` role (`{ "error": "FORBIDDEN", "message": "Forbidden: role 'individual' lacks sufficient permissions..." }`).
  - `404 Not Found`: Incident not found or belongs to another organization.

---

### 7.6 Module: Remediation Actions

#### 7.6.1 Update Recommended Action Status
- **Method & Path:** `PATCH /api/v1/actions/:id`
- **Purpose:** Marks an incident remediation step as taken or dismissed. Scoped to the user's accessible incidents.
- **Auth Required:** Bearer JWT (All authenticated roles).
- **Request Headers:** `Authorization: Bearer <token>`, `Content-Type: application/json`
- **Request Body Schema:**
  ```typescript
  {
    action_status: 'taken' | 'dismissed'; // Required
  }
  ```
- **Success Response (`200 OK`):**
  ```json
  {
    "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
    "incident_id": "f72a19b4-3c81-49e0-81f3-241b2c1a89d2",
    "action_type": "Quarantine email and block sender domain.",
    "action_status": "taken",
    "created_at": "2026-09-28T08:10:00.000Z"
  }
  ```
- **Error Responses:**
  - `400 Bad Request`: `action_status` not `'taken'` or `'dismissed'`.
  - `404 Not Found`: Action ID invalid, not found, or linked to another tenant's incident.

---

### 7.7 Module: Guardian Mode

#### 7.7.1 Initiate Guardian Link Request
- **Method & Path:** `POST /api/v1/guardian/link`
- **Purpose:** Initiates a pending link request. Caller must be either `guardian_user_id` or `dependent_user_id`.
- **Auth Required:** Bearer JWT.
- **Request Headers:** `Authorization: Bearer <token>`, `Content-Type: application/json`
- **Request Body Schema:**
  ```typescript
  {
    guardian_user_id: string;  // Required UUID
    dependent_user_id: string; // Required UUID (cannot equal guardian_user_id)
  }
  ```
- **Success Response (`201 Created`):**
  ```json
  {
    "link_id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
    "status": "pending",
    "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
    "created_at": "2026-09-28T10:20:00.000Z"
  }
  ```
- **Error Responses:**
  - `400 Bad Request`: Missing IDs or self-linking (`INVALID_LINK`).
  - `403 Forbidden`: Authenticated user matches neither guardian nor dependent.

#### 7.7.2 Accept Guardian Link Request
- **Method & Path:** `POST /api/v1/guardian/link/:id/accept`
- **Purpose:** Dependent user accepts link, transitioning status from `pending` to `active`.
- **Auth Required:** Bearer JWT (Caller must strictly be `dependent_user_id`).
- **Request Body:** None.
- **Success Response (`200 OK`):**
  ```json
  {
    "link_id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
    "status": "active",
    "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
    "created_at": "2026-09-28T10:20:00.000Z"
  }
  ```
- **Error Responses:**
  - `400 Bad Request`: Link is not in `pending` status.
  - `404 Not Found`: Link not found or caller is not the dependent.

#### 7.7.3 Decline or Revoke Guardian Link
- **Method & Path:** `POST /api/v1/guardian/link/:id/decline` *(Alias: `POST /api/v1/guardian/link/:id/revoke`)*
- **Purpose:** Dependent declines pending request, setting status to `revoked`.
- **Auth Required:** Bearer JWT (Dependent user only).
- **Request Body:** None.
- **Success Response (`200 OK`):**
  ```json
  {
    "link_id": "9b1c2d3e-4f5a-6b7c-8d9e-0f1a2b3c4d5e",
    "status": "revoked",
    "guardian_user_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
    "dependent_user_id": "c9d8e7f6-a5b4-3c2d-1e0f-9a8b7c6d5e4f",
    "created_at": "2026-09-28T10:20:00.000Z"
  }
  ```

#### 7.7.4 Get Dependent High-Priority Alerts
- **Method & Path:** `GET /api/v1/guardian/alerts`
- **Purpose:** Retrieves High and Critical incidents for all active dependents of the caller.
- **Auth Required:** Bearer JWT.
- **Request Body:** None.
- **Success Response (`200 OK`):**
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

### 7.8 Module: Command Dashboard Analytics

#### 7.8.1 Overview Metric Cards
- **Method & Path:** `GET /api/v1/analytics/overview`
- **Purpose:** Aggregate statistics for top-of-dashboard KPI cards and donut charts.
- **Auth Required:** Bearer JWT (Scoped to tenant for admins, personal for individuals).
- **Success Response (`200 OK`):**
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

#### 7.8.2 Incident Trendline Over Time
- **Method & Path:** `GET /api/v1/analytics/trends`
- **Purpose:** Time-series daily incident volume for Recharts line/area charts.
- **Auth Required:** Bearer JWT (Scoped).
- **Success Response (`200 OK`):**
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

#### 7.8.3 MITRE ATT&CK Matrix Breakdown
- **Method & Path:** `GET /api/v1/analytics/mitre`
- **Purpose:** Technique frequency distribution for MITRE heatmaps and bar charts.
- **Auth Required:** Bearer JWT (Scoped).
- **Success Response (`200 OK`):**
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

## 8. Global API Conventions

### 8.1 Response Envelopes & Inconsistencies
The backend does **not** employ a universal outer envelope (e.g. `{ data, status, error }`). Instead:
- Paginated listing (`GET /incidents`): Returns `{ total, limit, offset, incidents: [...], data: [...] }`.
- Detailed single resources (`GET /incidents/:id`, `PATCH /actions/:id`): Return the flat entity object directly.
- Guardian alerts and Analytics arrays (`GET /guardian/alerts`, `GET /analytics/trends`, `GET /analytics/mitre`): Return raw JSON arrays `[...]`.
- Threat check endpoints (`POST /check/*`): Return flat analysis objects with `{ id, risk_level, explanation, recommended_actions, signals }`.

### 8.2 Error Responses
Standard error payload returned by controllers and middlewares:
```json
{
  "error": "STRING_ERROR_CODE",
  "message": "Human-readable explanation of error condition"
}
```
Standard HTTP status codes utilized:
- `400 Bad Request`: Payload validation failures or missing required parameters.
- `401 Unauthorized`: Missing, expired, or invalid JWT Bearer token.
- `403 Forbidden`: Insufficient role or cross-organization violation.
- `404 Not Found`: Resource does not exist or fails tenant scoping.
- `429 Too Many Requests`: Rate limit exceeded.
- `500 Internal Server Error`: Unhandled database or runtime exception.
- `502 Bad Gateway`: Python ML microservice unreachable or returned error.

### 8.3 Casing Conventions
- **Database & JSON Request/Response Keys:** Exclusively `snake_case` (e.g., `user_id`, `risk_level`, `failed_attempts`, `recommended_actions`).
- **Risk Level Enums:**
  - Database & `GET /incidents` responses: Lowercase (`'safe'`, `'low'`, `'medium'`, `'high'`, `'critical'`).
  - FastAPI & `POST /check/*` responses: TitleCase (`'Safe'`, `'Low'`, `'Medium'`, `'High'`, `'Critical'`).
  - Frontend must normalize casing via `.toLowerCase()` when rendering badges or running conditionals!

### 8.4 File Upload Handling
The backend currently does **not** accept `multipart/form-data`. Endpoints expecting media files (`POST /api/v1/check/media`) require a JSON payload containing an already-hosted `file_url` string.

### 8.5 Rate Limiting Rules
Implemented via `express-rate-limit` using client IP address:
- **Authentication Limiter:** 5 requests per 15 minutes per IP (`/auth/login`, `/auth/signup`).
- **Check Limiter:** 100 requests per 15 minutes per IP (`/check/*`).
- **General Limiter:** 300 requests per 15 minutes per IP (`/incidents`, `/guardian`, `/analytics`, `/telemetry`, `/actions`).
- Standard headers returned: `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`.

### 8.6 CORS Configuration
- In `services/backend/src/index.js:28`, CORS is enabled globally via `app.use(cors())`, allowing all origins (`*`) in development.
- In `services/backend/src/config/socket.js:17-20`, Socket.io allows `origin: '*'` and methods `['GET', 'POST']`.

---

## 9. Real-Time WebSocket Architecture

### 9.1 Connection & Handshake
- **Protocol:** Socket.io v4 (`http://localhost:5000`).
- **Handshake Authentication:** Must include Bearer token:
  ```javascript
  import { io } from 'socket.io-client';

  const socket = io('http://localhost:5000', {
    auth: { token: userJwtToken }
  });
  ```
- Handshake middleware verifies token against `JWT_SECRET` and populates `socket.user = { id, role, organization_id, email }`.

### 9.2 Room Multiplexing
Upon successful connection, the server automatically joins the socket to appropriate rooms (`socket.js:51-64`):
1. **User Personal Room:** `user:<user_id>` (receives personal threat checks and account takeover alerts).
2. **Guardian Room:** `guardian:<user_id>` (receives dependent incident alerts).
3. **Organization Room:** `org:<organization_id>` (receives all enterprise threat alerts if user is affiliated with an org).

### 9.3 Client-Emitted Events
- **`subscribe`:** Allows client to explicitly join rooms:
  ```javascript
  socket.emit('subscribe', { room: `user:${userId}` });
  ```

### 9.4 Server-Emitted Events
- **Event Name:** `'incident:new'`
- **Trigger:** Dispatched whenever an incident is committed via `persistDetectionIncident` (`services/backend/src/services/incidentService.js:125-159`).
- **Payload Shape:**
  ```typescript
  interface IncidentNewSocketPayload {
    id: string;               // Incident UUID
    threat_type: string;      // e.g. 'phishing', 'deepfake', 'account_takeover'
    source_type: string;      // e.g. 'email', 'sms', 'login', 'url'
    risk_level: string;       // e.g. 'high', 'critical'
    risk_score: number;       // e.g. 85
    explanation: string;      // Plain-English explanation
    status: 'open';           // Newly created status
    created_at: string;       // ISO timestamp
    recommended_actions: string[]; // Prescriptive steps
    signals: Record<string, any>;  // Technical feature map
  }
  ```

---

## 10. Third-Party Integrations & External Services

| Service / Provider | Purpose | Status in Backend | Frontend Action Required |
|---|---|---|---|
| **Supabase / PostgreSQL** | Relational data persistence, foreign keys, RLS | Production-ready (direct `pg.Pool` connection string) | None (Backend handles all database queries) |
| **Python FastAPI Engine** | AI inference, ML anomaly scoring, prompt injection defense | Fully operational (`mlClient.js`) | None (Proxied transparently through Gateway) |
| **Firebase Cloud Messaging (FCM)** | Mobile push alerts for high/critical threats | Configured in `.env.example` (`FCM_SERVER_KEY`); dispatcher not yet bound in Express controllers | Mobile app should initialize FCM/Expo push token and request push permissions |
| **OpenAI / Groq API** | Optional few-shot LLM reasoning for phishing messages | Optional fallback in `ml-service` | None |
| **Cloud Storage (S3 / Supabase Storage)** | Hosting audio/image files for deepfake analysis | No upload endpoint in backend | Frontend must upload media to public CDN/storage before calling `POST /check/media` with `file_url` |

---

## 11. Business Logic Workflows & State Diagrams

### 11.1 Threat Detection & Auto-Incident Workflow

```mermaid
sequenceDiagram
    autonumber
    actor User as Frontend Client (Web / Mobile)
    participant GW as API Gateway (Node/Express)
    participant ML as AI/ML Microservice (FastAPI)
    participant DB as PostgreSQL Database
    participant WS as Socket.io Server
    actor Guardian as Linked Guardian

    User->>GW: POST /api/v1/check/message (Bearer JWT + Text)
    GW->>GW: Verify JWT & Apply Rate Limit (100/15min)
    GW->>ML: POST /internal/analyze/message
    ML->>ML: Sanitize Input & Run Heuristics / LLM
    ML-->>GW: Return UnifiedAnalysisResponse
    GW->>DB: BEGIN Transaction
    GW->>DB: INSERT into incidents
    GW->>DB: INSERT into mitre_mappings
    GW->>DB: INSERT into detection_signals
    GW->>DB: INSERT into recommended_actions
    GW->>DB: COMMIT Transaction
    GW->>WS: Emit 'incident:new' to user & org rooms
    opt If Dependent User Has Active Guardians
        GW->>WS: Emit 'incident:new' to guardian:<guardian_id>
        WS-->>Guardian: Push Real-Time Incident Notification
    end
    GW-->>User: Return 200 OK (id, risk_level, explanation, actions)
```

---

### 11.2 Guardian Mode Two-Step Handshake Workflow

```mermaid
stateDiagram-v2
    [*] --> Pending: Guardian calls POST /guardian/link
    Pending --> Active: Dependent calls POST /guardian/link/:id/accept
    Pending --> Revoked: Dependent calls POST /guardian/link/:id/decline
    Active --> [*]: Dependents' High/Critical Incidents Emitted to Guardian
    Revoked --> [*]: Link Terminated
```

---

### 11.3 Incident Triage Lifecycle (Admin SOC Flow)

```mermaid
stateDiagram-v2
    [*] --> Open: Created by Check or Telemetry
    Open --> Investigating: Admin calls PATCH /incidents/:id (status: 'investigating')
    Investigating --> Resolved: Admin calls PATCH /incidents/:id (status: 'resolved')
    Open --> Resolved: Direct resolution by Admin
    Resolved --> [*]: resolved_by and resolved_at set in DB
```
