# Backend Development Branch Audit Report (`origin/dev`) — Audit #3

**Date:** 2026-10-04  
**Auditor:** Pair Programming Assistant (Antigravity AI)  
**Target Branch:** `origin/dev` (commit `020a2af`)  
**Previous Audit Baseline:** `BACKEND_DEV_AUDIT_2.md` (commit `ee397be`, 2026-10-03)  
**Comparison Baseline:** `feature/frontend-dashboard` (`apps/web/src/services/*`, `types.ts`, `API_REFERENCE.md`)  
**Scope:** Read-only architectural and code-level verification of all commits, pull requests, background engines, endpoints, and schema changes landed on `origin/dev` since Audit #2.

---

## 1. What's New Since `BACKEND_DEV_AUDIT_2.md` (Commit Summary)

Fetched via `git log origin/dev --oneline -20 --format="%h | %an | %ad | %s" --date=short`:

| Commit Hash | Author | Commit Date | Subject / Description | PR & Feature Context |
|---|---|---|---|---|
| `020a2af` | Abhijit | 2026-10-04 | Merge pull request #31 from teamvisioncraft875-netizen/feature/engines_training_validation | **PR #31**: ML Engines Validation & Malware Engine |
| `e76c632` | sudhandu sekhar | 2026-10-04 | feat(ml): complete phishing and malicious URL validation | Supervised classifiers & EMBER static PE analyzer |
| `6f361c1` | Abhijit | 2026-10-04 | Merge pull request #30 from teamvisioncraft875-netizen/feature/firewall-integration | **PR #30**: Host Firewall Integration |
| `57d7d64` | Subha Sankar Sahu | 2026-10-04 | feat: add package.json configuration for backend service | Dependency locking & scripts |
| `553fc15` | Subha Sankar Sahu | 2026-10-04 | test: comprehensive firewall integration end-to-end + final audit (PRODUCTION READY) | 871-line end-to-end integration test suite |
| `cd6bc40` | Subha Sankar Sahu | 2026-10-04 | feat: comprehensive firewall error tracking and audit logging | Granular failure types & audit log coverage |
| `6ccd1e5` | Subha Sankar Sahu | 2026-10-04 | feat: bidirectional firewall rule deletion (admin revoke + agent cleanup) | Two-phase revocation lifecycle |
| `aee5595` | Subha Sankar Sahu | 2026-10-03 | feat: protected targets endpoint for agent sync | Live safe-list distribution for agents |
| `2a7ded0` | Subha Sankar Sahu | 2026-10-03 | feat: manual firewall command creation for admin testing/remediation | Direct manual agent command dispatch |
| `c0de3f4` | Subha Sankar Sahu | 2026-10-03 | fix: agent execution results → firewall rules table (dashboard visibility) | Result sync from agent command queue |
| `a4eb162` | Subha Sankar Sahu | 2026-10-03 | fix: wire policy engine → agent commands (response_action → firewall execution) | Policy Engine auto-containment translation |
| `8bbd7c3` | Subha Sankar Sahu | 2026-10-03 | feat: firewall integration agent - privilege elevation, execution, rate limiting, cross-platform support | Enterprise Agent OS firewall executor |
| `6b7178a` | Subha Sankar Sahu | 2026-10-03 | feat: firewall integration backend - rule tracking, validation, audit logging | Rules table, validation logic, controllers |
| `967d86f` | Abhijit | 2026-10-03 | Merge pull request #29 from teamvisioncraft875-netizen/feature/deepfake_media_engine | **PR #29**: Supervised Deepfake Engine |
| `df1ed16` | sudhandu sekhar | 2026-10-03 | feat(ml-service): add supervised visual deepfake detection engine, DFDC audit, and test suite | ResNet/ViT classifier & DFDC audit |
| `6bf5e73` | Abhijit | 2026-10-03 | Merge pull request #27 from teamvisioncraft875-netizen/feature/guard-app-v1-skeleton | **PR #27**: Enterprise Agent Foundation |
| `7b05af5` | Abhijit | 2026-10-03 | Merge pull request #26 from teamvisioncraft875-netizen/feature/background-scheduler | **PR #26**: Background Scheduler Cron |
| `93456d9` | Subha Sankar Sahu | 2026-10-03 | fix: hardening agent phase B - thread safety, timeouts, validation, exception handling, permissions | Agent concurrency & security hardening |
| `65dcbe5` | Subha Sankar Sahu | 2026-10-03 | feat: enterprise agent v1 backend foundation - enrollment, credentials, heartbeat, command queue | Agent enrollment & heartbeat engine |
| `bbb4c63` | Subha Sankar Sahu | 2026-10-03 | fix(scheduler): ensure isRunning checks and graceful drain on stopScheduler | Scheduler lifecycle & drain safety |
| `8e0fc8a` | Subha Sankar Sahu | 2026-10-03 | feat: background scheduler auto-executes due response actions every 60s with per-org circuit breaker (max 10/hour) | Core 60s node-cron scheduler loop |

---

## 2. Status of Previously-Flagged Issues from `BACKEND_DEV_AUDIT_2.md`

| Previously-Flagged Issue | Now Fixed? | Implementation Evidence (File & Line Numbers) | Exact Technical Details |
|---|---|---|---|
| **1. Background Scheduler merged into `dev`?** | **YES** | [`services/backend/src/services/schedulerService.js:1-238`](../../services/backend/src/services/schedulerService.js#L1-L238)<br>[`services/backend/src/index.js:101,107,113`](../../services/backend/src/index.js#L101)<br>Merged via PR #26 (commit `7b05af5`) | **Merged & Active:** Starts on boot via `schedulerService.startScheduler('* * * * *')`. Automatically scans `response_actions` where `status IN ('scheduled', 'approved')` and `scheduled_at <= NOW()`. Includes a strict per-organization circuit breaker (maximum 10 executions/hour).<br>**Frontend Impact:** Does **NOT** expose, modify, or break any endpoint the frontend calls. Operates entirely as an internal backend cron. |
| **2. Refresh Token Rotation on `POST /auth/refresh`?** | **NO** | [`services/backend/src/controllers/authController.js:336-339`](../../services/backend/src/controllers/authController.js#L336-L339)<br>[`services/backend/src/models/RefreshToken.js:100-145`](../../services/backend/src/models/RefreshToken.js#L100-L145) | **Still Reuses 7-Day Token:** When a valid refresh token is submitted, the controller issues a new 15-minute access token and returns `{ token: accessToken, accessToken }`. It does **not** invalidate the submitted refresh token, nor does it generate or return a rolling refresh token. The original refresh token remains valid for 7 days until expiry or explicit logout. |
| **3. Risk-Level Normalization in `GET /guardian/alerts`?** | **NO** | [`services/backend/src/controllers/guardianController.js:382`](../../services/backend/src/controllers/guardianController.js#L382)<br>[`services/backend/src/controllers/checkController.js:68,126,211`](../../services/backend/src/controllers/checkController.js#L68)<br>[`services/backend/src/controllers/incidentController.js:89-108`](../../services/backend/src/controllers/incidentController.js#L89-L108) | **Inconsistency Remains:** While `POST /check/*` and `GET /incidents` strictly return lowercase (`"safe"`, `"low"`, `"medium"`, `"high"`, `"critical"`), `guardianController.js:382` explicitly converts `risk_level` to TitleCase: `row.risk_level ? row.risk_level.charAt(0).toUpperCase() + row.risk_level.slice(1) : 'High'`. The frontend must continue normalizing with `.toLowerCase()`. |

---

## 3. Audit of Newly Merged Features

Across PRs #26, #27, #30, and #31, two major backend feature subsystems and one ML enhancement landed on `origin/dev`. Below is the complete specification for each.

---

### Feature 1: Host-Level Firewall Integration System (PR #30)
**Code Location:** [`services/backend/src/controllers/firewallController.js`](../../services/backend/src/controllers/firewallController.js), [`services/backend/src/services/firewallService.js`](../../services/backend/src/services/firewallService.js), [`services/backend/src/models/FirewallRule.js`](../../services/backend/src/models/FirewallRule.js), [`services/enterprise-agent/firewall_executor.py`](../../services/enterprise-agent/firewall_executor.py).  
**Purpose:** Provides centralized admin control, validation, and automated execution of OS-level firewall blocking rules (Windows Defender Firewall, Linux `ufw`, `firewalld`, `iptables`) across enrolled workstation enterprise agents.

| Endpoint | Method | Auth / Role | Description |
|---|---|---|---|
| `/api/v1/admin/firewall-rules` | `GET` | Bearer JWT (`admin`) | List organization-scoped firewall rules with status/type filters & pagination |
| `/api/v1/admin/firewall-rules/validate` | `POST` | Bearer JWT (`admin`) | Pre-validates IP/domain syntax and verifies non-collision with protected lists |
| `/api/v1/admin/firewall-rules` | `POST` | Bearer JWT (`admin`) | Creates a firewall containment rule in `pending` status |
| `/api/v1/admin/firewall-rules/:rule_id` | `DELETE` | Bearer JWT (`admin`) | Revokes rule (marks `pending_delete` & queues agent OS rule removal) |
| `/api/v1/admin/agents/:agent_id/firewall-commands` | `POST` | Bearer JWT (`admin`) | Manually queues an immediate firewall command (`block_ip` / `block_domain`) to an online agent |
| `/api/v1/agents/:device_id/protected-targets` | `GET` | Public / Rate-limited | Live download of protected IP ranges, loopback, and DNS safe-targets |

#### Request & Response Schemas for Feature 1

#### 1. `GET /api/v1/admin/firewall-rules`
- **Query Parameters:** `agent_id` (UUID), `status` (`'pending'|'active'|'failed'|'pending_delete'|'deleted'`), `rule_type` (`'block_ip'|'block_domain'`), `limit` (default 50, max 100), `offset` (default 0).
- **Response (`200 OK`):**
  ```json
  {
    "total": 1,
    "limit": 50,
    "offset": 0,
    "rules": [
      {
        "id": "a57bb816-0158-45ec-977d-78ea0e80a524",
        "agent_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
        "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
        "rule_type": "block_ip",
        "target_ip": "203.0.113.42",
        "target_domain": null,
        "target": "203.0.113.42",
        "agent_name": "DESKTOP-SEC-01",
        "rule_id_local": "CG_FW_BLOCK_203_0_113_42",
        "status": "active",
        "created_by_id": "11111111-2222-3333-4444-555555555555",
        "created_by": "admin@enterprise.com",
        "source_command_id": "cde38f96-295f-4956-b18e-5e1afba2265b",
        "source": "manual",
        "created_at": "2026-10-04T08:00:00.000Z",
        "expires_at": null,
        "deleted_at": null,
        "result": { "os_rule_created": true, "platform": "linux" }
      }
    ]
  }
  ```

#### 2. `POST /api/v1/admin/firewall-rules/validate`
- **Request Body:**
  ```json
  {
    "rule_type": "block_ip",
    "target_data": {
      "ip_address": "203.0.113.42"
    }
  }
  ```
  *(For domain: `rule_type: "block_domain"`, `target_data: { "domain": "malicious.com" }`)*
- **Response (`200 OK` - Valid Target):**
  ```json
  {
    "valid": true,
    "error_if_invalid": null,
    "error": null,
    "target_ip": "203.0.113.42",
    "target_domain": null
  }
  ```
- **Response (`200 OK` - Invalid / Protected Target):**
  ```json
  {
    "valid": false,
    "error_if_invalid": "Target IP 127.0.0.1 is in protected list and cannot be blocked",
    "error": "Target IP 127.0.0.1 is in protected list and cannot be blocked",
    "target_ip": null,
    "target_domain": null
  }
  ```

#### 3. `POST /api/v1/admin/firewall-rules`
- **Request Body:**
  ```json
  {
    "agent_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "rule_type": "block_ip",
    "target_data": {
      "ip_address": "203.0.113.42"
    }
  }
  ```
- **Response (`201 Created`):**
  ```json
  {
    "success": true,
    "rule_id": "a57bb816-0158-45ec-977d-78ea0e80a524",
    "status": "pending",
    "rule": {
      "id": "a57bb816-0158-45ec-977d-78ea0e80a524",
      "agent_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
      "rule_type": "block_ip",
      "target_ip": "203.0.113.42",
      "target_domain": null,
      "status": "pending",
      "created_at": "2026-10-04T08:00:00.000Z"
    },
    "validation_result": {
      "valid": true,
      "target_ip": "203.0.113.42"
    }
  }
  ```

#### 4. `DELETE /api/v1/admin/firewall-rules/:rule_id`
- **Response (`200 OK`):**
  ```json
  {
    "deleted": true,
    "rule_id": "a57bb816-0158-45ec-977d-78ea0e80a524",
    "status": "deletion_pending",
    "agent_notified": true,
    "command_id": "cde38f96-295f-4956-b18e-5e1afba2265b"
  }
  ```

#### 5. `POST /api/v1/admin/agents/:agent_id/firewall-commands`
- **Request Body:**
  ```json
  {
    "command_type": "block_ip",
    "target_data": {
      "ip_address": "203.0.113.42"
    },
    "reason": "Suspicious C2 beaconing observed"
  }
  ```
- **Response (`201 Created`):**
  ```json
  {
    "success": true,
    "command_id": "cde38f96-295f-4956-b18e-5e1afba2265b",
    "status": "pending",
    "agent_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "command": {
      "id": "cde38f96-295f-4956-b18e-5e1afba2265b",
      "device_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
      "command_type": "block_ip",
      "target_data": { "ip_address": "203.0.113.42" },
      "status": "pending",
      "can_execute": true,
      "created_at": "2026-10-04T08:00:00.000Z"
    }
  }
  ```

#### 6. `GET /api/v1/agents/:device_id/protected-targets`
- **Response (`200 OK`):**
  ```json
  {
    "protected_ips": ["127.0.0.1", "0.0.0.0", "::1", "::", "8.8.8.8", "1.1.1.1"],
    "protected_ip_ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"],
    "protected_domains": ["localhost", "cyberguard.local"]
  }
  ```

- **Impact on Existing Endpoints:**
  - `POST /admin/actions/:id/execute` ([`executionService.js:261-292`](../../services/backend/src/services/executionService.js#L261-L292)): When approving or executing an action with `action_type IN ('block_ip', 'block_domain', 'temporary_block_ip')`, the execution engine now automatically resolves the target device and enqueues an agent command, returning `agent_command_id` and `target_device_id` in the execution result.
- **Frontend Relevance:**
  - **Existing Pages:** The **Incidents Page** action triggers can now show whether an action translated to an enrolled host firewall command.
  - **New Feature Area:** Full administrative rule inspection and manual command dispatch represents a **new admin area** ("Firewall & Containment" or "Endpoint Protection") rather than fitting within standard individual dashboard triage.

---

### Feature 2: Enterprise Agent Infrastructure & Enrollment (PR #26 & PR #27)
**Code Location:** [`services/backend/src/controllers/agentController.js`](../../services/backend/src/controllers/agentController.js), [`services/backend/src/services/agentService.js`](../../services/backend/src/services/agentService.js), [`services/backend/src/models/Agent.js`](../../services/backend/src/models/Agent.js), [`services/enterprise-agent/`](../../services/enterprise-agent).  
**Purpose:** Provides complete device enrollment tokens, agent credentials, periodic heartbeats, command queue polling, and command result synchronization for enterprise workstation agents.

| Endpoint | Method | Auth / Role | Description |
|---|---|---|---|
| `/api/v1/admin/agents/tokens` | `POST` | Bearer JWT (`admin`) | Issues a 24-hour single-use enrollment token for device provisioning |
| `/api/v1/agents/enroll` | `POST` | Enrollment Token (Body) | Device handshake exchanging token for permanent `credential_id` & `credential_secret` |
| `/api/v1/agents/:device_id/heartbeat` | `POST` | Agent Credentials (Header/Body) | Periodic 30s heartbeat updating online status, agent version, connection count |
| `/api/v1/agents/:device_id/commands` | `GET` | Agent Credentials (Header/Body) | Polls queued executable commands and live protected targets list |
| `/api/v1/agents/:device_id/commands/:command_id/result` | `POST` | Agent Credentials (Header/Body) | Reports command success/failure, stdout/stderr, and synchronizes firewall rules |
| `/api/v1/agents/:device_id/status` | `GET` | Optional JWT or Open | Returns device hostname, platform, OS, status (`online`/`offline`/`disabled`), heartbeat age |

#### Request & Response Schemas for Feature 2

#### 1. `POST /api/v1/admin/agents/tokens`
- **Request Body:**
  ```json
  {
    "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
    "valid_for_hours": 24
  }
  ```
- **Response (`201 Created`):**
  ```json
  {
    "token": "eyJhbGciOi...",
    "expires_at": "2026-10-05T08:00:00.000Z",
    "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca"
  }
  ```

#### 2. `POST /api/v1/agents/enroll`
- **Request Body:**
  ```json
  {
    "enrollment_token": "eyJhbGciOi...",
    "hostname": "WORKSTATION-CORP-42",
    "os": "Ubuntu 22.04 LTS",
    "platform": "linux",
    "linked_user_id": null,
    "agent_version": "1.0.0"
  }
  ```
- **Response (`201 Created`):**
  ```json
  {
    "device_id": "3b07b2e1-81ad-496c-b0fa-80a72ba92d8e",
    "credential_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "credential_secret": "sec_7f9a8b1c2d3e4f5a6b7c8d9e0f1a2b3c",
    "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca"
  }
  ```

#### 3. `POST /api/v1/agents/:device_id/heartbeat`
- **Headers / Body:** `credential_id` (string), `credential_secret` (string), `agent_version` (string), `network_connections_count` (integer).
- **Response (`200 OK`):**
  ```json
  {
    "status": "online",
    "next_heartbeat_in_seconds": 30,
    "commands_pending": 0
  }
  ```

#### 4. `GET /api/v1/agents/:device_id/commands`
- **Query / Headers:** `credential_id`, `credential_secret`.
- **Response (`200 OK`):**
  ```json
  {
    "commands": [
      {
        "id": "cde38f96-295f-4956-b18e-5e1afba2265b",
        "command_type": "block_ip",
        "target_data": { "ip_address": "203.0.113.42" },
        "can_execute": true,
        "created_at": "2026-10-04T08:00:00.000Z"
      }
    ],
    "protected_targets": {
      "protected_ips": ["127.0.0.1", "0.0.0.0", "::1"],
      "protected_domains": ["localhost"]
    }
  }
  ```

#### 5. `POST /api/v1/agents/:device_id/commands/:command_id/result`
- **Request Body:**
  ```json
  {
    "credential_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "credential_secret": "sec_7f9a8b1c2d3e4f5a6b7c8d9e0f1a2b3c",
    "status": "completed",
    "result": {
      "success": true,
      "rule_id_local": "CG_FW_BLOCK_203_0_113_42",
      "stdout": "Rule added successfully",
      "stderr": ""
    }
  }
  ```
  *(Allowed `status` values: `'completed'`, `'failed'`, `'received_not_executed'`)*
- **Response (`200 OK`):**
  ```json
  {
    "success": true
  }
  ```

#### 6. `GET /api/v1/agents/:device_id/status`
- **Response (`200 OK`):**
  ```json
  {
    "id": "3b07b2e1-81ad-496c-b0fa-80a72ba92d8e",
    "organization_id": "7b09bf3c-4e89-48ce-8dbe-268e24c2ceca",
    "user_id": null,
    "device_name": "WORKSTATION-CORP-42",
    "hostname": "WORKSTATION-CORP-42",
    "os": "Ubuntu 22.04 LTS",
    "platform": "linux",
    "agent_version": "1.0.0",
    "status": "online",
    "last_heartbeat": "2026-10-04T08:01:00.000Z",
    "created_at": "2026-10-04T07:30:00.000Z",
    "last_heartbeat_age_seconds": 15
  }
  ```

- **Impact on Existing Endpoints:**
  - `POST /api/v1/telemetry/system-event` ([`telemetryRoutes.js:12-55`](../../services/backend/src/routes/telemetryRoutes.js#L12-L55)): Upgraded with `flexibleSystemEventAuth`. Allows requests authenticated with **either** standard User Bearer JWT **OR** Agent device credentials (`x-agent-credential-id`, `x-agent-credential-secret`). User JWT requests behave 100% identically to before.
- **Frontend Relevance:**
  - **New Feature Area:** Requires a new "Enrolled Devices / Agents" page or a tab in Settings/Admin for IT administrators to generate enrollment tokens, monitor agent online status, and view last heartbeat age.

---

### Feature 3: Machine Learning Engine Validation & Malware Analysis (PR #29 & PR #31)
**Code Location:** [`services/ml-service/app/routers/analyzeRouter.py:128-160`](../../services/ml-service/app/routers/analyzeRouter.py#L128-L160), [`services/ml-service/app/services/malware_engine.py`](../../services/ml-service/app/services/malware_engine.py), [`services/ml-service/app/services/message_engine.py`](../../services/ml-service/app/services/message_engine.py), [`services/ml-service/app/services/url_engine.py`](../../services/ml-service/app/services/url_engine.py).  
**Purpose:** Delivers verified supervised ML models for Phishing and Malicious URLs, integrates DFDC visual deepfake models, and introduces static PE binary malware analysis using the EMBER feature set.

| Endpoint (FastAPI ML Service) | Method | Auth | Description |
|---|---|---|---|
| `/analyze/malware` & `/internal/analyze/malware` | `POST` | Internal / No Auth | Static PE executable analysis for malware indicators using EMBER features (supports `multipart/form-data` or JSON `{ file_url }`) |

#### Request & Response Schema for Feature 3
- **Request (Multipart Form Data):** `file`: PE binary (`.exe`, `.dll`) up to 50 MB.
- **Request (JSON):**
  ```json
  {
    "file_url": "data:application/x-dosexec;base64,TVqQAAMAAAAEAAAA...",
    "file_name": "sample.exe"
  }
  ```
- **Response (`200 OK` - UnifiedAnalysisResponse):**
  ```json
  {
    "threat_type": "malware",
    "risk_score": 88.5,
    "risk_level": "high",
    "explanation": "Static PE analysis flagged 14 high-entropy suspicious import anomalies consistent with ransomware.",
    "signals": [
      { "signal_name": "pe_entropy", "signal_value": "7.84", "weight": 0.85 },
      { "signal_name": "suspicious_imports", "signal_value": "VirtualAllocEx, WriteProcessMemory", "weight": 0.90 }
    ],
    "recommended_actions": [
      { "action_type": "quarantine_file", "description": "Quarantine the suspicious binary" },
      { "action_type": "isolate_host", "description": "Disconnect host from corporate LAN" }
    ],
    "mitre_mappings": [
      { "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter" }
    ]
  }
  ```
- **Gateway Status:** As of `020a2af`, `POST /api/v1/check/malware` is **not yet wired** in Node.js Gateway `checkRoutes.js`. The capability is fully active and tested on FastAPI ML Service at port 8000, awaiting gateway route exposure.

---

## 4. Breaking Changes & Discrepancies vs. Current Frontend Services

Comparison against `apps/web/src/services/*.js` on `feature/frontend-dashboard`:

```
apps/web/src/services/
├── apiClient.js
├── authService.js
├── incidentService.js
├── scanService.js
├── analyticsService.js
└── index.js
```

### 4.1 🚨 CRITICAL: Token Expiry & Silent Refresh Handling (`apiClient.js`)
- **Backend Reality:** Access tokens expire in **15 minutes** (`ACCESS_TOKEN_EXPIRY = '15m'` in [`authController.js:10`](../../services/backend/src/controllers/authController.js#L10)). A 7-day refresh token is issued during login/signup via both JSON body (`data.refreshToken`) and HttpOnly cookie.
- **Frontend Current State:**
  - `apiClient.js:43-57`: Intercepts `401` errors and immediately deletes `localStorage.getItem('cyberguard_token')`, broadcasting `cyberguard:unauthorized` to force-redirect the user to `/login`.
  - `authService.js`: Has NO refresh function, does not store `refreshToken`, and does not pass credentials.
- **Breaking Impact:** After 15 minutes of user inactivity or interaction, every subsequent API call fails with `401 TOKEN_EXPIRED`, unexpectedly logging out users mid-task.
- **Frontend Action Required:** Add an Axios 401 retry interceptor that calls `POST /api/v1/auth/refresh` using the stored refresh token or cookie (`withCredentials: true`), updates `cyberguard_token`, and retries the queued failed request.

---

### 4.2 ⚠️ BREAKING: Employee Signup Missing Required `organization_name` (`authService.js`)
- **Backend Reality:** In [`authController.js:56-61`](../../services/backend/src/controllers/authController.js#L56-L61):
  ```javascript
  if (effectiveRole === 'employee' && (!organization_name || typeof organization_name !== 'string' || !organization_name.trim())) {
    return res.status(400).json({ error: 'MISSING_ORGANIZATION_NAME', message: 'Organization name is required for employee registration' });
  }
  ```
- **Frontend Current State:**
  - `authService.js:13-20`: `signup(email, password, full_name, role = 'individual')` only submits `{ email, password, full_name, role }`.
- **Breaking Impact:** Selecting the "Employee" role during signup fails immediately with `400 MISSING_ORGANIZATION_NAME`.
- **Frontend Action Required:**
  1. Update `authService.signup(email, password, full_name, role, organization_name)` to include `organization_name`.
  2. In `SignupPage.jsx`, conditionally require an "Organization Name" input when the employee role is selected.

---

### 4.3 ⚠️ DISCREPANCY: Client-Only Logout vs Stateful Server Logout (`authService.js`)
- **Backend Reality:** `POST /api/v1/auth/logout` ([`authRoutes.js:16`](../../services/backend/src/routes/authRoutes.js#L16), [`authController.js:354-387`](../../services/backend/src/controllers/authController.js#L354-L387)) accepts Bearer auth, sets `is_revoked = TRUE` on the refresh token in PostgreSQL, purges the user cache in Redis, and clears the HttpOnly cookie.
- **Frontend Current State:**
  - `authService.js:68-76`: Contains comment `// Local session termination (backend has no stateful logout endpoint)` and only clears `localStorage`.
- **Impact:** Refresh tokens remain valid in Redis/DB for 7 days even after the user clicks "Log out" in the UI.
- **Frontend Action Required:** Update `authService.logout()` to call `await apiClient.post('/auth/logout')` before clearing local storage.

---

### 4.4 ⚠️ DISCREPANCY: Media Direct File Upload Flow (`scanService.js`)
- **Backend Reality:**
  - `POST /api/v1/media/upload-url` generates signed Supabase upload URLs.
  - `POST /api/v1/check/media` accepts `{ file_path, media_type }` and validates user ownership.
- **Frontend Current State:**
  - `scanService.js:33-40`: `checkMedia({ file_url, media_type = 'image' })` only supports submitting an already-hosted URL.
- **Frontend Action Required:** Add `getMediaUploadUrl({ file_name, file_size_bytes, media_type })` to `scanService.js` to enable direct browser-to-storage uploads.

---

### 4.5 ⚠️ SUBTLE CASING: Risk Level Comparisons Across Services
- **Backend Reality:**
  - `/api/v1/check/*` and `/api/v1/incidents` return lowercase (`"safe"`, `"low"`, `"medium"`, `"high"`, `"critical"`).
  - `/api/v1/guardian/alerts` returns TitleCase (`"High"`, `"Critical"`).
  - `/api/v1/analytics/overview` returns TitleCase keys in `risk_breakdown` (`{ Safe: 0, Low: 0, ... }`).
- **Frontend Current State:**
  - `incidentService.js:17`: Correctly converts filter parameters using `String(risk_level).toLowerCase()`.
  - In UI badge renderers (e.g. `IncidentsPage.jsx`), direct equality checks against `'High'` or `'Critical'` will fail to render appropriate warning badges for incidents.
- **Frontend Action Required:** Always wrap risk level checks in `.toLowerCase()` (e.g. `risk_level?.toLowerCase() === 'high'`).

---

### 4.6 💡 MISSING FRONTEND SERVICES FOR NEW ENDPOINTS
The frontend currently lacks service files for the following fully implemented backend areas:

| Domain | Missing Endpoint(s) | Suggested Frontend Service & Functions |
|---|---|---|
| **Secret Scanning** | `POST /api/v1/check/secret` | Add `checkSecret({ input, context })` to `scanService.js` |
| **Guardian Mode** | `GET /guardian/links`<br>`POST /guardian/link`<br>`POST /guardian/link/:id/accept`<br>`POST /guardian/link/:id/decline`<br>`POST /guardian/link/:id/revoke`<br>`GET /users/search?email=...`<br>`GET /guardian/alerts` | Create `guardianService.js` with link lifecycle and email search methods |
| **Firewall Management** | `GET /admin/firewall-rules`<br>`POST /admin/firewall-rules/validate`<br>`POST /admin/firewall-rules`<br>`DELETE /admin/firewall-rules/:rule_id`<br>`POST /admin/agents/:agent_id/firewall-commands` | Create `firewallService.js` for admin containment controls |
| **Agent / Device Management** | `POST /admin/agents/tokens`<br>`GET /agents/:device_id/status` | Create `agentService.js` for enrollment token generation and device status |
| **Audit Logs** | `GET /api/v1/audit-logs` | Add `getAuditLogs({ limit, offset, action })` in `adminService.js` |

---

## 5. Summary Table: Backend Contract Audit Findings

| Category | Endpoint / Feature | Dev Status | Frontend Service Match | Action Required on Frontend |
|---|---|---|---|---|
| **Auth** | `POST /auth/signup` | Active (`bcrypt` + real DB) | Mismatch on `employee` | Pass `organization_name` when registering employees |
| **Auth** | `POST /auth/refresh` | Active (reusable 7-day token) | Missing | Add Axios 401 interceptor & token refresh flow |
| **Auth** | `POST /auth/logout` | Active (revokes DB & Redis) | Missing server call | Call `POST /auth/logout` on logout |
| **Checks** | `POST /check/message`, `/check/url` | Active | Full Match | None (already working) |
| **Checks** | `POST /check/media` | Active (accepts `file_path`) | Partial (only `file_url`) | Support Supabase upload flow via `/media/upload-url` |
| **Checks** | `POST /check/secret` | Active | Missing | Add `checkSecret()` to `scanService.js` |
| **Checks** | `POST /analyze/malware` | Active on ML Service | Not exposed on Gateway | Await gateway router wiring |
| **Incidents** | `GET /incidents`, `GET /incidents/:id` | Active | Full Match | Handle lowercase `risk_level` |
| **Actions** | `PATCH /actions/:id` | Active (`taken` / `dismissed`) | Full Match | None |
| **Scheduler** | `schedulerService.js` (60s cron) | Active on `dev` | N/A (Internal cron) | None |
| **Firewall** | `GET/POST/DELETE /admin/firewall-rules` | Active (PR #30) | Missing | Create `firewallService.js` for Admin UI |
| **Agents** | `POST /admin/agents/tokens`, `/status` | Active (PR #27) | Missing | Add agent enrollment UI for Enterprise admins |
| **Guardian** | Handshake & alert endpoints | Active | Missing | Create `guardianService.js` |
| **Socket.IO** | Event `'incident:new'` | Active (10-field payload) | Full Match | None |

---

## 6. Audit Verification & Branch Integrity Confirmation

- Verification completed entirely using non-destructive inspection (`git log`, `git diff`, `view_file`, `grep_search`).
- No commits, merges, or rebases were performed into `feature/frontend-dashboard`.
- Local pending workspace files were safely stashed prior to checkout and will be preserved intact.
