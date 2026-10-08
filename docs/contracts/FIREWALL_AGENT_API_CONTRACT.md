# CyberGuard Host Firewall Integration & Enterprise Agent API Contract

> **Document Status**: Production Backend Contract (Audited against `origin/dev` codebase in `services/backend/src`).  
> **Target Audience**: Frontend Engineers building Enterprise Administration & Firewall SOC views (`apps/web`), and Security Engineers maintaining the CyberGuard Agent Daemon.  
> **Scope**: Host Firewall rule management, agent enrollment token lifecycle, agent heartbeat/command protocol, and protected network boundaries.

---

## 1. Quick Reference Endpoint Matrix

| Method | Endpoint Path | Authentication & RBAC | Primary Consumer | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/admin/firewall-rules` | Bearer JWT (`admin` only) | Admin Web UI | List & filter organization firewall rules with pagination. |
| `POST` | `/api/v1/admin/firewall-rules/validate` | Bearer JWT (`admin` only) | Admin Web UI | Pre-flight validation of candidate IP / domain against protected ranges. |
| `POST` | `/api/v1/admin/firewall-rules` | Bearer JWT (`admin` only) | Admin Web UI | Create firewall rule in `pending` state and queue agent command. |
| `DELETE` | `/api/v1/admin/firewall-rules/:rule_id` | Bearer JWT (`admin` only) | Admin Web UI | Mark rule `pending_delete` and queue revocation command to agent. |
| `POST` | `/api/v1/admin/agents/:agent_id/firewall-commands` | Bearer JWT (`admin` only) | Admin Web UI | Directly queue a low-level firewall command to an online agent. |
| `POST` | `/api/v1/admin/agents/tokens` | Bearer JWT (`admin` only) | Admin Web UI | Generate single-use agent enrollment token with configurable expiry. |
| `POST` | `/api/v1/agents/enroll` | One-Time Token (Public) | Agent Daemon | Enrolls device, exchanges one-time token for agent credentials. |
| `POST` | `/api/v1/agents/:device_id/heartbeat` | Agent Credentials (`id` + `secret`) | Agent Daemon | Reports agent liveness, receives count of pending commands. |
| `GET` | `/api/v1/agents/:device_id/status` | Hybrid (Admin JWT or Public) | Admin UI / Agent | Inspects agent telemetry, OS platform, and heartbeat age. |
| `GET` | `/api/v1/agents/:device_id/protected-targets` | Public (Rate-limited) | Agent Daemon | Downloads protected baseline IPs/CIDRs/domains that must never be blocked. |
| `GET` | `/api/v1/agents/:device_id/commands` | Agent Credentials (`id` + `secret`) | Agent Daemon | Polled by agent daemon to retrieve queued instructions. |
| `POST` | `/api/v1/agents/:device_id/commands/:command_id/result` | Agent Credentials (`id` + `secret`) | Agent Daemon | Reports execution result back to gateway and syncs rule status. |

---

## 2. Firewall Management Endpoints (Admin Only)

### 2.1 `GET /api/v1/admin/firewall-rules`
- **Method & Path**: `GET /api/v1/admin/firewall-rules`
- **Authentication**: `Bearer <accessToken>`
- **Authorization**: `roleCheck(['admin'])`. The authenticated user must belong to an organization (`req.user.organization_id` must not be null; returns `403 FORBIDDEN` if null).
- **Rate Limiting**: `generalLimiter`
- **Code Reference**: [`adminRoutes.js:10-17`](../../services/backend/src/routes/adminRoutes.js#L10-L17), [`firewallController.js:17-45`](../../services/backend/src/controllers/firewallController.js#L17-L45), [`FirewallRule.js:75-127`](../../services/backend/src/models/FirewallRule.js#L75-L127)

#### Query Parameters
| Parameter | Type | Required | Default | Description |
| :--- | :--- | :---: | :---: | :--- |
| `agent_id` | UUID string | No | `undefined` | Filter rules for a specific enrolled agent device. |
| `status` | string | No | `undefined` | Filter by status: `pending`, `active`, `pending_delete`, `deleted`. |
| `rule_type` | string | No | `undefined` | Filter by type: `block_ip` or `block_domain`. |
| `limit` | integer | No | `50` | Page limit (clamped between `1` and `100`). |
| `offset` | integer | No | `0` | Pagination offset (minimum `0`). |

#### Response Shape (`200 OK`)
```json
{
  "total": 3,
  "limit": 50,
  "offset": 0,
  "rules": [
    {
      "id": "7b8f9e21-4d32-4871-bdf6-2e11e3b55555",
      "agent_id": "c1f7b0e2-89a3-4871-bdf6-2e11e3b33333",
      "organization_id": "a9e223b1-4091-4560-8431-727c9d924151",
      "rule_type": "block_ip",
      "target_ip": "198.51.100.24",
      "target_domain": null,
      "target": "198.51.100.24",
      "agent_name": "WIN-WORKSTATION-01",
      "rule_id_local": "CyberGuard_Block_198_51_100_24",
      "status": "active",
      "created_by_id": "d4e210b3-1122-4334-a556-998877665544",
      "created_by": "admin@defensecorp.com",
      "source_command_id": "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
      "source": "manual",
      "created_at": "2026-10-04T12:00:00.000Z",
      "expires_at": null,
      "deleted_at": null,
      "result": {
        "stdout": "Rule added successfully",
        "return_code": 0
      }
    }
  ]
}
```

#### Field Specifications & Nullability
- `id` (UUID, non-null): Rule identifier.
- `agent_id` (UUID, non-null): Reference to target agent in `devices` table.
- `organization_id` (UUID, non-null): Tenant boundary identifier.
- `rule_type` (Enum, non-null): Either `'block_ip'` or `'block_domain'`.
- `target_ip` (string, nullable): Non-null if `rule_type === 'block_ip'`.
- `target_domain` (string, nullable): Non-null if `rule_type === 'block_domain'`.
- `target` (string, non-null): SQL `COALESCE(target_ip, target_domain)` for straightforward display.
- `agent_name` (string, nullable): Joined `devices.hostname` of the agent.
- `rule_id_local` (string, nullable): Host OS native firewall identifier (e.g. Windows Defender DisplayName or iptables comment/hash). Populated after agent execution.
- `status` (Enum, non-null): One of:
  - `'pending'`: Rule created in database; agent execution command queued.
  - `'active'`: Agent reported successful rule enforcement.
  - `'pending_delete'`: Admin requested revocation; agent unblock command queued.
  - `'deleted'`: Agent successfully removed local rule.
- `created_by_id` (UUID, nullable): User ID of the initiating admin. `null` if triggered by Policy Engine.
- `created_by` (string, nullable): Email of the initiating admin.
- `source_command_id` (UUID, nullable): Linked `agent_commands.id`.
- `source` (Enum, non-null): Derived via SQL: `'manual'` if initiated by an admin user, `'policy_engine'` if automated.
- `created_at` (TIMESTAMPTZ, non-null): Rule creation timestamp.
- `expires_at` (TIMESTAMPTZ, nullable): TTL expiration timestamp for temporary mitigations.
- `deleted_at` (TIMESTAMPTZ, nullable): Populated when marked for deletion.
- `result` (JSONB object, non-null): Execution output reported back by the agent.

#### Error Responses
- `401 Unauthorized`: Missing or expired Bearer token.
- `403 Forbidden`: User role is not `admin`, or admin has no assigned `organization_id`.
- `500 Internal Server Error`: Database query failure (`{ "error": "INTERNAL_SERVER_ERROR", "message": "Failed to retrieve firewall rules" }`).

#### UX Implications
- The UI should support filtering by status (All, Active, Pending, Revoked) and searching by IP/domain.
- Rules marked `source: 'policy_engine'` should display an **"Automated Policy"** badge with a link to the associated Incident if present.

---

### 2.2 `POST /api/v1/admin/firewall-rules/validate`
- **Method & Path**: `POST /api/v1/admin/firewall-rules/validate`
- **Authentication**: `Bearer <accessToken>` (`admin` only)
- **Rate Limiting**: `generalLimiter`
- **Code Reference**: [`firewallController.js:51-78`](../../services/backend/src/controllers/firewallController.js#L51-L78), [`firewallService.js:155-304`](../../services/backend/src/services/firewallService.js#L155-L304)

#### Request Body
```json
{
  "rule_type": "block_ip",
  "target_data": {
    "ip_address": "192.168.1.50"
  }
}
```
*(Also accepts `{ "rule_type": "block_domain", "target_data": { "domain": "malicious-c2.com" } }` or raw strings in `target_data`).*

#### Protected Target Enforcement (What Makes a Target "Invalid")
The backend enforces hardcoded network boundary protection to prevent agents from bricking essential services or isolating the gateway:

1. **Static Protected IP Addresses**:
   - Loopback & Unspecified: `127.0.0.1`, `0.0.0.0`, `::1`, `::`
   - Public DNS Resolvers: `8.8.8.8`, `8.8.4.4` (Google), `1.1.1.1`, `1.0.0.1` (Cloudflare), `9.9.9.9` (Quad9)
   - Dynamic Backend Host IP: Resolved backend host/IP from configuration (`CYBERGUARD_BACKEND_IP` or `BACKEND_URL`).
2. **Protected IPv4 CIDR Blocks**:
   - `127.0.0.0/8` (Loopback)
   - `10.0.0.0/8` (RFC 1918 Class A Private)
   - `172.16.0.0/12` (RFC 1918 Class B Private: `172.16.0.0` – `172.31.255.255`)
   - `192.168.0.0/16` (RFC 1918 Class C Private)
   - `169.254.0.0/16` (Link-local / APIPA)
   - `0.0.0.0/8` (Current network / default route)
   - `224.0.0.0/4` (Multicast)
   - `240.0.0.0/4` (Reserved for future use)
   - `255.255.255.255/32` (Limited broadcast)
3. **Protected IPv6 Subnets**:
   - `fe80::/10` (Link-local)
   - `fc00::/7` & `fd00::/8` (Unique Local Addresses - ULA)
4. **Agent Self-Protection**:
   - If `target_data.agent_ip` is passed, blocking the agent's own IP is rejected.
5. **Domain Validation Rules**:
   - Wildcards are strictly prohibited (`*.badsite.com` is rejected).
   - URI protocols, ports, and paths (`http://`, `:8080`, `/path`) are rejected.
   - Whitespace and characters outside `^[a-z0-9.-]+$` are rejected.
   - Max length: 253 characters; labels between 1 and 63 characters.
   - Static Protected Domains: `localhost`, `cyberguard.local`, and the backend server's active domain (exact match or subdomain).

#### Response Shape: Valid Target (`200 OK`)
```json
{
  "valid": true,
  "error_if_invalid": null,
  "error": null,
  "target_ip": "198.51.100.24",
  "target_domain": null
}
```

#### Response Shape: Protected / Invalid Target (`200 OK`)
> [!NOTE]
> The validation endpoint returns **HTTP 200** with `valid: false` and the explicit reason in `error` and `error_if_invalid`.

```json
{
  "valid": false,
  "error_if_invalid": "Target IP 192.168.1.50 falls within protected private/reserved range (192.168.0.0/16) and cannot be blocked",
  "error": "Target IP 192.168.1.50 falls within protected private/reserved range (192.168.0.0/16) and cannot be blocked",
  "target_ip": null,
  "target_domain": null
}
```

#### Error Responses
- `400 Bad Request`: Missing payload (`{ "valid": false, "error": "Both rule_type and target_data are required" }`).
- `401 / 403`: Unauthorized or non-admin.

#### UX Implications
- Use this endpoint for **live, debounced pre-validation** as the admin types into the IP/Domain input field.
- If `valid === false`, show an inline warning explaining why (e.g. *"This IP is part of RFC 1918 Private Subnet 192.168.0.0/16 and cannot be blocked"*) and disable the "Add Rule" submission button.

---

### 2.3 `POST /api/v1/admin/firewall-rules`
- **Method & Path**: `POST /api/v1/admin/firewall-rules`
- **Authentication**: `Bearer <accessToken>` (`admin` only)
- **Rate Limiting**: `generalLimiter`
- **Code Reference**: [`firewallController.js:84-150`](../../services/backend/src/controllers/firewallController.js#L84-L150), [`firewallService.js:315-444`](../../services/backend/src/services/firewallService.js#L315-L444)

#### Request Body
```json
{
  "agent_id": "c1f7b0e2-89a3-4871-bdf6-2e11e3b33333",
  "rule_type": "block_ip",
  "target_data": {
    "ip_address": "203.0.113.88"
  }
}
```

#### Lifecycle & Execution Flow
1. **Validation**: The backend verifies `agent_id` exists in `public.devices` and runs full protected target validation.
2. **Initial State**: A new rule is created in `public.agent_firewall_rules` with **`status: 'pending'`**.
3. **Command Queueing**: An instruction is immediately inserted into `public.agent_commands` with `status: 'pending'`, `command_type: rule_type`, `can_execute: true`.
4. **Execution**: The next time the agent daemon polls `/commands`, it receives the directive, applies the local host rule, and reports the result via `/commands/:command_id/result`. This updates the rule status to `'active'`.

#### Response Shape (`201 Created`)
```json
{
  "success": true,
  "rule_id": "8f3e2b1a-9876-4abc-def0-123456789abc",
  "status": "pending",
  "rule": {
    "id": "8f3e2b1a-9876-4abc-def0-123456789abc",
    "agent_id": "c1f7b0e2-89a3-4871-bdf6-2e11e3b33333",
    "organization_id": "a9e223b1-4091-4560-8431-727c9d924151",
    "rule_type": "block_ip",
    "target_ip": "203.0.113.88",
    "target_domain": null,
    "rule_id_local": null,
    "status": "pending",
    "created_by_id": "d4e210b3-1122-4334-a556-998877665544",
    "expires_at": null,
    "deleted_at": null,
    "result": {
      "validation": "passed",
      "initiated_at": "2026-10-04T12:05:00.000Z"
    },
    "created_at": "2026-10-04T12:05:00.000Z"
  },
  "validation_result": {
    "valid": true,
    "target_ip": "203.0.113.88"
  }
}
```

#### Error Responses
- `400 Bad Request`:
  - Target in protected list:
    ```json
    {
      "error": "VALIDATION_FAILED",
      "error_type": "validation_failed",
      "message": "Target IP 127.0.0.1 is in protected list and cannot be blocked",
      "error_message": "Target IP 127.0.0.1 is in protected list and cannot be blocked",
      "validation_result": { "valid": false, "error": "Target IP 127.0.0.1 is in protected list and cannot be blocked" }
    }
    ```
  - Device not found:
    ```json
    {
      "error": "VALIDATION_FAILED",
      "message": "Agent device not found: c1f7b0e2-89a3-4871-bdf6-2e11e3b33333"
    }
    ```
- `500 Internal Server Error`: DB insertion failure.

#### UX Implications
- When the admin submits a rule, add it to the UI table with an Amber **"Pending Enforcement"** status badge.
- When WebSocket event `agent:command_result` or periodic polling triggers, update the badge to a Green **"Active"** status.

---

### 2.4 `DELETE /api/v1/admin/firewall-rules/:rule_id`
- **Method & Path**: `DELETE /api/v1/admin/firewall-rules/:rule_id`
- **Authentication**: `Bearer <accessToken>` (`admin` only)
- **Rate Limiting**: `generalLimiter`
- **Code Reference**: [`firewallController.js:156-210`](../../services/backend/src/controllers/firewallController.js#L156-L210), [`firewallService.js:479-598`](../../services/backend/src/services/firewallService.js#L479-L598)

#### Response Shape (`200 OK`)
```json
{
  "deleted": true,
  "rule_id": "8f3e2b1a-9876-4abc-def0-123456789abc",
  "status": "deletion_pending",
  "agent_notified": true,
  "command_id": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e"
}
```

#### Meaning of `pending_delete` for the UI
- **Asynchronous Deletion**: Deletion is **not** an immediate SQL `DELETE`. The backend updates the rule's status to `pending_delete` and inserts a `delete_firewall_rule` command into `agent_commands`.
- **UI Behavior**: The row should **not** instantly disappear from the screen.
- Instead, render the row with an animated/muted state:
  - Status badge: **"Revoking..."** or **"Deletion Pending"** (Amber/Gray with spinner).
  - Disable further actions on this row.
  - The row remains visible until the agent completes local unblocking and reports back.

#### Error Responses
- `400 Bad Request`: `Valid rule_id UUID is required`.
- `404 Not Found`:
  ```json
  {
    "error": "NOT_FOUND",
    "error_type": "rule_not_found",
    "message": "Firewall rule not found in your organization"
  }
  ```
- `500 Internal Server Error`: Revocation failure.

---

### 2.5 `POST /api/v1/admin/agents/:agent_id/firewall-commands`
- **Method & Path**: `POST /api/v1/admin/agents/:agent_id/firewall-commands`
- **Authentication**: `Bearer <accessToken>` (`admin` only)
- **Rate Limiting**: `generalLimiter`
- **Code Reference**: [`firewallController.js:238-480`](../../services/backend/src/controllers/firewallController.js#L238-L480)
- **Purpose**: Low-level operational endpoint to queue an ad-hoc firewall instruction directly to a target agent without pre-creating an `agent_firewall_rules` row. The rule row is created post-execution when the agent reports results.

#### Request Body
```json
{
  "command_type": "block_ip",
  "target_data": {
    "ip_address": "198.51.100.99"
  },
  "reason": "Active outbound C2 beaconing observed during incident #482"
}
```

#### Agent Liveness Requirements & Errors
This endpoint enforces strict agent availability checks:
- **Device Not Found**: Returns `404 Not Found` if `agent_id` does not exist or belongs to another organization.
- **Agent Disabled**: Returns `409 Conflict`:
  ```json
  {
    "error": "AGENT_DISABLED",
    "error_type": "agent_disabled",
    "message": "Agent is disabled and cannot receive commands"
  }
  ```
- **Agent Offline**: Returns `404 Not Found` (Note: Backend returns status `404` for offline state):
  ```json
  {
    "error": "AGENT_OFFLINE",
    "error_type": "agent_offline",
    "message": "Agent is offline and cannot receive commands"
  }
  ```
- **Validation Failed**: Returns `400 Bad Request` if target is in the protected network list.

#### Response Shape (`201 Created`)
```json
{
  "success": true,
  "command_id": "e4f5a6b7-c8d9-4e0f-1a2b-3c4d5e6f7a8b",
  "status": "pending",
  "agent_id": "c1f7b0e2-89a3-4871-bdf6-2e11e3b33333",
  "command": {
    "id": "e4f5a6b7-c8d9-4e0f-1a2b-3c4d5e6f7a8b",
    "device_id": "c1f7b0e2-89a3-4871-bdf6-2e11e3b33333",
    "organization_id": "a9e223b1-4091-4560-8431-727c9d924151",
    "command_type": "block_ip",
    "target_data": "{\"ip_address\":\"198.51.100.99\"}",
    "status": "pending",
    "can_execute": true,
    "created_at": "2026-10-04T12:10:00.000Z"
  }
}
```

---

### 2.6 `GET /api/v1/agents/:device_id/protected-targets`
- **Method & Path**: `GET /api/v1/agents/:device_id/protected-targets`
- **Authentication**: **PUBLIC / NO AUTH REQUIRED** (Rate-limited via `generalLimiter`).
- **Code Reference**: [`agentRoutes.js:41`](../../services/backend/src/routes/agentRoutes.js#L41), [`agentController.js:399-414`](../../services/backend/src/controllers/agentController.js#L399-L414)
- **Confirmation**: Audited and confirmed **completely public**. Intended for agent daemons during bootstrapping before credentials are confirmed, or periodically to update local safe bypass sets.

#### Response Shape (`200 OK`)
```json
{
  "protected_ips": [
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "::",
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "192.168.1.10"
  ],
  "protected_ip_ranges": [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "0.0.0.0/8",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32"
  ],
  "protected_domains": [
    "localhost",
    "cyberguard.local",
    "api.cyberguard.io"
  ],
  "updated_at": "2026-10-04T12:00:00.000Z"
}
```

---

## 3. Enterprise Agent Enrollment Endpoints

### 3.1 `POST /api/v1/admin/agents/tokens`
- **Method & Path**: `POST /api/v1/admin/agents/tokens`
- **Authentication**: `Bearer <accessToken>` (`admin` only)
- **Rate Limiting**: `generalLimiter`
- **Code Reference**: [`adminRoutes.js:77-83`](../../services/backend/src/routes/adminRoutes.js#L77-L83), [`agentController.js:16-55`](../../services/backend/src/controllers/agentController.js#L16-L55), [`agentService.js:20-56`](../../services/backend/src/services/agentService.js#L20-L56)

#### Request Body
```json
{
  "organization_id": "a9e223b1-4091-4560-8431-727c9d924151",
  "valid_for_hours": 48
}
```
*(Both fields optional: `organization_id` defaults to `req.user.organization_id`; `valid_for_hours` defaults to `24`, min `1`).*

#### Token Format & Expiry Mechanics
- **Token Generation**: Generates 32 random bytes converted to a 64-character lowercase hexadecimal string (`crypto.randomBytes(32).toString('hex')`).
- **Storage**: Inserts a new record into `public.devices` with `status: 'pending'`, `enrollment_token: token`, and `token_expires_at: NOW() + X hours`.
- **Single-Use**: Once used in `POST /agents/enroll`, `enrollment_token` and `token_expires_at` are nulled out.

#### Response Shape (`201 Created`)
```json
{
  "token": "4a9e223b1409145608431727c9d924151bdf62e11e3b333334a9e223b1409145",
  "expires_at": "2026-10-06T12:00:00.000Z",
  "organization_id": "a9e223b1-4091-4560-8431-727c9d924151"
}
```

#### Error Responses
- `400 Bad Request`: `Valid organization_id UUID is required`.
- `403 Forbidden`: `You cannot generate enrollment tokens for another organization`.
- `500 Internal Server Error`: Token generation failure.

#### UX Implications
- In the Admin Dashboard ("Agent Enrollment" modal), provide a "Generate Enrollment Token" button.
- Display the generated token in a prominent monospace field with a copy button and a copyable CLI installation command:  
  `cyberguard-agent --enroll <token>`
- Include a timer or badge indicating the expiry window (e.g. *"Expires in 24 hours"*).

---

### 3.2 `POST /api/v1/agents/enroll`
- **Method & Path**: `POST /api/v1/agents/enroll`
- **Authentication**: Authenticated via the one-time `enrollment_token` in body. (Public endpoint, rate-limited via `generalLimiter`).
- **Code Reference**: [`agentRoutes.js:24`](../../services/backend/src/routes/agentRoutes.js#L24), [`agentController.js:62-132`](../../services/backend/src/controllers/agentController.js#L62-L132), [`agentService.js:106-174`](../../services/backend/src/services/agentService.js#L106-L174)

#### Request Body
```json
{
  "enrollment_token": "4a9e223b1409145608431727c9d924151bdf62e11e3b333334a9e223b1409145",
  "hostname": "FINANCE-DESKTOP-12",
  "os": "Windows 11 Enterprise 23H2",
  "platform": "windows",
  "linked_user_id": "e2f1b0e2-89a3-4871-bdf6-2e11e3b55555",
  "agent_version": "1.2.0"
}
```
*(Required: `enrollment_token`, `hostname`. Optional: `os`, `platform`, `linked_user_id`, `agent_version`).*

#### Enrollment Flow & Cryptographic Credential Issuance
1. Token is verified against `devices` table: must exist, have `status = 'pending'`, and `token_expires_at > NOW()`.
2. Permanent credentials are created:
   - `credential_id`: UUIDv4
   - `credential_secret`: 64-character random hex string (`crypto.randomBytes(32).toString('hex')`)
   - `agent_credentials_hash`: `bcrypt.hash(credential_secret, 10)`
3. The device row is updated:
   - `status`: transitions to `'online'`
   - `hostname`, `os`, `platform`, `agent_version` are saved
   - `last_heartbeat` and `last_seen` are set to `NOW()`
   - `enrollment_token` and `token_expires_at` are nulled out (preventing replay).
4. The plaintext `credential_secret` is returned **EXACTLY ONCE** in the response.

#### Response Shape (`201 Created`)
```json
{
  "device_id": "c1f7b0e2-89a3-4871-bdf6-2e11e3b33333",
  "credential_id": "3d4e5f6a-7b8c-9d0e-1f2a-3b4c5d6e7f8a",
  "credential_secret": "e9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8",
  "organization_id": "a9e223b1-4091-4560-8431-727c9d924151"
}
```

#### Error Responses
- `400 Bad Request`: Missing `enrollment_token` or `hostname`.
- `401 Unauthorized`: Token invalid, expired, or already consumed.

---

### 3.3 `GET /api/v1/agents/:device_id/status`
- **Method & Path**: `GET /api/v1/agents/:device_id/status`
- **Authentication**: **Hybrid** via `optionalJwt` ([`agentRoutes.js:10-21`](../../services/backend/src/routes/agentRoutes.js#L10-L21)).
  - When called with an Admin Bearer JWT: Enforces tenant scoping (`device.organization_id === req.user.organization_id`). If the device belongs to another org, returns `404 Not Found`.
  - When called without JWT: Returns status if `device_id` exists.
- **Code Reference**: [`agentController.js:363-392`](../../services/backend/src/controllers/agentController.js#L363-L392), [`agentService.js:311-335`](../../services/backend/src/services/agentService.js#L311-L335)

#### Response Shape (`200 OK`)
```json
{
  "id": "c1f7b0e2-89a3-4871-bdf6-2e11e3b33333",
  "organization_id": "a9e223b1-4091-4560-8431-727c9d924151",
  "user_id": "e2f1b0e2-89a3-4871-bdf6-2e11e3b55555",
  "device_name": "FINANCE-DESKTOP-12",
  "hostname": "FINANCE-DESKTOP-12",
  "os": "Windows 11 Enterprise 23H2",
  "platform": "windows",
  "agent_version": "1.2.0",
  "status": "online",
  "last_heartbeat": "2026-10-04T14:30:15.000Z",
  "created_at": "2026-10-01T09:00:00.000Z",
  "last_heartbeat_age_seconds": 12
}
```

#### Field Specifications & Status Values
- `status`: One of `'online'`, `'offline'`, `'disabled'`, `'pending'`.
- `last_heartbeat_age_seconds`: Dynamic integer computed via `EXTRACT(EPOCH FROM (NOW() - last_heartbeat))`.
- Liveness threshold: Agents send heartbeats every 60 seconds. A device with `last_heartbeat_age_seconds > 180` should be treated as offline by the UI.

---

### 3.4 Agent-Side Protocols (Not Needed for Web UI)

#### `GET /api/v1/agents/:device_id/commands`
- **Consumer**: Agent Daemon background polling loop.
- **Authentication**: `x-agent-credential-id` and `x-agent-credential-secret` headers (or body/query). Validated via `bcrypt.compare` against `devices.agent_credentials_hash`.
- **Response**: Returns pending commands for execution along with latest protected targets list.
- **Web UI Note**: The admin web app does **not** call this endpoint.

#### `POST /api/v1/agents/:device_id/commands/:command_id/result`
- **Consumer**: Agent Daemon reporting execution success/failure.
- **Authentication**: `x-agent-credential-id` and `x-agent-credential-secret`.
- **Response**: `{ "success": true }`.
- **Web UI Note**: The web app never calls this endpoint. Result synchronization happens behind the scenes.

#### `POST /api/v1/agents/:device_id/heartbeat`
- **Consumer**: Agent Daemon (every 60s).
- **Authentication**: Agent credentials.
- **Response**: `{ "status": "online", "next_heartbeat_in_seconds": 60, "commands_pending": 0 }`.

---

## 4. Cross-Cutting Analysis

### 4.1 RBAC & Role Restrictions
- All `/api/v1/admin/*` endpoints strictly enforce `roleCheck(['admin'])`.
- Any user with `employee` or `individual` role attempting access receives:
  ```json
  {
    "error": "FORBIDDEN",
    "message": "Forbidden: role 'employee' lacks sufficient permissions for this resource"
  }
  ```
- Admins with no assigned `organization_id` receive:
  ```json
  {
    "error": "FORBIDDEN",
    "message": "Admin must belong to an organization"
  }
  ```

### 4.2 Relationship Between Firewall Rules and Incidents
- Both **manual rules** (created by admins) and **automated rules** (created by `PolicyEngine.js` during high-severity automated response workflows) share the exact same underlying table: `public.agent_firewall_rules`.
- In `GET /api/v1/admin/firewall-rules`, the SQL query differentiates origin via the computed `source` column:
  - If `created_by_id IS NOT NULL OR cmd.requested_by_id IS NOT NULL` $\rightarrow$ `source = 'manual'`.
  - Else $\rightarrow$ `source = 'policy_engine'`.
- If an automated rule was triggered by an incident response action, its `source_command_id` links to the corresponding `agent_commands` record.

### 4.3 Audit of `types.ts`
Reviewing [`types.ts`](../../types.ts) against the real backend implementation reveals substantial missing definitions:

1. **Firewall Types Missing entirely**:
   - `FirewallRule` entity is not defined.
   - `FirewallRuleType` (`'block_ip' | 'block_domain'`) is missing.
   - `FirewallRuleStatus` (`'pending' | 'active' | 'pending_delete' | 'deleted'`) is missing.
   - `FirewallValidationResult` is missing.
2. **Agent Types Missing entirely**:
   - `AgentEnrollmentTokenResponse` (`{ token, expires_at, organization_id }`) is missing.
   - `AgentStatusResponse` (`{ hostname, os, platform, status, last_heartbeat_age_seconds, ... }`) is missing.
3. **Outdated `Device` Interface**:
   - The existing `Device` interface in `types.ts:77-87` is an older, generic device model containing fields (`device_fingerprint`, `is_trusted`) that do not match the enterprise agent attributes (`hostname`, `os`, `status`, `last_heartbeat_age_seconds`, `agent_version`).

---

## 5. Backend Gaps & Architecture Blockers for the Web UI

| Gap Identified | Current Backend State | Impact on Web UI | Recommended Resolution |
| :--- | :--- | :--- | :--- |
| **No List Agents Endpoint** | `GET /api/v1/agents/:device_id/status` exists, but there is **no endpoint to list all agents for an organization** (e.g. `GET /api/v1/admin/agents` does not exist). | An Admin cannot view an "Enrolled Devices" inventory table, nor can a dropdown of online agents be populated when creating a firewall rule. | Add `GET /api/v1/admin/agents` returning `{ agents: [...] }` scoped to `req.user.organization_id`. |
| **Agent Offline on Direct Command** | `POST /admin/agents/:agent_id/firewall-commands` returns `404 Not Found` if the agent is offline rather than queueing the command for when it connects. | In contrast to `/firewall-rules` (which queues rules in `pending`), direct commands fail if the agent is temporarily disconnected. | Use `POST /api/v1/admin/firewall-rules` as the primary rule creation endpoint rather than manual commands. |
| **Missing Types in `types.ts`** | Zero firewall or agent enrollment interfaces exist in `types.ts`. | Frontend components will lack TypeScript auto-completion or compile-time guarantees when typing API responses. | Add TypeScript interfaces for `FirewallRule`, `AgentDevice`, and enrollment tokens. |
| **Rule Expiration (TTL) UI Support** | `expires_at` is supported in `agent_firewall_rules`, but `POST /admin/firewall-rules` does not accept a `ttl_hours` parameter in its request body. | Admins cannot specify temporary block windows (e.g. 1 hour block) via the current create endpoint. | Add `valid_for_hours` or `expires_at` support to `createRule`. |
