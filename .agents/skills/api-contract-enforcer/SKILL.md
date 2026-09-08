---
name: api-contract-enforcer
description: Validates and enforces consistency between docs/API_CONTRACT.md, backend endpoints, ML schemas, and frontend API clients across Web and Mobile. Activate when adding new endpoints, changing request/response payloads, validating risk-scoring schemas, or synchronizing contracts between services.
---

# API Contract Enforcer — CYBERGUARD Shared Contract

This skill ensures that all 5 team workstreams build against a single, unbroken API contract defined in `docs/API_CONTRACT.md`.

> **Authoritative Context:** See [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md) and [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md).

---

## 1. The Single Source of Truth (`docs/API_CONTRACT.md`)
Every endpoint consumed by the Web Dashboard (`apps/web`), Mobile App (`apps/mobile`), or the Node.js Gateway (`services/backend`) must be declared in `docs/API_CONTRACT.md`.

**Rules:**
1. If a payload, header, query parameter, or status code changes in code, `docs/API_CONTRACT.md` must be updated in the **exact same commit or Pull Request**.
2. Frontend teams build against this contract using mock data during early development phases. Breaking this contract blocks other team members.

---

## 2. Standard Risk-Scoring Contract
All detection engines in `services/ml-service/` and the Node.js Gateway must return responses adhering to this schema:

```json
{
  "risk_level": "Safe | Low | Medium | High | Critical",
  "risk_score": 85,
  "explanation": "High Risk: Sender domain mimics a trusted bank with typo-squatted spelling. Urgency keywords detected.",
  "recommended_action": "Quarantine email, block domain, and force password reset.",
  "mitre_technique": "T1566.002",
  "signals": {
    "sender_reputation": "Suspicious",
    "domain_age_days": 4,
    "urgency_score": 0.91
  }
}
```

### Risk Level Constraints
- `risk_level` must strictly equal one of: `"Safe"`, `"Low"`, `"Medium"`, `"High"`, or `"Critical"`.
- `risk_score` must be an integer between `0` and `100`.
- `explanation` must be a plain-English, non-technical sentence describing the specific trigger.
- `recommended_action` must be an imperative, actionable instruction.

---

## 3. Core Contract Registry

| Method | Endpoint | Consumer | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | Web, Mobile | Authenticate user; returns JWT token + role. |
| `POST` | `/api/v1/auth/register` | Web, Mobile | Register new user (`individual` or `enterprise`). |
| `POST` | `/api/v1/detect/scan` | Web, Mobile | Scan text, URL, or media; orchestrates FastAPI call. |
| `GET` | `/api/v1/incidents` | Web | Fetch paginated incident feed with risk filters. |
| `GET` | `/api/v1/incidents/:id` | Web, Mobile | Detailed incident view with technical signals & audit trail. |
| `POST` | `/api/v1/incidents/:id/resolve` | Web (SOC) | Mark incident resolved with triage notes. |
| `POST` | `/api/v1/telemetry/report` | Guard App | Ingest background login/process telemetry. |
| `POST` | `/api/v1/guardians/link` | Mobile | Link vulnerable user account to family guardian. |
| `POST` | `/detect/<engine>` (Internal) | Node Gateway | Internal FastAPI inference endpoints. |

---

## 4. Contract Drift Audit Procedure
When reviewing changes, execute:
1. Compare `git diff` on route files against `docs/API_CONTRACT.md`.
2. Inspect TypeScript interfaces in `apps/web/src/types/` and `apps/mobile/src/types/` to confirm field parity.
3. Validate Pydantic response models in `services/ml-service/schemas/` against the JSON contract.
4. Verify HTTP status codes:
   - Success: `200 OK` (reads/updates), `201 Created` (scans/records).
   - Client Error: `400 Bad Request` (schema fail), `401 Unauthorized` (missing/bad JWT), `403 Forbidden` (role unauthorized), `404 Not Found`.
   - Server Error: `500 Internal Server Error` with formatted JSON `{ error: "...", message: "..." }`.
