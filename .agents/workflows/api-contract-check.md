# Workflow: api-contract-check

> **Objective:** Verify that frontend clients (React Web Dashboard, React Native Mobile), the Node.js API Gateway, and the FastAPI ML Service remain in complete alignment with `docs/API_CONTRACT.md`.

---

## When to Run This Workflow
- Before submitting any Pull Request that touches routes, controllers, routers, schemas, or API clients.
- When frontend integration tests or mock data calls fail.
- When adding a new threat detection engine or incident field.

---

## Step 1: Identify Changed Endpoints & Schemas
Run `git diff` on API and contract definitions:
```bash
git diff origin/dev -- docs/API_CONTRACT.md services/backend/src/routes/ services/backend/src/controllers/ services/ml-service/routers/ services/ml-service/schemas/
```

Check specifically for:
- Path changes (e.g., `/api/v1/incidents` vs `/api/incidents`)
- HTTP method changes (`POST`, `GET`, `PUT`, `DELETE`)
- Added, renamed, or deleted request payload fields
- Added, renamed, or deleted response payload fields
- HTTP status codes (200 OK, 201 Created, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found, 500 Internal Error)

---

## Step 2: Validate Against `docs/API_CONTRACT.md`
Verify each modified endpoint in the source code against the documentation:

| Check | Requirement | Verified? |
|---|---|---|
| **Path & Method** | Exact character match with documented route | [ ] |
| **Authentication** | Documented headers (e.g. `Authorization: Bearer <jwt>`) match gateway middleware | [ ] |
| **Request Payload** | All required JSON keys present, types match, no silent schema mismatches | [ ] |
| **Response Payload** | Top-level keys match documented contract | [ ] |
| **Risk Scoring Schema** | Threat responses contain `risk_level`, `explanation`, `recommended_action` | [ ] |
| **Status Codes** | Errors return documented status code and `{ error: string, message: string }` | [ ] |

---

## Step 3: Verify Downstream Consumers

### 1. Web Frontend (`apps/web/`)
- Check API fetching services / Axios instances / React Query hooks.
- Ensure TypeScript types or prop-types match the documented response structure.
- Verify fallback handling when optional fields are null/undefined.

### 2. Mobile App (`apps/mobile/`)
- Check mobile API client calls and native Share-Sheet ingestion handler.
- Verify FCM push notification payload parser expects matching JSON keys.
- Verify read-aloud TTS receives the exact `explanation` string from the contract.

### 3. Internal Gateway-to-FastAPI Calls
- Verify Node.js controller formats the payload exactly as FastAPI's Pydantic schema expects.
- Check timeout and error handling if FastAPI returns 500 or times out.

---

## Step 4: Remediation
- **If the code change was intentional:** Update `docs/API_CONTRACT.md` immediately in the same branch before opening the PR.
- **If the code broke the existing contract:** Revert or adjust the code to preserve backward compatibility.
- Ensure teammates are notified in the team chat or PR description of any contract evolution.
