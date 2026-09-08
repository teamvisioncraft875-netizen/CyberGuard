# Workflow: new-endpoint

> **Objective:** Add a new API endpoint in the Node.js API Gateway or Python FastAPI ML Service while maintaining strict layered architecture, security, and contract synchronization.

---

## Pre-Flight Checklist
- [ ] Determine the responsible service:
  - **Node.js Gateway (`services/backend`)**: Client-facing endpoints, authentication, PostgreSQL persistence, WebSocket broadcasts, service orchestration.
  - **FastAPI ML Service (`services/ml-service`)**: Internal AI/ML inference, threat detection algorithms, explanation generation.
- [ ] Check if this endpoint changes or creates an API contract. If yes, consult `docs/API_CONTRACT.md`.
- [ ] Determine authentication & RBAC requirements: `public`, `authenticated (JWT)`, `enterprise_admin`, or `guardian`.

---

## Step-by-Step Implementation

### Option A: Node.js / Express Endpoint (`services/backend`)

1. **Update API Contract First:**
   - Define path, HTTP method, headers, request body, and response structure in `docs/API_CONTRACT.md`.
2. **Define/Update Model (`src/models/`):**
   - If persistent data is required, define or update database queries/schemas (PostgreSQL).
3. **Create Controller Logic (`src/controllers/`):**
   - Extract parameters from `req.body`, `req.params`, or `req.query`.
   - Call services, database models, or internal FastAPI endpoints.
   - Format response using standard utility wrappers.
   - Wrap in `try/catch` and pass errors to `next(err)`.
4. **Define Validation & Middleware (`src/middlewares/`):**
   - Create request schema validator (e.g., Joi or Zod).
   - Attach authentication middleware (`verifyToken`) and role guard (`requireRole`) if protected.
5. **Register Route (`src/routes/`):**
   - Map URL path and HTTP verb to middleware chain and controller function.
   - **Enforce Rule:** Zero business logic in `routes/`. Only route mapping and middleware binding.
6. **Real-Time Integration (If Applicable):**
   - If endpoint creates/updates an incident, emit WebSocket event (e.g., `io.emit('new_incident', incidentData)`).

---

### Option B: FastAPI ML Service Endpoint (`services/ml-service`)

1. **Define Pydantic Schemas (`schemas/`):**
   - Create request schema (e.g., `AnalyzeTextRequest`).
   - Create response schema matching standard risk scoring:
     ```python
     class ThreatResponse(BaseModel):
         risk_level: Literal["Safe", "Low", "Medium", "High", "Critical"]
         risk_score: int
         explanation: str
         recommended_action: str
         mitre_technique: Optional[str] = None
         signals: Dict[str, Any] = {}
     ```
2. **Implement Service Logic (`services/`):**
   - Implement inference, feature extraction, or heuristic evaluation inside `services/`.
   - Ensure inference runs asynchronously or in background tasks to avoid blocking the event loop.
3. **Register Route in Router (`routers/`):**
   - Define `@router.post("/...")` with typed request and response schemas.
   - Inject services or model singletons via FastAPI dependencies.
   - **Enforce Rule:** Zero model loading or calculation logic in `routers/`. Delegate to `services/`.
4. **Register Router in App (`main.py`):**
   - Include router in `app.include_router(...)` with appropriate prefix and tags.
5. **Expose via Node.js Gateway:**
   - Add orchestration method in Node.js backend so frontend clients never communicate directly with FastAPI.

---

## Verification & Testing
- [ ] Test endpoint using `curl` or Postman with valid inputs.
- [ ] Test 400 Bad Request with missing or malformed fields.
- [ ] Test 401 Unauthorized / 403 Forbidden with invalid or missing JWT tokens (if protected).
- [ ] Verify response JSON matches `docs/API_CONTRACT.md` exactly.
- [ ] Verify no unhandled promise rejections or unformatted 500 error dumps.
