# CYBERGUARD — Workspace Rules & Engineering Standards

These rules are mandatory for all AI agents and developers working in this repository. Follow them strictly.

---

## 1. Strict Layered Architecture (No Business Logic in Routes)

Maintain clean separation of concerns across both backend services:

### Node.js Backend (`services/backend/`)
- `routes/` — Endpoint URI definitions and middleware attachments only. **Zero business logic.**
- `controllers/` — Request handling, input extraction, calling services/models, returning responses.
- `middlewares/` — Auth (JWT), RBAC, input validation schemas, centralized error handling.
- `models/` — Database schema definitions and data access layers.
- `utils/` — Pure helper functions, formatting, and mathematical/token utilities.

### FastAPI ML Service (`services/ml-service/`)
- `routers/` — APIRouter endpoint definitions and dependency injections only. **Zero business logic.**
- `services/` — Heavy computation, model inference, feature engineering, and threat analysis logic.
- `schemas/` — Pydantic models defining input/output contracts and data validation.
- `utils/` — Preprocessing helpers, tokenizers, and model-loading utilities.

---

## 2. Secrets & Environment Configuration

- **Never hardcode** API keys, credentials, JWT secrets, or database URLs in source code.
- Always load configuration via environment variables through a centralized `config/` module (e.g., `config/index.js` or `config.py` using Pydantic `BaseSettings` / `dotenv`).
- **Never commit `.env` files.** Always verify `.env` is listed in `.gitignore`. Use `.env.example` to document required variables.

---

## 3. Shared API Contract Enforcement

- Every API endpoint implementation must strictly conform to `docs/API_CONTRACT.md`.
- If a request or response shape must change, **update `docs/API_CONTRACT.md` within the same Pull Request** before or alongside the code change. Never defer contract documentation.

---

## 4. Standard Risk-Scoring Response Format

All detection engines and analysis endpoints must return the standard threat payload structure:

```json
{
  "risk_level": "Safe | Low | Medium | High | Critical",
  "explanation": "Clear, plain-English explanation of why this was flagged",
  "recommended_action": "Actionable next step for the user or administrator"
}
```

- Allowed `risk_level` values are strictly: `"Safe"`, `"Low"`, `"Medium"`, `"High"`, `"Critical"`.
- Explanations must be plain-English and human-readable, not raw stack traces or internal model output tensors.
- Accompanying numeric scores (`risk_score`: 0–100) and telemetry metadata must augment this base contract, never replace it.

---

## 5. Frontend Component Reuse & Styling Conventions

- **Web (`apps/web`):**
  - Use Tailwind CSS and reusable UI components (e.g., `shadcn/ui`).
  - Do not use arbitrary inline `style={{ ... }}` objects.
  - Extract repeating layouts and UI cards into shared components in `components/ui/` or `components/shared/`.
- **Mobile (`apps/mobile`):**
  - Follow consistent styling conventions (e.g., `StyleSheet.create` or shared token constants).
  - Avoid ad-hoc, messy inline style props.
  - Re-use common buttons, alert banners, and cards across screens.

---

## 6. Commit Message Discipline

- Write clear, specific, and imperative commit messages detailing *what* and *where*:
  - **Good:** `add domain-mismatch check to phishing engine`
  - **Good:** `implement Isolation Forest feature scaler for telemetry`
  - **Good:** `integrate expo-speech read-aloud trigger on critical alerts`
  - **Bad:** `fix`, `update`, `wip`, `changes`, `cleanup`

---

## 7. Dependency Discipline & Bloat Prevention

- **Do not introduce new `npm` or `pip` dependencies casually.**
- If a new library is required:
  - Verify if standard libraries or already-installed packages can solve the problem.
  - Explicitly document the dependency and its rationale in the Pull Request description.
- Keep installation times fast and container images lightweight for hackathon evaluation.

---

## 8. Mentor Mandate — Test-Driven Development (TDD) & Automated Test Verification

- **Write Test Cases First (TDD):** For any new feature, endpoint, or detection engine, write automated test cases defining expected behavior, edge cases, and failure modes before or alongside production code.
- **Run & Pass All Tests:** Never consider a task completed until automated tests (`pytest`, `npm test`) execute and pass with 100% green status.
- **Proof in PRs:** Every Pull Request description must include the test execution results or screenshot as proof for the reviewer/mentor to verify functionality.
- **Follow Workflow:** Refer to `docs/DEVELOPMENT_WORKFLOW_AND_TDD.md` for standard step-by-step instructions.

