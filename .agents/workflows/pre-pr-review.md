# Workflow: pre-pr-review

> **Objective:** Comprehensive pre-flight verification checklist for developers and AI agents before opening a Pull Request into the `dev` branch.

---

## 1. Branch & Git Hygiene
- [ ] Working branch is cut from `dev` and targets `dev` as base.
- [ ] Branch naming follows conventions: `feature/<task-name>`, `fix/<task-name>`, or `setup/<task-name>`.
- [ ] Branch is rebased or merged with latest `origin/dev`.
- [ ] Commit messages are descriptive, clear, and imperative (e.g., `add domain-mismatch check to phishing engine`), containing no generic `fix` or `update` messages.

---

## 2. Architecture & Rules Compliance Check
Verify compliance with [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md):

| Check | Requirement | Pass? |
|---|---|---|
| **Layered Backend** | Node: `routes/controllers/middlewares/models/utils`. Zero business logic in `routes/`. | [ ] |
| **Layered ML Service** | FastAPI: `routers/services/schemas/utils`. Zero model logic in `routers/`. | [ ] |
| **No Hardcoded Secrets** | Credentials & URLs loaded via `config/`. Zero `.env` files staged or committed. | [ ] |
| **API Contract Sync** | If request/response shapes changed, `docs/API_CONTRACT.md` updated in this PR. | [ ] |
| **Risk Scoring Shape** | Threat payloads strictly include `risk_level`, `explanation`, `recommended_action`. | [ ] |
| **Frontend Styling** | Web uses Tailwind + shadcn; Mobile uses consistent styling conventions; no inline style mess. | [ ] |
| **Dependency Control** | Any new `npm` or `pip` package is explicitly justified in the PR description. | [ ] |

---

## 3. Build & Test Verification
Run checks on the relevant workspaces affected by this PR:

```bash
# Backend verification
cd services/backend && npm test # or npm run lint / npm run dev

# ML service verification
cd services/ml-service && python -m pytest # or python -c "import main; print('OK')"

# Web frontend verification
cd apps/web && npm run build # or npm run lint

# Mobile app verification
cd apps/mobile && npx expo-doctor # or lint
```

- [ ] Zero compile or bundling errors.
- [ ] Zero unhandled linter errors.

---

## 4. PR Description Template
Ensure the PR body contains:

```markdown
### Summary of Changes
- Briefly describe the feature or bugfix implemented.

### TDD & Automated Test Verification (Required by Mentor)
- [ ] Automated test cases written before / alongside implementation
- [ ] All test suites passing locally (`pytest`, `npm test`, etc.)

**Test Execution Output / Proof:**
```text
(Paste terminal test execution output here, e.g. pytest 8 passed)
```

### Affected Components
- [ ] Web Frontend (`apps/web`)
- [ ] Mobile App (`apps/mobile`)
- [ ] Backend Gateway (`services/backend`)
- [ ] ML Service (`services/ml-service`)
- [ ] Telemetry Guard App (`services/guard-app`)
- [ ] Documentation (`docs/`)

### Contract & Architecture Verification
- [ ] `docs/API_CONTRACT.md` updated (if applicable)
- [ ] Follows layered architecture pattern
- [ ] Uses standard risk scoring format

### New Dependencies Added (if any)
- List package name and reason, or write "None".

### How to Test
1. Step-by-step instructions for the reviewer to verify functionality.

```
