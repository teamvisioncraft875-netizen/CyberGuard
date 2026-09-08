# CYBERGUARD — AI-Assisted Development Guide

> **Team Onboarding & Operating Standard**  
> *Target Audience:* All 5 CYBERGUARD team members & AI agents  
> *Authoritative Context:* See [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md) and [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md)

---

## 1. Overview
CYBERGUARD is built using AI-assisted pair programming across a 5-person team. To maintain high engineering velocity without code drift or breaking changes, all developers and AI agents must follow the unified workflows, skill activations, and contribution standards outlined in this guide.

---

## 2. Required Skills Ecosystem
Custom agent skills live in [.agents/skills/](file:///c:/Users/subha/Downloads/CyberGuard/.agents/skills/). Activate or reference them according to your workstream:

| Skill | Primary Owner | Activation Scenarios |
|---|---|---|
| `backend-architect` | Backend Lead | Node.js Gateway routes, controllers, middlewares, JWT/RBAC auth, and FastAPI orchestration. |
| `fastapi-engine-builder` | AI Lead (Subrat) | Threat detection engines (`services/ml-service/engines/`), async inference, and Pydantic schemas. |
| `postgres-schema-designer` | Backend / Data Lead | PostgreSQL table design, migrations, UUIDs, `JSONB` signals, and performance indexing. |
| `websocket-integrator` | Backend / Web Lead | Real-time live incident pushes, room multiplexing (`org:*`, `user:*`), and connection resilience. |
| `react-dashboard-builder` | Web Lead (Teammate 4) | React Command Dashboard, shadcn/ui components, Recharts visualizations, and Framer Motion polish. |
| `mobile-security-app-builder` | Mobile Lead (Teammate 5) | React Native/Expo app, FCM push notifications, `expo-speech` TTS, and Share-Sheet integration. |
| `threat-model-reviewer` | All Members | Threat scenario verification, MITRE ATT&CK mapping, and 0–100 risk scoring calibration. |
| `api-contract-enforcer` | All Members | Validating and synchronizing code with `docs/API_CONTRACT.md`. |
| `cybersecurity-reviewer` | All Members | Pre-commit security audits, secret leakage checks, and parameterized query validation. |
| `documentation-writer` | All Members | Authoring specifications, benchmark reports (`docs/BENCHMARKS.md`), and judge demo scripts. |

---

## 3. Required Development Workflows
Pre-defined agent workflows live in [.agents/workflows/](file:///c:/Users/subha/Downloads/CyberGuard/.agents/workflows/):

- **`/new-endpoint`** — Step-by-step guide for creating endpoints in Node Gateway or FastAPI ML Service.
- **`/new-engine`** — Scaffold and register a new threat detection engine with standardized risk output.
- **`/api-contract-check`** — Verify parity across Web, Mobile, Gateway, and FastAPI against `docs/API_CONTRACT.md`.
- **`/security-review`** — Pre-PR security audit covering secrets, input validation, and RBAC boundaries.
- **`/bug-investigation`** — Multi-tier triage protocol to isolate failures across Gateway, ML, DB, and Sensor layers.
- **`/pre-pr-review`** — Mandatory pre-flight checklist before submitting any Pull Request.
- **`/architecture-review`** — Design review protocol for new features, external APIs, or model choices.
- **`/fast-execution`** — Rapid execution mode minimizing commentary and keeping completion output under 10 lines.

---

## 4. AI Model Recommendations

| Task Complexity | Recommended Model Class | Typical Use Cases |
|---|---|---|
| **High Reasoning / Architecture** | High-capacity reasoning models (e.g. Gemini Flash High, Claude Sonnet/Opus, GPT-4o) | Architecture reviews, ML inference pipeline design, threat modeling, complex multi-tier debugging, security audits. |
| **Fast Execution / Scaffolding** | Low-latency models (e.g. Gemini Flash, Claude Haiku, GPT-4o-mini) | Boilerplate generation, shadcn component styling, unit test scaffolding, documentation drafting, typo/lint fixes. |

---

## 5. Branch Workflow

CYBERGUARD utilizes a single monorepo with strict branch isolation:

```
[main] (Protected: Production & Judge Demo-Ready)
   ▲
   │ (Reviewed Release PRs only)
[dev]  (Default Integration Branch)
   ▲
   ├── feature/<task-name>   (e.g., feature/phishing-classifier)
   ├── fix/<bug-name>        (e.g., fix/websocket-reconnect)
   └── setup/<task-name>     (e.g., setup/ai-workspace)
```

1. Always branch off the latest `dev`:
   ```bash
   git checkout dev
   git pull origin dev
   git checkout -b feature/<descriptive-name>
   ```
2. Never push directly to `main` or `dev`.

---

## 6. Commit Message Conventions
Commit messages must be concise, specific, and imperative. State *what* was done and *where*:

- **Format:** `<action> <component/feature> - <detail>`
- **Examples:**
  - `add domain-mismatch check to phishing engine`
  - `implement Isolation Forest feature scaler for telemetry`
  - `integrate expo-speech read-aloud trigger on critical alerts`
  - `update incident schema in docs/API_CONTRACT.md`
- **Forbidden:** Generic commit messages such as `fix`, `update`, `wip`, `changes`, or `cleanup`.

---

## 7. Pull Request (PR) Workflow

Every change must go through a Pull Request into `dev`:

1. **Run Local Pre-Flight Checks:**
   - Execute the `/pre-pr-review` workflow.
   - Verify build and linting pass for modified workspaces:
     ```bash
     cd services/backend && npm test
     cd services/ml-service && python -m pytest
     cd apps/web && npm run build
     ```
2. **Open PR into `dev`:**
   - Title: Clear description matching the primary commit.
   - Body: Use the standard template (Summary, Affected Components, API Contract Sync, New Dependencies, How to Test).
3. **Dependency Rule:**
   - If introducing a new `npm` or `pip` package, explicitly justify it in the PR description to prevent hackathon dependency bloat.
4. **Contract Rule:**
   - If payload shapes changed, `docs/API_CONTRACT.md` must be modified in the same PR.
5. **Review & Merge:**
   - Requires at least one peer or mentor review approval before merging into `dev`.

---

## 8. Concise Execution Mode

To maximize development velocity during time-sensitive implementation, trigger **Concise Execution Mode** by including this exact phrase in your prompt:

> **"Use concise execution mode."**

### Expected Agent Behavior
- The agent implements requested changes immediately without lengthy pre-ambles.
- No conversational filler or unrequested architectural summaries.
- The completion response is strictly capped at **under 10 lines** using the standard format:

```text
✓ Completed requested task: [brief summary]
✓ Files modified: [count]
✓ Issues requiring attention: [None / list blocking issues]
```
