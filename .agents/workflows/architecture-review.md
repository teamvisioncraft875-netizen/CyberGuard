# Workflow: architecture-review

> **Objective:** Evaluate new features, refactors, or engine proposals against the CYBERGUARD system architecture, dual-backend boundaries, and hackathon delivery constraints.

---

## 1. Project Alignment Check
Evaluate the proposal against the core mission in [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md):

- [ ] **Mantra Alignment:** Does this change directly support **SHIELD**, **DETECT**, **EXPLAIN**, or **RESPOND**?
- [ ] **Explainability Principle:** Does the feature provide a clear, human-understandable reason for its actions rather than acting as a black box?
- [ ] **Target Persona Value:** Does it clearly deliver value to one of our key user profiles (Individual User, Guardian, Enterprise SOC, or Competition Judges)?

---

## 2. System Boundary & Service Placement
Verify that components reside in the correct architectural tier:

```
[Web/Mobile Client]
       │
       ▼ (HTTPS/WSS)
[Node.js API Gateway] ◄─── (Telemetry) ─── [Guard App Sensor]
       │
       ▼ (Internal Network Only)
[FastAPI ML Service]
```

- [ ] **Dual-Backend Separation:**
  - Client state, user authentication, authorization, database storage, and real-time WebSocket broadcasting belong exclusively in **Node.js Gateway (`services/backend/`)**.
  - Computationally intensive ML inference, pretrained model execution, feature extraction, and heuristics belong exclusively in **FastAPI (`services/ml-service/`)**.
- [ ] **Zero Direct Client Access:** Web and Mobile clients must never call the FastAPI service directly. All traffic routes through the Node.js API Gateway.
- [ ] **Lightweight Sensor Principle:** The desktop Guard App (`services/guard-app`) must remain a lightweight observer reporting telemetry over HTTPS. It must not run heavy local inference.

---

## 3. Pragmatic Hackathon Constraints
Protect the team against scope creep and unrealistic engineering burdens:

| Consideration | Acceptable Approach | Anti-Pattern (Reject) |
|---|---|---|
| **AI / Deepfake Models** | Pretrained open-source models (ViT, ASVspoof, XGBoost, LLM prompting). | Attempting to train deep learning models from scratch. |
| **Video Processing** | Periodic frame sampling (e.g. 1 frame every 2–3 seconds). | Building full real-time WebRTC deepfake video pipelines. |
| **Technical Threats** | Process anomaly spikes & abnormal network telemetry via `psutil`. | Writing kernel-level drivers or full binary malware sandboxes. |
| **Sensitive Scenarios** | Safe user redirection to national cybercrime helplines. | Building automated in-house classifiers for explicit blackmail media. |

---

## 4. Team Ownership & Workstream Impact
Check who needs to be consulted before implementing the change:

- **Backend Lead:** Consult if altering database schemas, authentication flows, or WebSocket events.
- **AI Lead (Subrat):** Consult if modifying FastAPI engine interfaces, model weights, or prompt templates.
- **Data Lead (Sudhanshu):** Consult if modifying telemetry data structures or requiring new threat datasets.
- **Web Frontend (Teammate 4):** Consult if changing dashboard incident feeds or Recharts visualization data.
- **Mobile Frontend (Teammate 5):** Consult if changing notification payloads or Share-Sheet ingestion contracts.

---

## 5. Review Verdict & Decision Record
Record the outcome of the architecture review:
- **Approved:** Proceed to implementation following `new-endpoint` or `new-engine` workflows.
- **Approved with Conditions:** Note required modifications (e.g., simplified model, updated API contract).
- **Rejected / Out of Scope:** Log reason (e.g., excessive latency, dependency bloat, violates dual-backend boundary).
