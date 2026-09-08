---
name: documentation-writer
description: Authors technical architecture specifications, API contracts, benchmark evaluation reports, demo scripts, and README guides for CYBERGUARD. Activate when updating docs/, editing README.md, updating docs/API_CONTRACT.md, preparing competition judge presentations, or documenting system workflows.
---

# Documentation Writer — Technical Specifications & Presentations

This skill guides the authoring of clear, authoritative technical documentation, API specifications, demo scripts, and evaluation reports across the CYBERGUARD repository.

> **Authoritative Context:** See [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md) and [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md).

---

## 1. Documentation Principles & Voice
- **Concise & Direct:** Focus on technical substance, architecture boundaries, and reproducible steps. Avoid marketing fluff or empty superlatives.
- **Explainability First:** Consistently emphasize the CYBERGUARD 4-pillar mantra:
  $$\text{\textbf{SHIELD}} \cdot \text{\textbf{DETECT}} \cdot \text{\textbf{EXPLAIN}} \cdot \text{\textbf{RESPOND}}$$
- **Audience-Aware Documentation:**
  - *Engineers & AI Agents:* Precise endpoint schemas, database relations, code layers, and directory layouts.
  - *Judges & Evaluators:* Clear threat scenario demonstrations, benchmark accuracy tables, and human-layer impact (Guardian Mode).

---

## 2. Core Documentation Repositories

```
cyberguard/
├── docs/
│   ├── API_CONTRACT.md          # Single source of truth for all API payloads & routes
│   ├── ARCHITECTURE.md          # Multi-tier data flow, component diagrams, system bounds
│   ├── BENCHMARKS.md            # Accuracy, precision/recall, and latency across 6 engines
│   └── DEMO_SCRIPT.md           # 3-minute live demonstration script for hackathon judges
├── .agents/
│   ├── PROJECT_CONTEXT.md       # Master project context for AI agents
│   ├── rules/cyberguard.md      # Enforced engineering constraints
│   └── workflows/               # Step-by-step developer workflows
└── README.md                    # Public GitHub entrance and quick-start guide
```

---

## 3. Authoring Guidelines for Specific Deliverables

### A. Updating `docs/API_CONTRACT.md`
When documenting endpoints, include:
1. Endpoint path and HTTP verb.
2. Authentication requirements (`Bearer JWT` + required role).
3. Request headers, query params, and JSON body sample.
4. Response status codes (`200`, `201`, `400`, `401`, `403`, `500`).
5. Standard Threat Response payload with risk scoring keys.

### B. Benchmarks & Evaluation Reports (`docs/BENCHMARKS.md`)
Structure engine evaluation metrics into clear comparative tables:
- Test dataset source and sample count (benign vs. malicious).
- Accuracy, Precision, Recall, and F1-Score.
- P95 Inference Latency (ms).
- Fallback activation rates (e.g. TF-IDF fallback when LLM rate-limited).

### C. Judge Demo Script (`docs/DEMO_SCRIPT.md`)
Structure live demonstrations in clear chronological phases:
1. **The Hook (30s):** Show hyper-convincing AI phishing email & cloned voice sample that traditional tools miss.
2. **The Detection & Explanation (60s):** Scan content on Web Dashboard; highlight instant plain-English reasoning and 0–100 risk score.
3. **The Response & Human Layer (60s):** Demonstrate real-time WebSocket incident pop-up in Enterprise SOC view, followed by Guardian Mode mobile push notification and automated read-aloud alert.
4. **Conclusion (30s):** Summarize architecture, open-source model design, and production scalability.

---

## 4. Documentation Quality Checklist
- [ ] Code samples in documentation are syntactically valid and match current codebase.
- [ ] Relative links to files (e.g. `docs/API_CONTRACT.md`, `.agents/PROJECT_CONTEXT.md`) are accurate.
- [ ] No generic placeholders (`<insert text here>`) left in committed markdown.
- [ ] Risk scoring tiers are consistently capitalized: `Safe`, `Low`, `Medium`, `High`, `Critical`.
- [ ] Commit message follows project conventions (e.g. `docs: update incident API contract in docs/API_CONTRACT.md`).
