# Workflow: bug-investigation

> **Objective:** Systematically isolate, triage, and resolve bugs across CYBERGUARD's multi-tier stack (Client → Gateway → Database/WebSocket → AI Service → Sensor).

---

## 1. Triage & Layer Isolation
Identify where the breakdown is occurring by inspecting boundaries:

```
[Web/Mobile Client] ──①──> [Node Gateway] ──②──> [FastAPI ML Service]
          ▲                      │
          │                      ├──③──> [PostgreSQL]
          └──⑤── [WebSocket] ◄───┘
                    ▲
                    └──④── [Guard App Sensor]
```

- **Boundary ① (Client ↔ Gateway):** UI freezing, network 4xx/5xx errors, CORS errors, or missing auth tokens.
- **Boundary ② (Gateway ↔ ML Service):** Internal HTTP connection refused, timeout during model inference, unhandled 500 from FastAPI.
- **Boundary ③ (Gateway ↔ Database):** SQL syntax errors, failed migrations, missing relation columns, slow connection pool.
- **Boundary ④ (Sensor ↔ Gateway):** Telemetry packets dropped, malformed device payload, sensor daemon crash.
- **Boundary ⑤ (Gateway ↔ WebSocket):** Incidents saved in DB but not updating live on Dashboard; missed broadcast rooms.

---

## 2. Inspect Logs & Diagnostic Data
Gather diagnostic evidence before touching code:

1. **Node.js Gateway Logs:**
   - Look for request paths, HTTP status codes, and stack traces.
2. **FastAPI ML Service Logs:**
   - Check Uvicorn console for unhandled Python exceptions, CUDA/torch memory issues, or Pydantic validation errors.
3. **Browser DevTools / Metro Logs:**
   - Check Network tab: inspect request headers, payload, and response body.
   - Check Console: examine uncaught JavaScript/React rendering errors.
   - Check WS tab: confirm WebSocket handshake and received frames.
4. **PostgreSQL Database State:**
   - Query recent entries to verify if data was written:
     ```sql
     SELECT id, threat_scenario, risk_tier, created_at FROM incidents ORDER BY created_at DESC LIMIT 5;
     ```

---

## 3. Reproduce in Isolation
Reproduce the issue with minimal overhead:
- **Test Gateway directly:** Use `curl` or Postman with test credentials to bypass the frontend.
- **Test ML Service directly:** Call the internal FastAPI endpoint (`http://localhost:8000/detect/...`) with mock JSON to determine if the AI model or preprocessor is failing.
- **Test Sensor directly:** Run the Guard App telemetry packaging function locally and verify output schema.

---

## 4. Implement Fix Adhering to Architecture
When applying the fix:
- **Layered Code Rule:** Put fixes in `controllers/`, `services/`, or `models/`—**never** insert ad-hoc logic into `routes/` or `routers/`.
- **Contract Rule:** If the fix alters payload fields, update `docs/API_CONTRACT.md` immediately.
- **Risk Format Rule:** Ensure all threat outputs maintain `{ risk_level, explanation, recommended_action }`.

---

## 5. Regression & Verification Checklist
- [ ] Reproduce the exact original failure and confirm it now passes.
- [ ] Test edge cases: empty strings, null values, malformed URLs, special characters.
- [ ] Confirm related downstream components still work (e.g. Command Dashboard still displays incident, Mobile push notification still arrives).
- [ ] Verify no new warnings or unhandled exceptions are logged in console.
