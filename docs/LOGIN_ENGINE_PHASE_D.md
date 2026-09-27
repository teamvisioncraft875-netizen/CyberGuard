# CYBERGUARD — Login & Authentication Anomaly Detection Engine
## Phase D: Backend Gateway Wiring, Telemetry Endpoint & End-to-End Security Tests Report

This document records the backend gateway wiring, authentication enforcement, request and response validation, fail-closed resilience, privacy protections, performance benchmarks, and end-to-end integration tests implemented for **Phase D** of the CYBERGUARD Login Anomaly Detection Engine.

> **CRITICAL ARCHITECTURAL GUARANTEE (FAIL-CLOSED)**:
> If the upstream ML microservice fails, crashes, times out, is unavailable, or returns malformed/corrupted data, the Express gateway **strictly returns HTTP 502 Bad Gateway (`DETECTION_ENGINE_UNAVAILABLE`)**. Under no circumstances does the system swallow errors or return a false `risk_level: "Safe"` or HTTP 200/201 verdict.

---

### 1. Architectural Flow Diagram

```text
Client / Telemetry Sensor (Guard App)
                 │
                 ▼  POST /api/v1/telemetry/login-event
       ┌────────────────────────────────────────────────────────┐
       │               Node.js Express API Gateway              │
       ├────────────────────────────────────────────────────────┤
       │ 1. JWT Authentication (Bearer Token)                   │
       │ 2. Tenant Isolation & RBAC Validation                  │
       │ 3. Strict Payload Type & ISO-8601 Validation           │
       │ 4. Privacy Invariant: Strip credentials & secrets      │
       └─────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼  POST /internal/analyze/login (HTTP / JSON)
                                 │  Bounded Timeout (10,000 ms)
       ┌─────────────────────────┴──────────────────────────────┐
       │                FastAPI ML Microservice                 │
       ├────────────────────────────────────────────────────────┤
       │ 1. Schema Ingestion (LoginAnalyzeRequest)              │
       │ 2. Session Tracking (BoundedLoginSessionTracker)       │
       │ 3. Feature Assembly (20 Features Schema)               │
       │ 4. Isolation Forest Inference (Real Model Checkpoint)  │
       │ 5. Decision Score Normalization -> [0.0, 1.0]          │
       │ 6. UnifiedAnalysisResponse Packaging                   │
       └─────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼  UnifiedAnalysisResponse
       ┌─────────────────────────┴──────────────────────────────┐
       │               Node.js Express API Gateway              │
       ├────────────────────────────────────────────────────────┤
       │ 1. Response Validation (Risk Level, Scores, Signals)   │
       │ 2. Anomaly Signal Derivation                           │
       │    (anomaly_detected: risk_level not in [Safe, Low])   │
       │ 3. On Failure/Timeout/Malformed -> HTTP 502            │
       └─────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼  HTTP 201 Created (Recorded)
                         Client / Guard App
```

---

### 2. Telemetry Endpoints & Route Mapping

The login telemetry endpoint is registered in `services/backend/src/routes/telemetryRoutes.js` and mounted by Express:
- **Canonical API v1 Path**: `POST /api/v1/telemetry/login-event`
- **Root Alias Path**: `POST /api/telemetry/login-event`
- **Internal ML Microservice Path**: `POST /internal/analyze/login` (and `POST /api/v1/analyze/login`)

---

### 3. Authentication & Authorization Requirements

- **JWT Enforcement**: The endpoint is guarded by `auth` middleware (`services/backend/src/middlewares/auth.js`). Requests without a valid Bearer token, with expired tokens, or with forged signatures are immediately rejected with **HTTP 401 Unauthorized**.
- **Tenant Isolation**: Non-admin users are strictly locked to their authenticated identity (`req.user.id`). Any `user_id` passed in the body by a non-admin is ignored. If an admin provides a custom `user_id`, the gateway validates that the target user belongs to the admin's organization (`req.user.organization_id`), returning **HTTP 403 Forbidden** if mismatched.

---

### 4. Strict Request Validation

Incoming telemetry payloads undergo structural validation in `telemetryController.reportLoginEvent`:
- `timestamp`: Required string, must parse as a valid ISO-8601 date string (`!isNaN(Date.parse(timestamp))`).
- `device_id`: Required non-empty string.
- `failed_attempts`: Required non-negative integer ($\ge 0$). Booleans, negative numbers, floats, and non-numeric strings are rejected with **HTTP 400 Bad Request (`INVALID_PAYLOAD`)**.
- `location`: Optional; if present, must be a string.

---

### 5. Privacy & Sensitive Credential Protection

Login telemetry often originates in authentication contexts where passwords or tokens could inadvertently be included.
- **Sanitization**: Any raw passwords (`password`), auth tokens (`token`, `auth_token`), or session secrets (`secret`, `credential`) mistakenly included in the request body are stripped.
- **Non-Leakage Guarantee**: Credentials and raw secrets are never passed downstream to the ML service, never logged in server logs, and never reflected in JSON response or error bodies.

---

### 6. Fail-Closed Error & Timeout Handling (HTTP 502)

The gateway treats the ML microservice as an external, bounded dependency:
- **Bounded Timeout**: Dispatches via `callMlEngine` using `AbortSignal.timeout(ML_SERVICE_TIMEOUT_MS)` (default: 10,000 ms, configurable via `process.env.ML_SERVICE_TIMEOUT_MS`).
- **Service Down / Network Refused**: If the ML service is unreachable, returns **HTTP 502 Bad Gateway**:
  ```json
  {
    "error": "DETECTION_ENGINE_UNAVAILABLE",
    "message": "Detection engine unavailable"
  }
  ```
- **Timeout**: If the ML service exceeds the configured timeout threshold, returns **HTTP 502 Bad Gateway**.
- **Malformed ML Response**: If the ML service returns invalid risk levels, non-finite scores, out-of-bounds anomaly scores, missing explanations, or non-array recommended actions, the gateway rejects the payload with **HTTP 502 Bad Gateway**.
- **No False Safe Verdicts**: ML failures are **never** masked as `risk_level: "Safe"` or HTTP 200/201.

---

### 7. Response Contract & Anomaly Semantics

Successful ingestion returns **HTTP 201 Created** with the unified analysis payload:

```json
{
  "status": "recorded",
  "anomaly_detected": true,
  "risk_level": "High",
  "risk_score": 76,
  "explanation": "Elevated authentication failure volume (15 attempts) indicates automated brute-force probing.",
  "recommended_actions": [
    "Apply authentication rate-limiting on source identifier",
    "Prompt user for multi-factor authentication (MFA) challenge"
  ],
  "signals": {
    "failed_attempts": 15,
    "attempt_frequency_hz": 0.2,
    "session_duration": 75.0,
    "unique_usernames_count": 1,
    "anomaly_score": 0.7602,
    "raw_decision_score": -0.1541,
    "detector_triggered": "Behavioral Login Anomaly Detector",
    "supervised_probability": null,
    "is_new_device": null,
    "impossible_travel": null,
    "attack_vector": "Behavioral Authentication Anomaly"
  }
}
```

- **Anomaly Score Semantics**: Preserves Phase C normalization:
  - `0.0` = Inlier conforming to baseline normal activity.
  - `1.0` = Extreme statistical outlier.
  - Terminology: Strictly an **anomaly score**, never termed an "attack probability".
- **Zero Fabricated Probabilities**: `signals.supervised_probability` is explicitly `null`.
- **Operational Risk Classification**: Mapped via the calibrated 5-tier thresholds: Safe ($0-19$), Low ($20-39$), Medium ($40-69$), High ($70-89$), Critical ($90-100$).

---

### 8. End-to-End Test Suite (`test_phase5_e2e_and_security.js`)

All 10 Phase D end-to-end integration and security test cases are implemented and automated in `services/backend/test_phase5_e2e_and_security.js`:

| Test # | Test Scenario | Expected Behavior | Result |
| :---: | :--- | :--- | :---: |
| **Test 1** | Valid Login Telemetry Ingestion | HTTP 201, valid risk level, score, signals, actions | **PASS** |
| **Test 2** | High-Failure Session Anomaly | HTTP 201, `anomaly_detected: true`, High risk, anomaly $\ge 0.6$ | **PASS** |
| **Test 3** | Baseline / Lower-Anomaly Login | HTTP 201, operational risk tier, anomaly score $<$ Test 2 | **PASS** |
| **Test 4** | Request Validation (7 Malformed Cases) | HTTP 400 `INVALID_PAYLOAD` on missing/bad types | **PASS** |
| **Test 5** | Authentication Enforcement | HTTP 401 on missing, expired, and forged JWTs | **PASS** |
| **Test 6** | Upstream ML Service Unavailable | Strictly HTTP 502 `DETECTION_ENGINE_UNAVAILABLE` (Never Safe) | **PASS** |
| **Test 7** | Upstream ML Service Timeout | Strictly HTTP 502 on bounded timeout | **PASS** |
| **Test 8** | Malformed ML Response Payload | Strictly HTTP 502 on invalid schema from ML service | **PASS** |
| **Test 9** | Privacy & Credential Leakage | Passwords/tokens/secrets stripped; never in response | **PASS** |
| **Test 10**| Existing Detection Engines Regression | URL check (Critical) and Network spike (High) fully operational | **PASS** |

---

### 9. End-to-End Latency Benchmark

Measured across 50 consecutive round-trip requests (`Client` $\to$ `Express Gateway` $\to$ `FastAPI ML Microservice` $\to$ `Isolation Forest Inference` $\to$ `Express Gateway` $\to$ `Client`):
- **Mean Latency**: **42.20 ms**
- **P95 Latency**: **47.95 ms**
- **P99 Latency**: **48.22 ms**

*(Compares with Phase C in-process Python baseline: Mean 21.4 ms, P95 28.7 ms; the $\sim 20$ ms delta corresponds to Node.js JSON serialization, local HTTP loopback transport, and schema validation.)*

---

### 10. Known Limitations

1. **Unsupervised Behavioral Anomaly Model**: The engine uses an Isolation Forest trained on Cowrie honeypot network session distributions. It detects deviations from observed honeypot baseline dynamics; it is **not** a supervised phishing or credential-stuffing classifier.
2. **Unsupported Telemetry Signals**: `supervised_probability`, `is_new_device`, and `impossible_travel` remain `null` as they are unmeasured by the current Cowrie telemetry ingestion stream.
3. **No Enterprise Baseline**: Honeypot activity does not represent enterprise corporate SSO baselines; thresholds must not be represented as enterprise-normal behavior.
