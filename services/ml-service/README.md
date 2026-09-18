# CYBERGUARD — AI/ML Microservice

FastAPI threat detection microservice hosting detection engines, risk calibration, and explainability generators for CYBERGUARD.

---

## 1. Login / Behavioral Anomaly Detection Engine (Phase 1)

Located at `app/services/login_anomaly/`.

### Architecture & Capabilities
- **Algorithm:** Unsupervised `scikit-learn` `IsolationForest` calibrated to CYBERGUARD's 5-tier risk scale (`Safe`, `Low`, `Medium`, `High`, `Critical`).
- **Telemetry Features:**
  - `login_hour` (0–23, supports ISO timestamp parsing)
  - `is_new_device` (hardware/browser fingerprint indicator)
  - `is_new_location` (geographic IP / country indicator)
  - `failed_attempts` (consecutive failed logins in recent window)
  - `impossible_travel` (geo-velocity anomaly flag)
- **Unified Contract:**
  ```json
  {
    "risk_level": "Safe | Low | Medium | High | Critical",
    "risk_score": 0-100,
    "explanation": "Human-readable plain-English explanation",
    "recommended_action": "Prescriptive remediation step",
    "signals": [
      {
        "name": "signal_name",
        "weight": 0.0
      }
    ]
  }
  ```
- **Independence:** Completely standalone from FastAPI and PostgreSQL database layers; reusable across worker scripts, batch evaluators, and API routers.

---

## 2. Running Tests & Evaluation

### Run Unit Tests
```bash
cd services/ml-service
.\venv\Scripts\python.exe -m pytest tests/test_login_anomaly.py -v
```

### Run Engine Evaluation & Demo
```bash
cd services/ml-service
.\venv\Scripts\python.exe evaluate.py
```
