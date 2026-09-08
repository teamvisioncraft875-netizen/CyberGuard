# Workflow: new-engine

> **Objective:** Add or extend a threat detection engine in `services/ml-service/engines/` following the CYBERGUARD architecture, standardized risk format, and open-source model strategy.

---

## 1. Threat Scenario & Scope Identification
Identify which of the 6 core challenge scenarios this engine serves:
- **Scenario 1:** Phishing (Email, SMS, Social DM, QR) → Content Analysis + URL Engine
- **Scenario 2:** Deepfake Detection (Image, Audio, Video) → Multimedia Authenticity Engine
- **Scenario 3:** Digital Impersonation (Brands, Officials, VIPs) → Identity/Impersonation Engine
- **Scenario 4:** Credential Theft & Account Takeover → Login/Behavioural Anomaly Engine
- **Scenario 5:** Malicious URLs & Websites → URL/Website Analysis Engine
- **Scenario 6:** Technical Threats (Process, Network) → System Behaviour Engine

Assign the corresponding **MITRE ATT&CK Technique ID** (e.g., `T1566` Phishing, `T1586` Account Compromise, `T1071` Application Layer Protocol).

---

## 2. Model & Data Source Selection (Pragmatic Hackathon Constraints)
- **Zero Training from Scratch:** Utilize pretrained open-source models (Hugging Face Transformers, ViT, ASVspoof weights, scikit-learn Isolation Forest).
- **Offline / Fallback Support:** Ensure text engines include lightweight fallbacks (e.g., TF-IDF + Logistic Regression/XGBoost) if LLM API limits are reached.
- **Dataset Alignment:** Verify feature inputs with Data Lead (Sudhanshu) before coding input parsers.

---

## 3. Directory & File Setup
Create the engine inside `services/ml-service/engines/<engine_name>/`:
```
services/ml-service/engines/<engine_name>/
├── __init__.py
├── detector.py      # Core detection & inference logic
├── preprocessor.py  # Feature extraction, normalization, tokenization
├── rules.py         # Heuristic checks, look-alike domain distance, sender metadata
└── config.py        # Model checkpoints, thresholds, weights
```

---

## 4. Implementation Steps

1. **Implement Feature Extraction (`preprocessor.py`):**
   - Clean text, extract domain components, or process audio/image frames.
   - For video: sample frames periodically (do not build heavy real-time video streaming pipelines).
2. **Implement Core Detector (`detector.py`):**
   - Load pretrained model as a singleton or via FastAPI lifecycle handler (do not reload model on every request).
   - Compute probability scores and map to standardized risk scale.
3. **Enforce Unified Risk-Scoring Format:**
   Every engine must map output to:
   - `risk_level`: `"Safe"` (0–19), `"Low"` (20–39), `"Medium"` (40–69), `"High"` (70–89), or `"Critical"` (90–100).
   - `risk_score`: Calibrated integer (0–100).
   - `explanation`: Plain-English explanation detailing specific flags.
   - `recommended_action`: Concrete, prescriptive mitigation step.
   - `mitre_attack`: Technique ID and description.
   - `signals`: Dictionary of technical features/evidence for dashboard inspection.
4. **Expose Endpoint in Router (`services/ml-service/routers/<engine_name>.py`):**
   - Add POST endpoint with Pydantic request and response schemas.
   - Register router in `services/ml-service/main.py`.
5. **Connect Node.js Gateway:**
   - Update `services/backend/src/controllers/detectionController.js` to dispatch incoming client payloads to this new FastAPI engine.
   - Write incident to PostgreSQL and broadcast over WebSocket for live dashboard rendering.

---

## 5. Validation Checklist
- [ ] Engine returns result in < 500ms for text/URL, or < 2s for audio/image.
- [ ] Output schema strictly matches `.agents/rules/cyberguard.md` format.
- [ ] Tested against at least 3 benign samples (must score `Safe` or `Low`).
- [ ] Tested against at least 3 known malicious samples (must score `High` or `Critical`).
- [ ] Explanation is clear, jargon-free, and directly references what triggered the alert.
