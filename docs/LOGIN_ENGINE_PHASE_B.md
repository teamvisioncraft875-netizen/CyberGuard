# CYBERGUARD — Login & Authentication Anomaly Detection Engine
## Phase B: Model Training, Evaluation & Checkpoint Creation Report

This document records the model training, scientific target audit, Isolation Forest fitting, latency benchmarking, and held-out zero-day evaluation for **Phase B** of the CYBERGUARD Login Anomaly Detection Engine.

---

### 1. Supervised Target Audit
In accordance with the strict scientific rules of CYBERGUARD:
- **Status**: **NOT TRAINED**
- **Reason**: **A defensible supervised target is unavailable in the current Cowrie dataset.**
- **Rationale**: The Cowrie dataset captures unfiltered honeypot traffic from public internet scanners, botnets, and attackers. It contains no enterprise employee ground truth. Fabricating arbitrary binary labels (e.g., declaring all failed logins as "attack" and all successful logins as "benign") would produce scientifically invalid classifiers. Therefore, `HistGradientBoostingClassifier` was deliberately not trained on synthetic or fabricated targets.

---

### 2. Unsupervised Isolation Forest Model
- **Model**: `sklearn.ensemble.IsolationForest`
- **Ensemble Size**: 100 isolation trees (`n_estimators=100`)
- **Contamination**: 0.04 (conservative baseline outlier fraction)
- **Random Seed**: 42 (deterministic)
- **Provisional Training Baseline**: 446,998 records (99.10% of training data) filtered using conservative standard-intensity thresholds (`failed_attempts_count <= 1`, `unique_usernames_count <= 1`, `success_after_failure == 0`, `attempt_frequency_hz <= 1.5`).

---

### 3. Anomaly Score Normalization
- **Raw Decision Function**:
  Outputs from `IsolationForest.decision_function(X)` typically range from $+0.15$ (standard inlier) to $-0.25$ (extreme outlier).
- **Monotonic Normalization Mapping**:
  $$\text{normalized\_anomaly\_score} = \text{clip}\left(\frac{0.15 - \text{decision\_function}}{0.15 - (-0.25)}, 0.0, 1.0\right)$$
- **Properties**:
  - Strictly monotonic and continuous.
  - Bounded within $[0.0, 1.0]$ ($0.0 = \text{normal baseline}$, $1.0 = \text{extreme outlier}$).
  - Strictly documented as a statistical anomaly score, not an attack probability $P(\text{attack})$.

---

### 4. Zero-Day Held-Out Sensor Evaluation
- **Held-Out Sensor**: `172_234_228_9` (29,238 rows, 100% unseen during training)
- **Results**:
  - `Anomaly Score Mean`: 0.2721
  - `Anomaly Score Median`: 0.2514
  - `Anomaly Score P95`: 0.5467
  - `Outliers Flagged`: 2,904 sessions (9.93% outlier detection rate)
  - `Classification Metrics (Precision/Recall/F1)`: **N/A — ground truth unavailable**

---

### 5. Single-Vector Inference Latency Benchmark
Measured over 1,000 continuous single-vector inferences (excluding model loading and disk I/O):
- **Mean Latency**: 19.5071 ms
- **Median Latency**: 18.5782 ms
- **P95 Latency**: 24.5245 ms
- **P99 Latency**: 25.9437 ms

---

### 6. Model Artifacts Persisted
Located in `services/ml-service/app/models/`:
1. `login_anomaly_forest.joblib` (1,411.2 KB) — Serialized fitted Isolation Forest model
2. `login_feature_schema.json` (0.6 KB) — Deterministic 20-feature ordering & boundary schema
3. `login_training_metadata.json` (2.8 KB) — Complete audit trail, hyperparameters, sensor splits, and limitations

---

### 7. Known Limitations
1. Cowrie honeypot logs capture external adversary behavior, not an enterprise employee population.
2. In-production deployments must calibrate normal baseline distributions against legitimate corporate SSO/IdP telemetry.
3. Isolation Forest outputs measure behavioral anomaly, not ground-truth malice.
