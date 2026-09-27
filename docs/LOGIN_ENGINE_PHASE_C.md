# CYBERGUARD — Login & Authentication Anomaly Detection Engine
## Phase C: Real Model Integration & Login Analysis Engine Report

This document records the architectural integration, model loading, feature schema validation, state management, latency benchmarks, and fail-loud security behaviors implemented for **Phase C** of the CYBERGUARD Login Anomaly Detection Engine.

> **CRITICAL ARCHITECTURAL FACT**:
> The current engine uses the **Isolation Forest behavioral anomaly detector**. **No supervised attack probability is produced** because Phase B found no defensible ground-truth labels in the Cowrie honeypot dataset. The engine operates exclusively on statistical outlier analysis and deterministic behavioral signal attributions.

---

### 1. Model Loading Architecture
- **Artifacts Loaded**:
  - `services/ml-service/app/models/login_anomaly_forest.joblib` (1,411.2 KB)
  - `services/ml-service/app/models/login_feature_schema.json` (0.6 KB)
  - `services/ml-service/app/models/login_training_metadata.json` (2.8 KB)
- **Singleton Pattern**:
  `get_login_anomaly_engine()` provides safe, lazy-loaded initialization protected by a `threading.Lock`. Model deserialization occurs strictly **once** across the process lifecycle; subsequent inference requests reuse the in-memory ensemble without re-reading from disk.
- **Fail-Loud Guarantee**:
  If a model checkpoint is missing, corrupted, or incompatible, the engine raises an explicit `FileNotFoundError` or `RuntimeError`. It **never** falls back to a false "Safe" verdict.

---

### 2. Feature Contract & Schema Validation
The inference pipeline strictly enforces the 20-dimensional feature ordering defined in Phase A and Phase B:

```text
1.  failed_attempts_count     11. login_hour
2.  successful_attempts_count 12. login_hour_sin
3.  total_attempts            13. login_hour_cos
4.  attempt_frequency_hz      14. day_of_week
5.  unique_usernames_count    15. proto_ssh
6.  unique_usernames_ratio    16. proto_telnet
7.  password_entropy          17. proto_other
8.  unique_password_count     18. has_client_version
9.  password_reuse_ratio      19. has_hassh
10. session_duration          20. success_after_failure
```

- **Validation Rules**:
  - Missing features $\to$ `ValueError`
  - Any `NaN` values $\to$ `ValueError`
  - Any `Infinite` values $\to$ `ValueError`

---

### 3. Anomaly-Score Semantics & Normalization
The Isolation Forest `decision_function(X)` is transformed into a continuous, monotonic, bounded anomaly score $A \in [0.0, 1.0]$ using the exact Phase B calibration:

$$\text{anomaly\_score} = \text{clip}\left(\frac{0.15 - \text{decision\_score}}{0.15 - (-0.25)}, 0.0, 1.0\right)$$

- $0.0$: Inlier conforming to baseline normal activity.
- $1.0$: Extreme statistical outlier.
- **Terminology**: This metric is strictly an **anomaly score**, not an attack probability $P(\text{attack})$.

---

### 4. CYBERGUARD 5-Tier Risk Mapping
Normalized anomaly scores are mapped to the standard CYBERGUARD 5-tier risk scale:

$$\text{risk\_score} = \text{round}(\text{anomaly\_score} \times 100)$$

| Risk Score Range | Risk Level | Description | Recommended Remediation Action |
| :---: | :---: | :--- | :--- |
| **0 – 19** | `Safe` | Conforms to baseline operational patterns | No action required; log for audit trail |
| **20 – 39** | `Low` | Minor behavioral variance detected | Monitor authentication activity for subsequent anomalies |
| **40 – 69** | `Medium` | Noticeable timing or failure deviation | Review authentication source context and attempt rate |
| **70 – 89** | `High` | Elevated failure velocity or spray patterns | Apply rate-limiting; prompt user for MFA challenge |
| **90 – 100** | `Critical` | Severe anomaly or repeated failure breach | Enforce immediate MFA; apply temporary rate-limit barrier; alert SOC |

---

### 5. Unavailable Signals
To preserve empirical integrity, unmeasured features are **never** fabricated:
- `supervised_probability`: Explicitly `None` (no fake classification confidence).
- `is_new_device`: Explicitly `None` (no enterprise device inventory in honeypot logs).
- `impossible_travel`: Explicitly `None` (unsupported by Cowrie telemetry stream).

---

### 6. State Management: Bounded Rolling Window
Features such as attempt velocity (`attempt_frequency_hz`), unique usernames, and session duration require temporal aggregation:
- **Class**: `BoundedLoginSessionTracker`
- **Rolling Window**: 300 seconds (5 minutes), identical to Phase A.
- **Aggregation Key**: `src_ip` (or `user_id` / `session_id`).
- **Memory Ceiling**: Bounded to 5,000 active sessions with FIFO/LRU eviction.
- **TTL Pruning**: Automatic cleanup of sessions older than 300 seconds on every event.
- **Concurrency**: Thread-safe execution guarded by `threading.Lock`.

---

### 7. Password Privacy & Security
- Raw passwords are **never stored, never logged, and never included in API responses**.
- If a password is provided in live telemetry, character Shannon entropy $H(X)$ is computed immediately and the raw string is discarded.

---

### 8. Inference Latency
Benchmarked over 1,000 live end-to-end `analyze()` pipeline evaluations:
- **Mean Latency**: 21.38 ms
- **Median Latency**: 20.56 ms
- **P95 Latency**: 28.67 ms
- **P99 Latency**: 32.29 ms

---

### 9. Test Coverage
Phase C adds **14 unit and integration tests** in `services/ml-service/tests/test_login_engine_phase_c.py`:
1. `test_production_model_loads`: Verifies disk artifact deserialization.
2. `test_valid_login_analysis`: Validates `UnifiedAnalysisResponse` schema conformance.
3. `test_anomaly_score_bounds`: Verifies scores are bounded in $[0.0, 1.0]$.
4. `test_no_fake_supervised_probability`: Confirms absence of fabricated supervised outputs.
5. `test_feature_ordering_conformance`: Validates column ordering against `login_feature_schema.json`.
6. `test_nan_input_fails_loud`: Confirms `ValueError` on NaN input.
7. `test_infinite_input_fails_loud`: Confirms `ValueError` on Infinite input.
8. `test_missing_model_fails_loud`: Confirms fail-loud behavior when model is absent.
9. `test_corrupted_model_fails_loud`: Confirms fail-loud behavior on corrupt checkpoint.
10. `test_deterministic_result`: Verifies identical outputs for identical requests.
11. `test_explanation_accuracy`: Verifies explanations cite only observed indicators.
12. `test_unavailable_signals_reported_as_none`: Confirms unsupported signals are `None`.
13. `test_risk_mapping_boundaries`: Verifies 5-tier risk boundaries.
14. `test_model_loaded_once`: Verifies in-memory singleton reuse.

**Total Test Suite**: **160 tests passing (100% GREEN)**.
