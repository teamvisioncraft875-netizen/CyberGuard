# CYBERGUARD — Login & Authentication Anomaly Detection Engine
## Phase A: Cowrie Dataset Preprocessing & Feature Engineering Report

This document records the data extraction, session reconstruction, feature engineering, and strict sensor-level holdout split executed for **Phase A** of the CYBERGUARD Login Anomaly Detection Engine.

---

### 1. Dataset Source & Type
- **Source**: `datasets/logs_dataset/` containing honeypot telemetry from 10 distinct Cowrie sensors.
- **Volume**: 83 JSONL log files totaling **1,400.52 MB** (~1.4 GB) and **3,308,028 raw JSON events**.
- **Nature**: Adversarial honeypot traffic capturing automated SSH and Telnet brute-force attacks, dictionary attacks, and credential stuffing.

### 2. Cowrie Event Types Discovered
Through streaming inspection, the following event IDs were identified and extracted:
- `cowrie.session.connect`: Connection initiation (`src_ip`, `dst_ip`, `dst_port`, `protocol`, `session`, `timestamp`).
- `cowrie.login.failed`: Unsuccessful authentication attempt (`username`, `password`, `session`, `src_ip`, `timestamp`).
- `cowrie.login.success`: Successful authentication attempt (`username`, `password`, `session`, `src_ip`, `timestamp`).
- `cowrie.client.version`: SSH client banner/version fingerprint (`version`, `session`, `timestamp`).
- `cowrie.client.kex`: Key exchange algorithm list & SSH client HASSH fingerprint (`hassh`, `session`, `timestamp`).
- `cowrie.session.closed`: Connection teardown (`duration`, `session`, `timestamp`).

### 3. Feature Definitions
The generated dataset contains **20 numerical feature columns** and **3 metadata tracking columns**:

| Column Name | Type | Description | Rationale |
| :--- | :--- | :--- | :--- |
| `sensor_id` | Metadata (str) | Identifier of the Cowrie sensor (e.g. `172_234_228_9`) | Enables strict sensor-level train/test holdout splitting. |
| `session_id` | Metadata (str) | Unique honeypot session identifier | Session-level aggregation key. |
| `src_ip` | Metadata (str) | Originating IPv4/IPv6 address of the connection | Host behavioral tracing and grouping. |
| `failed_attempts_count` | Feature (int) | Number of failed logins (`cowrie.login.failed`) in session | Core indicator of brute-force and dictionary attacks. |
| `successful_attempts_count` | Feature (int) | Number of successful logins (`cowrie.login.success`) in session | Identifies successful compromise or single-try access. |
| `total_attempts` | Feature (int) | Sum of failed and successful login attempts | Overall authentication pressure within the session. |
| `attempt_frequency_hz` | Feature (float) | Total attempts divided by effective duration (`max(duration, 1.0)`) | Distinguishes rapid automated scripts from slow attempts. |
| `unique_usernames_count` | Feature (int) | Count of distinct usernames attempted | Detects multi-user dictionary attacks. |
| `unique_usernames_ratio` | Feature (float) | Unique usernames / max(total_attempts, 1) | Highlights credential spraying across diverse accounts. |
| `password_entropy` | Feature (float) | Mean Shannon entropy $H(X) = -\sum p_i \log_2(p_i)$ of attempted passwords | Captures algorithmic vs simple/dictionary passwords. |
| `unique_password_count` | Feature (int) | Count of distinct passwords attempted | Distinguishes single-password spraying from dictionary lists. |
| `password_reuse_ratio` | Feature (float) | Ratio of repeated password attempts within the session | Identifies repetitive password brute-forcing. |
| `session_duration` | Feature (float) | Total connection duration in seconds | Short burst vs prolonged interactive session distinction. |
| `login_hour` | Feature (float) | Hour of the first event (0.0 to 23.98) | Raw temporal context. |
| `login_hour_sin` | Feature (float) | $\sin(2\pi \times \text{login\_hour} / 24.0)$ | Continuous cyclical time representation for ML models. |
| `login_hour_cos` | Feature (float) | $\cos(2\pi \times \text{login\_hour} / 24.0)$ | Continuous cyclical time representation (handles 23:59 -> 00:00). |
| `day_of_week` | Feature (int) | Day index (0 = Monday, 6 = Sunday) | Weekly seasonality / off-peak access patterns. |
| `proto_ssh` | Feature (int) | Binary flag (1 if protocol is SSH, else 0) | Protocol differentiation. |
| `proto_telnet` | Feature (int) | Binary flag (1 if protocol is Telnet, else 0) | Protocol differentiation. |
| `proto_other` | Feature (int) | Binary flag (1 if unknown/custom protocol, else 0) | Fallback protocol isolation. |
| `has_client_version` | Feature (int) | Binary flag (1 if SSH version banner was advertised, else 0) | Client fingerprint completeness. |
| `has_hassh` | Feature (int) | Binary flag (1 if client HASSH fingerprint was negotiated, else 0) | High-fidelity cryptographic fingerprint presence. |
| `success_after_failure` | Feature (int) | Binary flag (1 if both failures and success occurred, else 0) | Attack signature: repeated failures followed by breach. |

### 4. Aggregation Strategy
- **Session-level Reconstruction**: Grouping is performed by `(sensor_id, session_id)`. All connection, negotiation, authentication, and teardown events belonging to a session are assembled in memory.
- **Chronological File Streaming**: Daily rotated log files (`cowrie.json.YYYY-MM-DD`) are processed in historical order followed by active `cowrie.json`.
- **Filtering**: Sessions with at least one authentication attempt (`failed_logins + successful_logins > 0`) are extracted for the login anomaly dataset, separating pure port scanning from credential attacks.

### 5. Missing-Value & Division Safety Handling
- **Zero Duration**: If `session_duration` is 0.0 or unavailable from `session.closed`, duration is derived from timestamps. For rate computations (`attempt_frequency_hz`), an epsilon floor of `1.0s` is enforced: `total_attempts / max(duration, 1.0)`.
- **Empty Passwords/Usernames**: Safely defaulted to `password_entropy = 0.0`, `unique_password_count = 0`, and `password_reuse_ratio = 0.0`.
- **Missing Protocol/Fingerprints**: Defaulted to `proto_other = 1`, `has_client_version = 0`, `has_hassh = 0`.
- **Result**: Zero NaN values and zero Infinite values across all 480,276 generated feature rows.

### 6. Label Limitations & Honeypot Scope
- **Adversarial Population**: The Cowrie dataset captures traffic directed at public honeypot sensors. It does **NOT** represent an enterprise employee baseline.
- **No Synthetic Benign Fabrication**: Per the Phase A specification, synthetic "normal employee" records were **NOT** fabricated.
- **Unlabeled Anomaly Framing**: Phase B will evaluate this dataset via unsupervised anomaly modeling (Isolation Forest) and attack signature modeling against held-out zero-day sensors.

### 7. Strict Sensor-Level Split Strategy
To evaluate real-world transferability to previously unseen sensor locations without temporal or spatial leakage:
- **Held-out Sensor**: `172_234_228_9` (Sensor directory: `cowrie-logs-172_234_228_9`).
- **Training Sensors (9 sensors)**:
  `139_162_38_249`, `172_233_11_134`, `172_234_123_193`, `172_234_178_211`, `20_39_206_37`, `40_126_227_168`, `45_79_13_34`, `4_222_19_165`, `74_226_238_175`.
- **Testing Sensor (1 sensor)**:
  `172_234_228_9`.

### 8. Data Leakage Precautions
- **Strict Disjoint Partition**: $\text{Train Sensors} \cap \text{Test Sensors} = \emptyset$.
- **Zero Inter-Sensor State**: Session reconstruction and rate aggregations are isolated strictly per sensor.
- **No Forward-Looking Information**: All session metrics are bounded to the session window; no future global statistics are used.

### 9. Generated Artifacts
- `services/ml-service/data/login/train_login_features.parquet` (13.07 MB, 451,038 rows)
- `services/ml-service/data/login/test_login_features.parquet` (1.07 MB, 29,238 rows)
- `services/ml-service/app/utils/cowrie_preprocessor.py` (Streaming preprocessor engine)
- `services/ml-service/tests/test_cowrie_preprocessor.py` (13 unit tests)


### 10. Known Limitations
- Honeypot logs reflect automated attack behavior; enterprise benign telemetry must be acquired or modeled via outlier baselines.
- Single failed logins should not be classified as high-confidence malicious without temporal contextualization (e.g. employee typo vs brute-force burst).
- Passwords are discarded immediately after computing entropy and uniqueness statistics; no plaintext credentials are stored or exposed.
