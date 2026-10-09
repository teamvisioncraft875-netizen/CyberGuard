# CYBERGUARD — Golden Demonstration & Verification Suite

The **Golden Demonstration & Verification Suite** provides a curated, reproducible, and non-destructive verification layer for CYBERGUARD's 11 production machine learning and threat intelligence detection engines.

This suite exercises production inference pathways using representative benign and malicious samples sourced from authentic benchmarks, public datasets, and forensic fixtures. It guarantees that models, heuristics, operating thresholds, and security guardrails function with high fidelity for live testing, competition demonstrations, and demo-video recording.

---

## 1. Directory Structure

```text
datasets/golden_demonstration/
├── README.md                          # Documentation and operating guide (this file)
├── showcase_manifest.json             # Canonical JSON manifest with SHA-256 signatures
├── audio_deepfake/                    # Real & synthetic speech clips (FLAC/WAV)
├── visual_deepfake/                   # Authentic and manipulated optical face frames (PNG)
├── url_threat/                        # Defanged benign and phishing URL records (JSON)
├── message_phishing/                  # Legitimate corporate emails & credential lures (JSON)
├── login_anomaly/                     # Baseline & brute-force authentication events (JSON)
├── network_telemetry/                 # Benign web flows & botnet DDoS/C2 telemetry (JSON)
├── malware/                           # Safe PE binaries & EMBER LightGBM feature vectors (JSON/EXE)
├── edr_behavior/                      # Linux kernel syscall and process execution chains (JSON)
├── false_positive/                    # BETH security alerts with false-positive disposition (JSON)
├── correlation/                       # Multi-alert intrusion clusters & background noise (JSON)
└── recommendation/                    # Incident context schemas for ranked SOC response (JSON)
```

---

## 2. Dataset Provenance & Licensing

All samples in this suite are derived from established security benchmarks, authorized corporate baselines, or non-hazardous forensic fixtures:

| Engine | Source Dataset | Origin / Provenance | License / Usage Notes |
| :--- | :--- | :--- | :--- |
| **Audio Deepfake** | `datasets/deepfake-audio-detection` | Podonos Benchmark & In-the-Wild YouTube audio clips with Kokoro TTS / Hume AI clones | Research & evaluation use |
| **Visual Deepfake** | `datasets/FaceForensics` | FaceForensics++ (TUM/Google) original optical frames, DeepFakes, NeuralTextures | FaceForensics Terms of Use |
| **URL Threat** | `datasets/Malicious url` | PhishTank / Verified Online feed and curated legitimate enterprise documentation | Educational & defensive security research |
| **Message Phishing** | `datasets/Phishing` | Nazario Phishing Corpus, CEAS 2008, and Enron Email Dataset | Public domain / Open research corpus |
| **Login Anomaly** | `datasets/logs_dataset` | Cowrie SSH/Telnet honeypot logs and baseline authentication telemetry | Open security telemetry |
| **Network Telemetry** | `datasets/ctu13` | CTU-13 University Botnet Dataset (Scenarios 42–45) | Creative Commons Attribution |
| **Malware** | `datasets/malware/ember2018` | EMBER 2018 Static PE benchmark test partition & signed Windows binaries | CC0 1.0 Universal / PE Header Analysis |
| **EDR Behavior** | `datasets/BETH` | BETH Linux Kernel & Syscall Telemetry Dataset (MIT/TUM) | Open defensive cybersecurity benchmark |
| **False Positive** | `datasets/BETH` | BETH labelled host telemetry alert instances | Open defensive cybersecurity benchmark |
| **Correlation** | `datasets/ctu13` | Multi-stage botnet attack progression flows (DNS query -> C2 beacon -> Data exfiltration) | Open research dataset |
| **Recommendation**| `datasets/Recommendation`| Incident Response Playbook dataset aligned with MITRE ATT&CK framework | Internal enterprise defense framework |

---

## 3. Real Benchmark Records vs. Software-Test Fixtures

To ensure transparency and prevent simulated evidence:

- **`real_benchmark`**: Directly extracted from authentic public security datasets (e.g., audio FLAC files from the deepfake audio benchmark, optical frames from FaceForensics++, PE feature vectors from EMBER, network flows from CTU-13, syscall chains from BETH).
- **`approved_fixture`**: Curated enterprise benign records (e.g., Microsoft signed `notepad.exe`, legitimate internal corporate IT announcements, defanged known phishing URLs) validated for production inference.
- **`synthetic_software_test`**: Small unit-test fixtures used strictly in isolated tests (e.g. testing duplicate ID rejection or hash tamper detection). Never used in the primary golden showcase manifest.

---

## 4. Manifest Schema (`showcase_manifest.json`)

Each sample entry in `showcase_manifest.json` conforms to the following schema:

```json
{
  "sample_id": "AUD-REAL-001",
  "engine": "deepfake_audio",
  "engine_version": "v1.0.0",
  "sample_type": "benign",
  "source": "datasets/deepfake-audio-detection",
  "provenance": "deepfake-audio-detection/manifest.csv [raw/real/yt_0003_part_001.flac]",
  "ground_truth": "genuine",
  "expected_verdict": "SAFE",
  "expected_risk_range": [0, 20],
  "mitre_context": "None",
  "rationale": "Natural human pitch variation, authentic spectral decay, non-cloned voice.",
  "payload_type": "file_path",
  "payload_path": "datasets/golden_demonstration/audio_deepfake/yt_0003_part_001.flac",
  "sha256": "b2687aa1d1e7bb7d392715d7288d42289787e11d5346cdcab6c7aa386b4cd917",
  "fixture_kind": "real_benchmark",
  "safety_notes": "Acoustic audio file; offline forensic evaluation only."
}
```

### Required Fields:
- `sample_id`: Unique, stable sample identifier (e.g. `AUD-REAL-001`, `URL-THR-001`).
- `engine`: Authoritative engine name matching CYBERGUARD registry.
- `engine_version`: Engine release version.
- `sample_type`: Classification category (`benign` or `threat`).
- `source`: Dataset origin.
- `provenance`: File path, split, or dataset row reference.
- `ground_truth`: Authoritative label (`genuine`, `manipulated`, `safe`, `malicious`, etc.).
- `expected_verdict`: Expected decision tier (`SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, or engine-specific action code).
- `expected_risk_range`: Accepted numeric score interval `[min, max]` when calibrated, or `null`.
- `mitre_context`: Applicable MITRE ATT&CK tactic/technique mapping or `"None"`.
- `rationale`: Concise technical justification.
- `payload_type`: Format of payload (`file_path`, `structured_json`, `binary_base64`).
- `payload_path`: Repository-relative path to asset file.
- `sha256`: Cryptographic SHA-256 hash of payload file.
- `fixture_kind`: Provenance classification (`real_benchmark` or `approved_fixture`).
- `safety_notes`: Operational safety constraints.

---

## 5. Running the Golden Showcase Demo

### Default Run (All 11 Engines, 102 Samples):
```powershell
python scripts/run_golden_showcase_demo.py
```

### Filter by Engine:
```powershell
# Run only audio deepfake verification
python scripts/run_golden_showcase_demo.py --engine deepfake_audio

# Run only EDR behavior engine
python scripts/run_golden_showcase_demo.py --engine edr_behavior

# Run only malware static analysis
python scripts/run_golden_showcase_demo.py --engine malware
```

### Limit Sample Count:
```powershell
python scripts/run_golden_showcase_demo.py --limit 10
```

### Custom Report Output:
```powershell
python scripts/run_golden_showcase_demo.py --output artifacts/golden_showcase/demo_eval.json
```

---

## 6. How Verdicts and Risk Ranges Are Verified

The demonstration runner implements deterministic exemplar verification without model overrides:

1. **Cryptographic Pre-flight**: Every payload asset is read from disk and its SHA-256 hash is compared against `showcase_manifest.json`. If a file is missing or tampered with, the runner exits immediately with code `1`.
2. **Production Inference Path**: The payload is dispatched to the production service interface (e.g., `analyze_message`, `analyze_url`, `analyze_media`, `analyze_login`, `analyze_system`, `analyze_malware_bytes`, `EDRBehaviorEngine.analyze`, `FalsePositiveEngine.analyze`, `correlate_events`, `recommend_actions`).
3. **Verdict Concordance**: The actual model verdict is compared to `expected_verdict`. If an accepted risk interval is defined (`expected_risk_range`), the continuous score is checked against `[min, max]`.
4. **Honest Reporting**: Actual model predictions are never overridden or modified. If a sample receives an unexpected verdict, it is flagged as `MISMATCH` in the scorecard while preserving the real explanation, latency, and signals.
5. **Human Approval Safeguards**: Incident recommendation outputs are verified to confirm that high-impact actions (such as `isolate_device`, `kill_process`, `force_password_reset`) require human approval (`requires_approval == True`).

---

## 7. Safety Restrictions

- **Zero Dangerous Execution**: Static PE binaries and scripts are analyzed as inert feature byte arrays. Binaries are never executed or spawned.
- **Offline URL Processing**: Malicious URLs are analyzed lexically by regex, TLD, brand similarity, and Shannon entropy. No network connection is made to external domains.
- **No Production Mutation**: Models are never retrained, re-fitted, or modified by this demonstration suite. All model weights and metadata are read-only.
- **Advisory Recommendations**: Recommended incident response actions are advisory only; no host containment or network disconnection is executed automatically.
