---
name: threat-model-reviewer
description: Evaluates threat coverage across CYBERGUARD's 6 threat scenarios, audits MITRE ATT&CK technique mapping, balances false-positive/negative tradeoffs, and verifies heuristic weights. Activate when reviewing detection logic, tuning scoring thresholds, adding new attack vectors, or preparing competition evaluation benchmarks.
---

# Threat Model Reviewer — Scenario Auditing & MITRE ATT&CK

This skill evaluates threat coverage, heuristic scoring weights, and industry taxonomy mapping across the **six core threat scenarios** in CYBERGUARD.

> **Authoritative Context:** See [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md) and [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md).

---

## 1. Six Threat Scenarios & MITRE ATT&CK Taxonomy

| Scenario | Threat Category | Assigned Engine | Primary MITRE Technique | Heuristic / ML Indicators |
|---|---|---|---|---|
| **1** | Phishing & Social Scams | `Content Analysis` + `URL Engine` | `T1566` (Phishing) | Urgency cues, fake authorities, financial pressure, credential harvesting links. |
| **2** | Deepfake Media | `Multimedia Authenticity` | `T1586.002` (Compromise Accounts: Synthetic Persona) | Facial artifact distortions, frequency domain blurs, synthetic voice spectral features. |
| **3** | Digital Impersonation | `Identity/Impersonation` | `T1585` (Establish Accounts) / `T1566.002` | Typo-squatted domains, spoofed display names, SPF/DKIM failures, logo mismatch. |
| **4** | Credential Theft & ATO | `Login/Behavioural Anomaly` | `T1078` (Valid Accounts) | Rapid geo-velocity anomalies, unknown device fingerprint, off-hours logins, brute force spikes. |
| **5** | Malicious URLs | `URL/Website Analysis` | `T1204.001` (User Execution: Malicious Link) | Zero-day domain age (<14 days), low VirusTotal score, high Levenshtein distance to known brands. |
| **6** | Technical Threats | `System Behaviour Engine` | `T1059` (Command & Scripting) / `T1071` | Sudden spikes in outbound network sockets, unauthorized background process spawning. |

---

## 2. Risk Tier Calibration & Threshold Review

Threat models must score between 0 and 100, mapped strictly into the five standard tiers:

```
[0 ────────── 19]  Safe      -> Benign traffic, verified signatures, trusted origins.
[20 ───────── 39]  Low       -> Minor anomalies (e.g., new device) without malicious intent.
[40 ───────── 69]  Medium    -> Ambiguous signals, unverified new domains, mild urgency text.
[70 ───────── 89]  High      -> Strong malicious indicators, deepfake artifact detection.
[90 ──────── 100]  Critical  -> Active credential harvesting, confirmed voice clone, ATO cluster.
```

### Reviewing Heuristic Weighting
When tuning engine weights:
- **Heuristic Overrides:** A known blacklisted URL or a confirmed SPF/DKIM hard-fail for a brand claim must automatically elevate the threat score to `>= 70` (High), regardless of LLM text politeness.
- **Explainability Check:** The explanation string must explicitly call out the weighted factors that triggered the classification:
  - *Poor:* `"This text is dangerous."`
  - *Standard:* `"High Risk (86/100): Sender domain closely mimics 'paypal-support.com' (registered 3 days ago), and the message demands immediate credential verification under threat of account suspension."`

---

## 3. False Positive vs. False Negative Tradeoff Strategy
- **In Hackathon Demonstrations:** Missing a blatant scam in a live test is fatal to judge perception. Favor recall slightly over precision for blatant indicators (e.g. newly registered domains mimicking banks), but prevent trivial false positives on benign corporate newsletters.
- **In Enterprise Scenarios:** Avoid automated blocking on `Medium` risk. Recommend review or multi-factor authentication rather than halting user productivity.

---

## 4. Threat Review Audit Checklist
- [ ] Every detected incident links to a valid MITRE ATT&CK technique ID.
- [ ] Explanations mention specific observables (e.g., domain age, header mismatch, audio artifact).
- [ ] Scoring strictly aligns with 0–100 ranges and standard 5-tier labels.
- [ ] Recommended actions provide operational remediation, not passive notices.
- [ ] Extortion/blackmail edge cases redirect to national crisis reporting authorities.
