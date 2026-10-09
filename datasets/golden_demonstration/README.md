# CYBERGUARD Golden Showcase Datasets & Evaluation Testcases

This directory contains standardized, curated evaluation inputs across CYBERGUARD's detection engines.
All records are format-compatible with `services/ml-service` and gateway APIs (`services/backend`).

## Dataset Directory Structure

```
datasets/golden_demonstration/
├── README.md                                 # Source, license, metadata documentation
├── urls/
│   └── urls.json                             # Labeled benign, suspicious, and typosquatted URLs
├── messages/
│   └── messages.json                         # Labeled SMS/Email social engineering lures and legitimate notices
├── login_events/
│   └── login_events.json                     # Anomaly detection testcases (geo-velocity, device shifts)
├── secrets/
│   └── secrets.json                          # Synthetic test credential patterns
├── network_flows/
│   └── network_flows.json                    # Traffic flow summaries and DDoS threshold test cases
└── scenarios/
    └── enterprise_multi_stage_incident.json  # Correlated end-to-end security walkthrough scenario
```

## Data Provenance, Licensing & Safety Notice

1. **URLs**: Sourced from public research benchmarks (PhishTank, OpenPhish archives, Tranco Top 1M benign list). All live URLs are sanitized, defanged, and mapped to reserved/documentation domains (`.example`, `.test`, `.xyz`) where necessary to prevent accidental navigation.
2. **Messages**: Representative SMS/Email phishing and transactional notification templates modeled after CERT-In and RBI banking advisory patterns. Synthetic and devoid of PII.
3. **Secrets**: 100% synthetic, non-functional placeholder credential strings designed to test regex and Shannon entropy heuristics. None of these tokens can authenticate to any service.
4. **Login Events & Network Flows**: Generated telemetric records reflecting real-world statistical distributions for baseline training and threshold violation detection.
5. **No Live Exploits or Real Malicious Payloads**: In compliance with security standards, all samples are safe evaluation inputs.
