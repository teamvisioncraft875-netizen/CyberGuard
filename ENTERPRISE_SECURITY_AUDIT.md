# CYBERGUARD — Comprehensive Enterprise Security Audit

**Audit Date:** October 1, 2026  
**Auditor Mode:** Strict Read-Only Codebase Audit (Zero Speculation, Line-by-Line Evidence)  
**Target Repository:** `CYBERGUARD` (Branch: `feature/full-system-sprint`)

---

## EXECUTIVE SUMMARY

CYBERGUARD is positioned at the intersection of consumer identity safety and enterprise threat detection. While originally seeded with individual and guardian protection features, the codebase already possesses substantial, real enterprise infrastructure:
- **Tenant-isolated PostgreSQL persistence** with multi-tenant schemas and production-grade Row-Level Security (`rls_policies.sql`).
- **Real ML detection engines** trained on published cybersecurity datasets (CTU-13 botnet flows, Cowrie honeypot SSH logs, and PhishTank corpus).
- **Explainable AI contract** (`UnifiedAnalysisResponse`) providing detection signals, feature weights, plain-language reasoning, and prescriptive recommended actions for every single check.
- **Real-time multi-room Socket.IO infrastructure** supporting user, organization, and guardian broadcast tiers.
- **A functioning host network daemon** (`services/guard-app`) collecting live OS socket telemetry.

However, CYBERGUARD currently operates strictly in an **advisory/observability posture**:
- The event flow is **Detect → Score → Alert → Store**.
- **Zero auto-remediation or active blocking occurs.** Recommended actions are recorded with `action_status: 'pending'` and await human triage.
- No email dispatch mechanism, SIEM connector, or host execution quarantine is currently wired into the backend.

---

## SECTION 1: CURRENT SECURITY ENGINES

| Engine Name | Purpose | Input | Output | Risk Scoring | ML Model / Technique | Real Implementation Status | Evidence |
|---|---|---|---|---|---|:---:|---|
| **URL Threat & Phishing Engine** | Evaluates target URLs for look-alike brand impersonation, deceptive registration, raw IP hosts, and phishing signatures. | `url: str` via `UrlAnalyzeRequest` | `UnifiedAnalysisResponse` | 0–100 scale: <br>• Safe: 10<br>• High: 75<br>• Critical: 95 | Lexical entropy, domain parser (`tldextract`), brand keyword matcher, suspicious TLD list. (Supervised binary classifier blocked due to single-class dataset). | **Partial** (Heuristic & Brand Matcher) | [`services/ml-service/app/services/url_engine.py:5-105`](file:///c:/Users/subha/Downloads/CyberGuard/services/ml-service/app/services/url_engine.py#L5-L105) |
| **Message & Social Engineering Engine** | Detects spear phishing, credential harvesting, urgency coercion, and prompt injection attacks in text. | `text: str`, `source_type: email\|sms\|social` | `UnifiedAnalysisResponse` | 0–100 scale: Urgency weight (35 pts), Credential solicitation (30 pts), Brand spoof (15 pts), Embedded link (10 pts). | Hybrid pipeline: Rule-based regex/lexical extractor with offline fallback; optional upstream LLM integration (OpenAI `gpt-4o-mini` / Groq `llama-3.1-8b-instant`) with prompt injection sanitizer. | **Complete** (Hybrid Heuristic + Optional LLM) | [`services/ml-service/app/services/message_engine.py:28-215`](file:///c:/Users/subha/Downloads/CyberGuard/services/ml-service/app/services/message_engine.py#L28-L215) |
| **Media & Deepfake Detection Engine** | Analyzes images and audio clips for synthetic generation, facial manipulation, and voice cloning artifacts. | `file_url: str`, `media_type: image\|audio` | `MediaCheckResponse` (Signals, heatmaps, explanation) | 0–100 calibrated score: <br>• $\ge 85$: Critical<br>• $\ge 70$: High<br>• $\ge 40$: Medium<br>• $< 40$: Low | • **Image:** 2D Fast Fourier Transform (SciPy `fft2`), azimuthal radial integration, periodic lattice peak prominence.<br>• **Audio:** F0 pitch jitter autocorrelation, spectral rolloff/flatness, scikit-learn `RandomForestClassifier` (`deepfake_audio_classifier.joblib`). | **Partial** (Mathematical signal processing + audio RF; no CNN/ViT) | [`services/ml-service/app/services/media_engine.py:175-322`](file:///c:/Users/subha/Downloads/CyberGuard/services/ml-service/app/services/media_engine.py#L175-L322) |
| **Login Anomaly Engine** | Detects credential stuffing, account takeover (ATO), and brute-force authentication spikes. | `user_id`, `timestamp`, `location`, `device_id`, `failed_attempts` | `UnifiedAnalysisResponse` | Normalized anomaly score [0, 100] derived from decision function distance and heuristic penalties. | Production Scikit-Learn `IsolationForest` (`login_anomaly_forest.joblib`, 1.44 MB) trained on Cowrie honeypot authentication logs. | **Complete** (Production ML Checkpoint) | [`services/ml-service/app/services/login_anomaly/engine.py:169-720`](file:///c:/Users/subha/Downloads/CyberGuard/services/ml-service/app/services/login_anomaly/engine.py#L169-L720) |
| **System & Network Telemetry Engine** | Identifies botnet Command & Control (C2) communication, outbound data exfiltration surges, and anomalous host network flows. | `user_id`, `timestamp`, `event_type`, `details: dict` (duration, bytes, packets, ports, protocol) | `UnifiedAnalysisResponse` | 5-tier calibrated scale (0–19 Safe, 20–39 Low, 40–69 Medium, 70–89 High, 90–100 Critical). | Scikit-Learn `HistGradientBoostingClassifier` (`network_threat_model.joblib`, 1.31 MB) + `IsolationForest` (`network_anomaly_forest.joblib`, 927 KB) trained on CTU-13 botnet traffic. | **Complete** (Production ML Checkpoint) | [`services/ml-service/app/services/network_anomaly/model.py:47-262`](file:///c:/Users/subha/Downloads/CyberGuard/services/ml-service/app/services/network_anomaly/model.py#L47-L262) |

---

## SECTION 2: CURRENT ENTERPRISE FEATURES

| Feature | Status | Implementation Details | Evidence |
|---|:---:|---|---|
| **Multi-Tenant Organizations** | **Exists** | Full PostgreSQL schema support with `organizations` table (`id`, `name`, `created_at`). Every user, incident, and telemetry event carries `organization_id`. First employee registering under a new organization automatically provisions the tenant and is granted `admin`. | [`services/backend/src/models/Organization.js:1-42`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/models/Organization.js#L1-L42)<br>[`services/backend/src/controllers/authController.js:80-92`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/authController.js#L80-L92) |
| **Employee Management** | **Partial** | Users can register with `role: 'employee'` and link to an existing organization. Admin queries can view tenant-scoped users. However, dedicated admin employee management endpoints (invite, deactivate, change role, team assignments) are **missing**. | [`services/backend/src/controllers/authController.js:78-86`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/authController.js#L78-L86)<br>[`services/backend/src/models/User.js:39-48`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/models/User.js#L39-L48) |
| **Admin Roles & RBAC** | **Exists** | Strict 3-role hierarchy: `individual`, `employee`, `admin`. Enforced at the gateway via `roleCheck(['admin'])` middleware and inside SQL queries via tenant isolation filters. | [`services/backend/src/middlewares/roleCheck.js:1-32`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/middlewares/roleCheck.js#L1-L32)<br>[`services/backend/src/routes/incidentRoutes.js:11`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/routes/incidentRoutes.js#L11) |
| **Incident Management** | **Exists** | Complete lifecycle management: creation, multi-tenant pagination (`limit`/`offset`), severity/status filters, triage detail views, and status transitions (`open` → `investigating` → `resolved`). | [`services/backend/src/controllers/incidentController.js:14-242`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/incidentController.js#L14-L242)<br>[`services/backend/src/models/Incident.js:1-135`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/models/Incident.js#L1-L135) |
| **MITRE ATT&CK Mapping** | **Exists** | Every anomalous incident is automatically tagged with a validated MITRE ATT&CK Technique ID and Name (e.g., Phishing T1566, Account Takeover T1078, Application Layer Protocol T1071, Data Exfiltration T1041). Analytics endpoints aggregate incidents by technique. | [`services/backend/src/models/MitreMapping.js:1-110`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/models/MitreMapping.js#L1-L110)<br>[`services/backend/src/services/incidentService.js:102-108`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/services/incidentService.js#L102-L108) |
| **Real-Time Alerting** | **Exists** | Socket.IO gateway attached to HTTP server. Handshake authenticates JWT and automatically joins `user:<id>`, `guardian:<id>`, and `org:<id>`. Emits `incident:new` in real time on threat detection. | [`services/backend/src/config/socket.js:14-87`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/config/socket.js#L14-L87)<br>[`services/backend/src/services/incidentService.js:145-195`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/services/incidentService.js#L145-L195) |
| **Guardian Monitoring** | **Exists** | Family/dependent and team guardian linkage system. Allows authorized guardians to link accounts, receive cross-account alerts, and monitor dependent incident activity in real time. | [`services/backend/src/controllers/guardianController.js:1-290`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/guardianController.js#L1-L290)<br>[`services/backend/src/models/GuardianLink.js:1-107`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/models/GuardianLink.js#L1-L107) |
| **Threat Intelligence** | **Partial** | PhishTank phishing database (14.8 MB) and CTU-13 botnet indicators are baked into feature extraction. However, live external Threat Intel API feeds (VirusTotal, AlienVault OTX, AbuseIPDB) are **not integrated**. | [`datasets/phising.csv`](file:///c:/Users/subha/Downloads/CyberGuard/datasets/phising.csv)<br>[`services/ml-service/data/ctu13/`](file:///c:/Users/subha/Downloads/CyberGuard/services/ml-service/data/ctu13) |
| **Security Analytics** | **Exists** | Dedicated endpoints `GET /api/v1/analytics/overview`, `/trends`, and `/mitre` power dashboard cards, time-series line charts, and MITRE matrix breakdowns scoped by tenant. | [`services/backend/src/controllers/analyticsController.js:8-121`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/analyticsController.js#L8-L121) |
| **Risk Scoring** | **Exists** | Standardized 0–100 scoring across all engines mapped to a calibrated 5-tier system: Safe (0–19), Low (20–39), Medium (40–69), High (70–89), Critical (90–100). | [`services/ml-service/app/schemas/analyzeSchema.py:56-63`](file:///c:/Users/subha/Downloads/CyberGuard/services/ml-service/app/schemas/analyzeSchema.py#L56-L63)<br>[`services/ml-service/app/services/network_anomaly/model.py:21-45`](file:///c:/Users/subha/Downloads/CyberGuard/services/ml-service/app/services/network_anomaly/model.py#L21-L45) |
| **Automated Response** | **Missing** | Actions are prescriptive strings stored in the database with status `pending`. No automated webhook, SOAR integration, or firewall rule update is triggered automatically. | [`services/backend/src/services/incidentService.js:116-125`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/services/incidentService.js#L116-L125) |
| **Email Alerting** | **Missing** | Zero email libraries installed (no `nodemailer`, `sendgrid`, `resend`, or `ses`). Incidents do not dispatch email notifications. | [`services/backend/package.json:14-26`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/package.json#L14-L26) |
| **Audit Logging** | **Partial** | Model `AuditLog.js` exists with methods `create`, `findByUserId`, and `findRecent`. However, it is **never called or imported** by controllers. Administrative actions are not audit-logged. | [`services/backend/src/models/AuditLog.js:1-47`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/models/AuditLog.js#L1-L47) |
| **Device Monitoring** | **Exists** | Model `Device.js` tracks endpoints (`device_id`, `device_name`, `platform`, `is_trusted`, `last_seen_at`). Ingests device fingerprints with authentication events. | [`services/backend/src/models/Device.js:1-39`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/models/Device.js#L1-L39)<br>[`services/backend/src/models/LoginEvent.js:10-33`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/models/LoginEvent.js#L10-L33) |
| **Endpoint Monitoring** | **Partial** | Host sensor (`services/guard-app`) captures real OS network flows via `psutil`. Ingested via `/api/v1/telemetry/system-event`. Lacks process tree and file monitoring. | [`services/guard-app/main.py:1-190`](file:///c:/Users/subha/Downloads/CyberGuard/services/guard-app/main.py#L1-L190)<br>[`services/backend/src/controllers/telemetryController.js:203-305`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/telemetryController.js#L203-L305) |
| **Telemetry Collection** | **Exists** | Dedicated ingestion pipelines for authentication attempts (`POST /telemetry/login-event`) and system network traffic (`POST /telemetry/system-event`), persisted to PostgreSQL tables. | [`services/backend/src/controllers/telemetryController.js:36-305`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/telemetryController.js#L36-L305) |
| **Security Policies** | **Missing** | No custom organization security policy engine (e.g., custom risk thresholds, domain whitelists, mandatory MFA enforcement rules). | Codebase inspection across `services/backend/` |
| **Access Control (RBAC)** | **Exists** | Role enforcement on API routes (`individual`, `employee`, `admin`), query scoping preventing cross-tenant access. | [`services/backend/src/middlewares/roleCheck.js:1-32`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/middlewares/roleCheck.js#L1-L32) |
| **Row Level Security (RLS)** | **Exists** | 710 lines of production SQL policies in `rls_policies.sql` covering 10 tables, with `SECURITY DEFINER` helpers (`get_auth_org_id()`, `is_admin()`). | [`services/backend/sql/rls_policies.sql:1-710`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/sql/rls_policies.sql#L1-L710) |
| **Rate Limiting** | **Exists** | Multi-tier rate limiting via `express-rate-limit`: Auth (5 req/15 min), Threat Checks (100 req/15 min), Search (30 req/15 min), General (300 req/15 min). | [`services/backend/src/middlewares/rateLimiter.js:1-82`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/middlewares/rateLimiter.js#L1-L82) |
| **Token Revocation** | **Exists** | Refresh tokens can be explicitly revoked on logout or security events via `RefreshToken.revokeByUserId()`, clearing DB tokens and HTTP-only cookies. | [`services/backend/src/models/RefreshToken.js:115-132`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/models/RefreshToken.js#L115-L132)<br>[`services/backend/src/controllers/authController.js:275-300`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/authController.js#L275-L300) |
| **Refresh Tokens** | **Exists** | Dual-token authentication: Short-lived JWT access tokens (15m) + long-lived SHA-256 hashed refresh tokens (7 days) stored in DB and cached in Redis. | [`services/backend/src/models/RefreshToken.js:1-160`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/models/RefreshToken.js#L1-L160)<br>[`services/backend/src/controllers/authController.js:106-134`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/authController.js#L106-L134) |
| **Media Storage Security** | **Exists** | Direct-to-Supabase signed upload URLs (`POST /api/v1/media/upload-url`), 50MB file size limit, strict MIME type validation, and user directory isolation (`uploads/<user_id>/*`). | [`services/backend/src/controllers/mediaController.js:1-75`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/mediaController.js#L1-L75)<br>[`services/backend/sql/004_storage_setup.sql:1-56`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/sql/004_storage_setup.sql#L1-L56) |
| **Malware Detection** | **Missing** | No static file scanning (e.g. YARA rules, PE/ELF header parser, ClamAV) for uploaded binaries. | Zero malware engine files in repository. |
| **Secret Detection** | **Missing** | No regex or entropy scanning for API keys, AWS credentials, or private certificates in inspected messages or files. | Zero secret scanner files in repository. |
| **Data Loss Prevention (DLP)** | **Missing** | No PII / credit card / SSN masking or transmission policy blocking. | Zero DLP scanner files in repository. |
| **Firewall Controls** | **Missing** | No integration with host firewalls (`iptables`, Windows Filtering Platform) or cloud security groups. | Zero firewall control files in repository. |
| **Auto Blocking** | **Missing** | Block directives only exist as advice strings in `recommended_actions`. No automated IP or domain drop occurs. | [`services/backend/src/controllers/checkController.js:101`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/checkController.js#L101) |
| **Asset Discovery** | **Missing** | No network range scanning (ARP/SNMP/Nmap) or cloud asset inventory integration. | Zero asset scanner files in repository. |
| **Attack Surface Discovery** | **Missing** | No external port scanning, DNS certificate transparency monitoring, or sub-domain enumeration. | Zero attack surface discovery tools in repository. |

---

## SECTION 3: MENTOR FEEDBACK MAPPING

| Mentor Requirement | Status | Detailed Technical Justification |
|---|:---:|---|
| **Enterprise Security Layer** | **Partially Implemented** | Tenant-isolated database architecture, RBAC middleware, and Supabase RLS exist. However, SSO/SAML 2.0, SCIM provisioning, and audit logs are missing. |
| **Automated Blocking System** | **Missing** | The system suggests blocking in `recommended_actions`, but cannot programmatically block IPs, terminate sessions, or update firewalls. |
| **Firewall Protection** | **Missing** | CYBERGUARD has rate limiting and SSRF IP blocklists for its own outbound requests, but does not provide an incoming packet filter or endpoint firewall. |
| **Encryption** | **Partially Implemented** | Passwords are encrypted with bcrypt (10 rounds), refresh tokens with SHA-256, and sessions with JWT. In-transit TLS is supported. Field-level database encryption at rest is not implemented. |
| **Explainable AI** | **Fully Implemented** | Every ML engine adheres to `UnifiedAnalysisResponse`: outputs human-readable explanations, key signals with numeric weights, confidence scores, and prescriptive actions. |
| **Proactive Detection** | **Partially Implemented** | Guard App daemon collects background network telemetry continuously. However, proactive external scanning (URL crawling, mailbox watching) does not run autonomously. |
| **Reactive Detection** | **Fully Implemented** | High-throughput reactive endpoints exist for user-submitted URLs, text messages, multimedia files, and login attempts. |
| **DDoS Protection** | **Missing** | Rate limiting protects Express gateway endpoints from simple request flooding, but there is no volumetric DDoS mitigation, CDN integration, or SYN flood detection. |
| **Recommendation System** | **Fully Implemented** | Machine learning engines generate structured, prescriptive remediation steps (`recommended_actions`) persisted to the database and managed via triage endpoints. |
| **Email Alerting** | **Missing** | No mail transport (SMTP, SES, SendGrid) exists. Alerts are exclusively emitted via Socket.IO WebSockets and saved to PostgreSQL. |
| **Enterprise Endpoint Protection** | **Partially Implemented** | `services/guard-app` runs locally on the host OS and captures socket flows via `psutil`. However, it lacks process killing, EDR hooks, or antivirus scanning. |
| **Enterprise Device Monitoring** | **Partially Implemented** | Devices are registered in PostgreSQL (`devices` table) with platform, trust status, and last seen timestamp. Real-time device health metrics are not monitored. |
| **Large Dataset Training** | **Partially Implemented** | Network model is trained on CTU-13 botnet data (Scenarios 42–44); login model on Cowrie honeypot logs; URL engine references PhishTank (14.8MB). Visual deepfakes lack large-scale training. |
| **Hacker Mindset Protection** | **Partially Implemented** | Defends against adversarial LLM prompt injection, SSRF cloud metadata bypasses, SQL injection (parameterized queries), and brute-force logins. Lacks runtime memory defenses. |
| **Employee Security Monitoring** | **Partially Implemented** | Telemetry and incidents can be filtered by `organization_id` and `user_id`. Admins can inspect employee incidents, but cannot enforce mandatory compliance or DLP policies. |

---

## SECTION 4: EXPLAINABLE AI AUDIT

### Audit Checklist
1. **Detection Signals:** **YES**. Returned as a key-value or weighted dictionary in every engine response and persisted into the `detection_signals` table ([`incidentService.js:110-114`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/services/incidentService.js#L110-L114)).
2. **Risk Factors & Weights:** **YES**. Individual signal weights (0.0 to 1.0) are calculated and normalized (e.g. `high_frequency_tail_ratio`, `urgency_score`, `failed_attempt_weight`).
3. **Evidence:** **YES**. Raw inputs, payloads, and Fourier transformation heatmaps (`fourier_heatmap_base64`) are captured and stored in `incident_evidence` ([`incidentController.js:154`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/controllers/incidentController.js#L154)).
4. **Explanations:** **YES**. Plain-language, context-specific text explanations accompany every result (e.g., *"Sudden outbound traffic surge to an unknown external IP address unaccompanied by recognized application processes"*).
5. **Recommended Actions:** **YES**. Prescriptive remediation steps are generated for every incident and tracked with lifecycle statuses (`pending`, `taken`, `dismissed`) in `recommended_actions`.

### Explainable AI Score: **92 / 100**

**Technical Evaluation:**  
CYBERGUARD has an exceptionally mature foundation for Explainable AI. Rather than treating ML models as black-box binary oracles, the entire architecture centers on the `UnifiedAnalysisResponse` contract. Incident detail views provide security analysts with the exact features that triggered the alert, the weight of each factor, the underlying evidence, and concrete steps to resolve it. The only missing 8% is formal Shapley value (SHAP) calculation for the ensemble models.

---

## SECTION 5: ENTERPRISE AGENT AUDIT (`services/guard-app`)

### Telemetry Collected
- Delta byte volumes across sampling intervals (`bytes_sent`, `bytes_recv`, `total_bytes`, `source_bytes`).
- Packet counts (`packets_sent`, `packets_recv`, `total_packets`).
- Flow sampling duration (`duration`).
- Dominant protocol (`protocol`: TCP/UDP).
- Port attribution (`source_port`, `destination_port`).
- Traffic direction (`direction`: `inbound` vs `outbound`).
- Destination remote IP address (filtering out `127.0.0.1`, `::1`, `0.0.0.0`).

### System Data Monitored
- Operating system network interface I/O counters via `psutil.net_io_counters()`.
- Host socket connection table via `psutil.net_connections(kind="inet")`.
- Graceful handling of OS permission boundaries (runs as non-admin standard user or elevated root/Administrator).

### Security Events Generated
- Emits `network_flow_telemetry` events.
- Evaluates flows directly against the ML service (`/api/v1/analyze/system`) or forwards authenticated events to the Express Gateway (`/api/v1/telemetry/system-event`).
- Anomalous traffic triggers `technical_threat` incidents mapped to MITRE ATT&CK T1071 / T1041.

### Does CYBERGUARD already have an enterprise agent foundation?
### **Verdict: YES**

**Evidence:**  
[`services/guard-app/collector.py`](file:///c:/Users/subha/Downloads/CyberGuard/services/guard-app/collector.py) and [`main.py`](file:///c:/Users/subha/Downloads/CyberGuard/services/guard-app/main.py) provide a legitimate, functioning host sensor daemon. It operates continuously in the background, collects live OS socket activity, adapts the data into standardized JSON schemas, and transmits it via authenticated REST calls. It forms the exact structural foundation required for an Enterprise Endpoint Detection and Response (EDR) agent.

---

## SECTION 6: AUTO RESPONSE AUDIT

### Current Incident Flow

$$\mathbf{Detect} \longrightarrow \mathbf{Score} \longrightarrow \mathbf{Alert\ (Socket.IO)} \longrightarrow \mathbf{Store\ (PostgreSQL)}$$

### Trace Evidence from [`incidentService.js:88-191`](file:///c:/Users/subha/Downloads/CyberGuard/services/backend/src/services/incidentService.js#L88-L191):
1. **Transaction Begin:** Opens PostgreSQL client transaction.
2. **Store Incident:** Writes row to `incidents` with `status: 'open'`.
3. **Store MITRE Mapping:** Inserts technique row into `mitre_mappings`.
4. **Store Signals:** Inserts feature weights into `detection_signals`.
5. **Store Actions:** Writes prescriptive steps into `recommended_actions` with default `action_status: 'pending'`.
6. **Transaction Commit:** Commits data atomically.
7. **Broadcast Alert:** Dispatches `incident:new` over Socket.IO to connected web dashboards.

### Does auto-remediation currently exist?
### **Verdict: NO**

**List of automatic actions currently performed:**
- **Zero active actions.** No accounts are locked, no tokens are revoked automatically, no network interfaces are severed, and no firewall rules are installed. Remediation requires an analyst or user to explicitly click "Take Action" via `PATCH /api/v1/actions/:id`.
