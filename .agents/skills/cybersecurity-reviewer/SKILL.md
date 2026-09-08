---
name: cybersecurity-reviewer
description: Audits security posture, secret isolation, authentication boundaries, injection defenses, and safe crisis handling across all CYBERGUARD repositories and services. Activate when reviewing PRs for security vulnerabilities, inspecting authentication middleware, auditing file upload safety, or checking sensitive content boundaries.
---

# Cybersecurity Reviewer — Security Posture & Defense

This skill enforces high-standard application security, data protection, and operational safeguards across the CYBERGUARD ecosystem.

> **Authoritative Context:** See [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md) and [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md).

---

## 1. Secrets & Credentials Zero-Leak Policy
- **Scan Working Trees:** Search codebases for hardcoded credentials, JWT secrets, database connection strings, or cloud provider API keys (VirusTotal, Google Web Risk, Firebase).
- **Enforce Environment Sourcing:** All secrets must be loaded via `config/` referencing `process.env` (Node) or `os.getenv` / Pydantic `BaseSettings` (FastAPI).
- **Git Ignore Verification:** Confirm `.env`, `.env.*`, and credentials files are listed in `.gitignore` across root and all subpackages. Only sanitized `.env.example` templates may be committed.

---

## 2. Authentication & Authorization Boundaries
- **JWT Verification:** All non-public endpoints in `services/backend/src/routes/` must pass through `verifyToken` middleware.
- **RBAC Checks:**
  - `individual`: Can access only their own scans, devices, and profile data.
  - `guardian`: Can access linked at-risk user alerts and history.
  - `enterprise_admin`: Access to organization-wide telemetry, incident triage, and analytics.
- **Service Isolation:** FastAPI (`services/ml-service`) must never be exposed directly to the public internet. Ensure it binds only to `127.0.0.1` or an internal Docker network, with all ingress routed through the Node.js API Gateway.

---

## 3. Input Validation & Injection Protection
- **PostgreSQL Parameterization:** Never concatenate SQL strings. All queries in `services/backend/src/models/` must use parameterized placeholders (`$1, $2`) or a verified ORM query builder.
- **File Upload Defenses:**
  - Enforce strict size limits (e.g. 10MB maximum for image/audio analysis).
  - Validate MIME types against allowlists (`image/png`, `image/jpeg`, `audio/wav`, `audio/mpeg`).
  - Sanitize filenames and generate random UUIDs on disk to prevent directory traversal (`../`) attacks.
- **Telemetry Ingestion Validation:**
  - Reject Guard App telemetry packets missing cryptographic device signatures or valid tenant API tokens.

---

## 4. Human-Layer Boundary & Crisis Protocols
- **Blackmail & Sextortion Scope:** Per project architecture, the system must not attempt automated parsing, deep storage, or machine analysis of explicit personal extortion media.
- **Crisis Redirection:** Ensure the application detects extortion keywords and immediately surfaces official crisis response numbers (e.g., national cybercrime helplines) with clear instructions to seek law enforcement assistance.

---

## 5. Security Review Checklist
- [ ] No hardcoded keys, database URLs, or API tokens found.
- [ ] `.env` files are strictly excluded from git.
- [ ] Database queries are 100% parameterized against SQL injection.
- [ ] Internal ML service is not exposed to public ingress.
- [ ] User role permissions are strictly enforced on all administrative endpoints.
- [ ] File uploads validate size and type, and sanitize paths.
