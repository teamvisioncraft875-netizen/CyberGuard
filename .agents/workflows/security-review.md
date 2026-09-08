# Workflow: security-review

> **Objective:** Conduct a systematic security and privacy audit of the CYBERGUARD codebase to prevent credential leaks, insecure endpoints, injection vulnerabilities, and improper data handling.

---

## 1. Secrets & Credentials Audit
Check the working tree for exposed secrets before committing:

1. **Scan for Hardcoded Tokens & Keys:**
   - Search for strings matching: `api_key`, `secret`, `jwt_secret`, `password`, `postgres://`, `Bearer `, `PRIVATE KEY`.
   - Verify that all sensitive values are retrieved exclusively from `process.env` (Node) or `os.getenv` / `pydantic.BaseSettings` (FastAPI).
2. **Verify `.gitignore` Compliance:**
   - Ensure `.env`, `.env.local`, `.env.production` are ignored in root, `services/backend/`, `services/ml-service/`, `apps/web/`, and `apps/mobile/`.
   - Verify that only sanitized `.env.example` templates exist in the repository.

---

## 2. Authentication & Authorization Boundaries

1. **Node.js API Gateway (Public Perimeter):**
   - Verify that all sensitive routes (`/api/v1/incidents`, `/api/v1/telemetry`, `/api/v1/users`, `/api/v1/admin`) attach `verifyToken` middleware.
   - Verify Role-Based Access Control (RBAC): Ensure enterprise SOC endpoints require `role: "enterprise_admin"` and Guardian endpoints require `role: "guardian"`.
2. **FastAPI ML Service (Internal Perimeter):**
   - Ensure FastAPI is strictly bound to internal networking (e.g., `127.0.0.1` or internal Docker network).
   - Ensure clients (Web and Mobile) **never** access FastAPI directly without going through the Node.js Gateway.
3. **WebSocket Authentication:**
   - Verify that WebSocket connections authenticate clients (via handshake token/query param) before joining broadcast rooms.

---

## 3. Input Validation & Injection Protection

1. **Database Queries (PostgreSQL):**
   - Verify that all SQL queries use parameterized queries (`$1, $2`) or ORM abstractions.
   - **Never allow raw string concatenation in database queries.**
2. **File & Media Uploads:**
   - Verify file upload size limits (e.g. max 10MB for images/audio).
   - Validate file MIME types (`image/jpeg`, `image/png`, `audio/wav`, `audio/mp3`).
   - Sanitize filenames to prevent directory traversal (`../`) attacks when storing temporary analysis files.
3. **Guard App Telemetry Ingestion:**
   - Ensure the telemetry ingestion endpoint validates device identifiers and rate-limits incoming sensor packets to prevent telemetry spoofing or flooding.

---

## 4. Human-Layer & Sensitive Content Boundary
- **Blackmail / Sextortion Policy:**
  - Verify the system does not attempt automated deep-parsing or persistent storage of explicit personal imagery/content.
  - If detected, ensure the response safely redirects the user to designated national reporting authorities (e.g., cybercrime helplines) per project architecture guidelines.

---

## 5. Security Audit Sign-off Checklist
- [ ] No hardcoded keys, tokens, or connection strings found.
- [ ] `.env` is uncommitted and protected by `.gitignore`.
- [ ] Protected endpoints enforce JWT verification and correct role checks.
- [ ] File uploads validate size, extension, and MIME type.
- [ ] Database queries are 100% parameterized.
