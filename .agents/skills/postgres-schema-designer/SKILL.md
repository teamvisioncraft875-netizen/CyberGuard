---
name: postgres-schema-designer
description: Designs PostgreSQL database schemas, relational migrations, indexing strategies, and query performance optimizations for CYBERGUARD. Activate when creating or modifying database tables, defining relational models for users/incidents/telemetry, or writing complex analytical SQL queries.
---

# PostgreSQL Schema Designer — Data Persistence & Modeling

This skill guides relational data modeling, schema migrations, and indexing strategies in **PostgreSQL** for the CYBERGUARD platform.

> **Authoritative Context:** See [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md) and [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md).

---

## 1. Core Data Entities & Relationships
The PostgreSQL database serves as the single source of truth for all structured data:

```
┌──────────────────┐       1:N       ┌──────────────────┐
│  organisations   │────────────────>│      users       │
└──────────────────┘                 └─────────┬────────┘
                                               │
                               1:N             │ 1:N
                        ┌──────────────────────┼──────────────────────┐
                        ▼                                             ▼
             ┌─────────────────────┐                       ┌─────────────────────┐
             │      incidents      │                       │     guardians       │
             └──────────┬──────────┘                       └─────────────────────┘
                        │ 1:N
                        ▼
             ┌─────────────────────┐
             │     audit_logs      │
             └─────────────────────┘
```

---

## 2. Core Relational Schemas (DDL Reference)

```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Organisations (for enterprise multi-tenancy)
CREATE TABLE organisations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Users (Individuals, Enterprise Employees, Admins, Guardians)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organisations(id) ON DELETE SET NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'individual' CHECK (role IN ('individual', 'enterprise_admin', 'guardian')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Guardian Links (Guardian Mode)
CREATE TABLE guardian_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    guardian_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ward_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(guardian_user_id, ward_user_id)
);

-- 4. Incidents (All Threat Events)
CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID REFERENCES organisations(id) ON DELETE CASCADE,
    threat_scenario VARCHAR(50) NOT NULL, -- 'PHISHING', 'DEEPFAKE', 'IMPERSONATION', etc.
    risk_tier VARCHAR(20) NOT NULL CHECK (risk_tier IN ('Safe', 'Low', 'Medium', 'High', 'Critical')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    explanation TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    mitre_technique VARCHAR(50),
    signals JSONB DEFAULT '{}'::jsonb,
    status VARCHAR(50) DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved')),
    resolved_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Telemetry Logs (From Guard App Sensors)
CREATE TABLE telemetry_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(100) NOT NULL, -- 'login_attempt', 'process_spike', 'network_outbound'
    telemetry_data JSONB NOT NULL,
    is_anomalous BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

---

## 3. High-Performance Indexing Strategy
To support real-time dashboards and high-volume incident feeds without latency:

```sql
-- Feed queries filtered by organization, status, and sorted by recency
CREATE INDEX idx_incidents_org_created ON incidents(org_id, created_at DESC);

-- Risk-tier aggregation queries for analytics charts
CREATE INDEX idx_incidents_risk_tier ON incidents(risk_tier, created_at);

-- JSONB indexing for querying specific threat signals
CREATE INDEX idx_incidents_signals ON incidents USING GIN(signals);

-- Fast lookup for user-specific safety history
CREATE INDEX idx_incidents_user_created ON incidents(user_id, created_at DESC);
```

---

## 4. Modeling Guidelines for CYBERGUARD
1. **JSONB for Signals:** Use `JSONB` for `signals` and `telemetry_data` to flexibly accommodate varied engine parameters without recurring schema migrations.
2. **Strict Enums/Constraints:** Use `CHECK` constraints on `risk_tier` and `role` to guarantee database-level integrity with the API contract.
3. **Always Parameterize:** All queries in `services/backend/src/models/` must use parameterized variables (`$1`, `$2`). Never concatenate raw SQL strings.
