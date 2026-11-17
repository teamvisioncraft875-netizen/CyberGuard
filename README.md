```markdown
<div align="center">

```text
 ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝

```

# CYBERGUARD

### *Detect Threats. Defend Everyone.*

**An AI-Powered Cyber Defense Platform for Real-Time Detection, Investigation, and Automated Response**

<p align="center">
  <a href="https://github.com/teamvisioncraft875-netizen/CyberGuard">
    <img src="https://img.shields.io/badge/Status-Active%20Development-blue?style=for-the-badge&logo=git&logoColor=white&color=2563EB&labelColor=0F172A" alt="Development Status" />
  </a>
  <a href="https://github.com/teamvisioncraft875-netizen/CyberGuard/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-See%20Repository-blue?style=for-the-badge&color=2563EB&labelColor=0F172A" alt="License" />
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Frontend-React%2018%20%7C%20TypeScript-61DAFB?style=for-the-badge&logo=react&logoColor=white&color=0284C7&labelColor=0F172A" alt="Frontend React and TypeScript" />
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Backend-Express.js%20%7C%20Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white&color=16A34A&labelColor=0F172A" alt="Backend Express and Node.js" />
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Database-PostgreSQL%20%7C%20Redis-4169E1?style=for-the-badge&logo=postgresql&logoColor=white&color=3B82F6&labelColor=0F172A" alt="Database PostgreSQL and Redis" />
  </a>
</p>

<p align="center">
  <img src="https://skillicons.dev/icons?i=react,typescript,nodejs,express,python,postgres,redis,docker,git,github" alt="CYBERGUARD Technology Stack" />
</p>

<p align="center">
  CYBERGUARD combines machine-learning detection engines, security automation, endpoint telemetry,
  and AI-assisted investigation into a unified cyber defense platform.
  <br />
  It helps individuals and security operations teams detect phishing, malware, deepfakes,
  account anomalies, exposed secrets, denial-of-service activity, and other security threats.
</p>

---

</div>

## Table of Contents

- [About the Project](#about-the-project)
- [Core Objectives](#core-objectives)
- [Key Capabilities](#key-capabilities)
  - [Threat Detection and Intelligence](#threat-detection-and-intelligence)
  - [Security Operations](#security-operations)
  - [Endpoint Agents and Response](#endpoint-agents-and-response)
  - [Platform and Tenant Security](#platform-and-tenant-security)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [Project Directory Structure](#project-directory-structure)
- [Detection Engines](#detection-engines)
- [Application Workflow](#application-workflow)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Local Installation](#local-installation)
  - [Environment Variables](#environment-variables)
  - [Running the Platform](#running-the-platform)
- [API Reference](#api-reference)
- [Testing Strategy](#testing-strategy)
- [Security Architecture](#security-architecture)
- [Development Roadmap](#development-roadmap)
- [Contributing Guidelines](#contributing-guidelines)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## About the Project

**CYBERGUARD** is an AI-powered cyber defense platform designed to detect, investigate, and respond to modern security threats in real time.

Traditional security systems often depend on static rules and isolated tools. CYBERGUARD brings together machine-learning detection engines, explainable threat scoring, security operations workflows, endpoint agents, and automated response capabilities in one platform.

The platform is designed for both individual protection and enterprise security operations:

- **Individual Protection:** Detect phishing, malicious URLs, deepfakes, account anomalies, and exposed credentials.
- **Security Operations:** Help analysts investigate incidents, correlate related activity, hunt for threats, and coordinate response.
- **Automated Response:** Execute approved firewall actions, endpoint commands, and SOAR playbooks.
- **Enterprise Visibility:** Collect endpoint telemetry, map attack surface exposure, and maintain a complete audit trail.
- **Secure Multi-Tenant Operation:** Isolate customer data through PostgreSQL row-level security and tenant-aware authorization.

CYBERGUARD focuses on shortening the gap between detection and response:

> **Detect threats in seconds. Respond in minutes. Protect everyone.**

---

## Core Objectives

1. **Real-Time Threat Detection:** Identify suspicious activity across URLs, login behavior, media, secrets, and network traffic.
2. **Explainable Security Decisions:** Provide plain-English explanations for threat scores and recommended actions.
3. **AI-Assisted Investigation:** Give security analysts a conversational copilot for incident analysis and response planning.
4. **Automated Security Operations:** Use controlled SOAR playbooks and approval workflows to reduce repetitive manual work.
5. **Endpoint Visibility:** Deploy agents that collect system telemetry and receive authorized security commands.
6. **Secure Multi-Tenant Architecture:** Enforce tenant isolation at the application and database layers.
7. **Auditable Response:** Preserve append-only security events and administrative actions for investigation and compliance.
8. **Operational Reliability:** Protect critical workflows with validation, rate limiting, race-condition safeguards, and structured error handling.

---

## Key Capabilities

The following capability breakdown represents the platform's primary functional areas.

> **Status Legend:**  
> ✅ **Implemented:** Available in the platform implementation.  
> 🔄 **In Progress:** Integration, refinement, or hardening is ongoing.  
> 📋 **Planned:** Designed for a future development phase.

### Threat Detection and Intelligence

| Capability | Description | Status |
| :--- | :--- | :---: |
| **Phishing Detection** | Analyze messages, domains, URLs, and content for phishing indicators | ✅ Implemented |
| **Malicious URL Detection** | Score URLs using machine-learning and security intelligence signals | ✅ Implemented |
| **Deepfake Detection** | Analyze media for manipulated or synthetic content indicators | ✅ Implemented |
| **Login Anomaly Detection** | Identify unusual authentication behavior and account access patterns | ✅ Implemented |
| **Secret Exposure Detection** | Detect exposed credentials, tokens, and sensitive secrets | ✅ Implemented |
| **DDoS Detection** | Identify suspicious traffic patterns associated with denial-of-service activity | ✅ Implemented |
| **Threat Scoring** | Classify activity from Safe through Critical using normalized risk scores | ✅ Implemented |
| **Explainable AI** | Generate human-readable explanations for detection decisions | ✅ Implemented |
| **Attack Surface Discovery** | Map exposed assets and calculate exposure risk | ✅ Implemented |
| **IOC Investigation** | Investigate IP addresses, domains, URLs, hashes, and email indicators | ✅ Implemented |
| **Threat Correlation** | Correlate related indicators, events, and incidents | ✅ Implemented |
| **Threat Hunting** | Search telemetry and security events for suspicious patterns | ✅ Implemented |

### Security Operations

| Capability | Description | Status |
| :--- | :--- | :---: |
| **AI Security Copilot** | Conversational assistance for incident investigation and response planning | ✅ Implemented |
| **Incident Management** | Track incidents, severity, status, ownership, and investigation history | ✅ Implemented |
| **SOAR Playbooks** | Define repeatable automated workflows for security response | ✅ Implemented |
| **Case Management** | Create, assign, review, and close security operations cases | ✅ Implemented |
| **Approval Workflows** | Enforce L1, L2, and L3 approval requirements for sensitive actions | ✅ Implemented |
| **Race-Condition Protection** | Prevent duplicate or conflicting approval and execution operations | ✅ Implemented |
| **Automated Recommendations** | Generate recommended investigation and response actions | ✅ Implemented |
| **Audit Logging** | Record security, administrative, authentication, and response events | ✅ Implemented |
| **Real-Time Alerts** | Deliver security alerts through WebSocket connections | ✅ Implemented |
| **Email Notifications** | Notify users about incidents, approvals, and security events | ✅ Implemented |
| **Push Notifications** | Deliver mobile notifications for relevant security activity | ✅ Implemented |

### Endpoint Agents and Response

| Capability | Description | Status |
| :--- | :--- | :---: |
| **Enterprise Agent Enrollment** | Securely enroll Windows and Linux endpoints with the platform | ✅ Implemented |
| **Agent Heartbeats** | Track endpoint availability, version, and health status | ✅ Implemented |
| **System Telemetry** | Collect endpoint system events and operational telemetry | ✅ Implemented |
| **Command Queue** | Queue authorized commands for enrolled enterprise agents | ✅ Implemented |
| **Remote Execution** | Execute approved commands through controlled agent workflows | ✅ Implemented |
| **Firewall Rule Management** | Create, execute, and delete endpoint firewall rules | ✅ Implemented |
| **Windows Firewall Support** | Execute firewall operations through PowerShell | ✅ Implemented |
| **Linux Firewall Support** | Execute firewall operations through platform-appropriate shell commands | ✅ Implemented |
| **Guardian Mode** | Require two-party consent for supervised-user actions | ✅ Implemented |
| **Protected Targets** | Define endpoints and resources requiring enhanced protection | ✅ Implemented |
| **Credential Management** | Store and use agent credentials through thread-safe handling | ✅ Implemented |

### Platform and Tenant Security

| Capability | Description | Status |
| :--- | :--- | :---: |
| **JWT Authentication** | Authenticate users with short-lived access and refresh tokens | ✅ Implemented |
| **Role-Based Access Control** | Enforce administrator, analyst, and viewer permissions | ✅ Implemented |
| **Tenant Isolation** | Restrict access to tenant-owned records and resources | ✅ Implemented |
| **PostgreSQL RLS** | Enforce row-level security at the database layer | ✅ Implemented |
| **Rate Limiting** | Protect APIs from abuse and excessive request volume | ✅ Implemented |
| **Input Validation** | Validate request payloads and security-sensitive parameters | ✅ Implemented |
| **Append-Only Audit Records** | Preserve audit history without allowing destructive modification | ✅ Implemented |
| **Encrypted Sensitive Data** | Protect credentials, tokens, and other sensitive values | ✅ Implemented |
| **Real-Time WebSocket Security** | Authenticate and authorize real-time event subscriptions | 🔄 In Progress |
| **Operational Monitoring** | Monitor service health, agent health, and response workflows | 🔄 In Progress |

---

## Technology Stack

### Platform Architecture

```text
┌──────────────────────────────────────────────────────────────────┐
│                       CYBERGUARD PLATFORM                       │
├───────────────────────┬──────────────────────────────────────────┤
│ Web Dashboard         │ React 18, TypeScript, Tailwind CSS       │
│ Mobile Application    │ React Native, Expo                       │
│ API Layer             │ Node.js 18+, Express.js, TypeScript     │
│ Data Persistence      │ PostgreSQL, Row-Level Security           │
│ Caching and Limits    │ Redis                                    │
│ Machine Learning      │ Python 3.9+, TensorFlow, PyTorch        │
│ AI Copilot            │ Gemini API                               │
│ Endpoint Agent        │ Python, PowerShell, Bash                 │
│ Real-Time Events      │ WebSocket                                 │
│ Deployment            │ Docker, PostgreSQL Cloud, Redis Cloud     │
└───────────────────────┴──────────────────────────────────────────┘
```

### Detailed Component Breakdown

| Layer | Technology | Purpose | Status |
| :--- | :--- | :--- | :---: |
| **Web Frontend** | React 18 | Security dashboard and analyst workflows | ✅ Active |
| **Frontend Language** | TypeScript | Type-safe frontend development | ✅ Active |
| **UI Styling** | Tailwind CSS | Responsive utility-first interface styling | ✅ Active |
| **Mobile Application** | React Native and Expo | Mobile security alerts and management workflows | ✅ Active |
| **Backend Runtime** | Node.js 18+ | API and service execution environment | ✅ Active |
| **Backend Framework** | Express.js | REST API routing and middleware pipeline | ✅ Active |
| **Backend Language** | TypeScript | Type-safe backend development | ✅ Active |
| **Primary Database** | PostgreSQL 14+ | Tenant-aware relational data persistence | ✅ Active |
| **Database Security** | PostgreSQL RLS | Database-level tenant isolation | ✅ Active |
| **Cache and Rate Limits** | Redis | Caching, queues, and request throttling | ✅ Active |
| **ML Runtime** | Python 3.9+ | Detection engine and model execution | ✅ Active |
| **ML Frameworks** | TensorFlow and PyTorch | Training and serving detection models | ✅ Active |
| **AI Integration** | Gemini API | Security copilot analysis and recommendations | ✅ Active |
| **Endpoint Agent** | Python | Endpoint enrollment, telemetry, and execution | ✅ Active |
| **Windows Response** | PowerShell | Windows firewall and endpoint actions | ✅ Active |
| **Linux Response** | Bash and subprocess | Linux firewall and endpoint actions | ✅ Active |
| **Containerization** | Docker | Reproducible service deployment | 🔄 In Progress |
| **API Verification** | Automated test suites | Endpoint and workflow verification | ✅ Active |

---

## System Architecture

CYBERGUARD follows a modular, multi-service architecture built around a secure API layer, dedicated detection services, tenant-aware persistence, and managed endpoint agents.

```mermaid
flowchart TD
    subgraph Clients["Client Applications"]
        Web["Web Dashboard<br/>React 18 + TypeScript"]
        Mobile["Mobile Application<br/>React Native + Expo"]
        Agent["Enterprise Agent<br/>Python"]
    end

    subgraph Gateway["Backend API Layer"]
        Security["Security Middleware<br/>JWT, RBAC, Validation, Rate Limits"]
        Routes["REST API Routes"]
        Controllers["Controllers"]
        Services["Application Services"]
        WebSocket["WebSocket Alert Gateway"]
    end

    subgraph Intelligence["Detection and Intelligence Layer"]
        Detection["Detection Engines"]
        Copilot["AI Security Copilot"]
        IOC["IOC Investigation"]
        Correlation["Threat Correlation"]
        Hunting["Threat Hunting"]
    end

    subgraph Operations["Security Operations Layer"]
        Incidents["Incident Management"]
        SOAR["SOAR Playbooks"]
        Approvals["Approval Workflows"]
        Firewall["Firewall Automation"]
        Commands["Command Queue"]
    end

    subgraph Data["Persistence and Infrastructure"]
        PostgreSQL[("PostgreSQL<br/>Tenant-Aware Database")]
        Redis[("Redis<br/>Cache and Rate Limits")]
        Audit["Append-Only Audit Log"]
    end

    Web --> Security
    Mobile --> Security
    Agent --> Security

    Security --> Routes
    Security --> WebSocket
    Routes --> Controllers
    Controllers --> Services

    Services --> Detection
    Services --> Copilot
    Services --> IOC
    Services --> Correlation
    Services --> Hunting

    Services --> Incidents
    Services --> SOAR
    Services --> Approvals
    Services --> Firewall
    Services --> Commands

    Services --> PostgreSQL
    Services --> Redis
    Services --> Audit

    Commands --> Agent
    Firewall --> Agent
    WebSocket --> Web
    WebSocket --> Mobile
```

### Architectural Principles

1. **Layered Service Design:** Routes, middleware, controllers, services, models, and integrations remain separated by responsibility.
2. **Tenant-Aware Authorization:** Every protected operation validates both the authenticated identity and the active tenant context.
3. **Defense in Depth:** Authentication, RBAC, request validation, rate limiting, database RLS, encryption, and audit logging work together.
4. **Explainable Detection:** Detection results include risk scores, contributing signals, and understandable explanations.
5. **Controlled Automation:** Sensitive response actions pass through authorization and approval requirements before execution.
6. **Append-Only Accountability:** Security and administrative actions are preserved as auditable events.
7. **Fail-Safe Execution:** Endpoint commands and firewall operations validate inputs and report explicit execution results.
8. **Real-Time Visibility:** WebSocket alerts and agent heartbeats keep operators informed about active threats and endpoint health.

---

## Project Directory Structure

The repository is organized as a multi-application platform with dedicated web, mobile, backend, and endpoint-agent packages:

```text
CYBERGUARD/
├── apps/
│   ├── web/                          # React security dashboard
│   │   ├── public/                   # Static public assets
│   │   ├── src/                      # Dashboard source code
│   │   ├── package.json              # Web application manifest
│   │   └── README.md                 # Web application documentation
│   └── mobile/                       # React Native and Expo application
│       ├── assets/                   # Mobile assets
│       ├── src/                      # Mobile application source
│       ├── app.json                  # Expo configuration
│       └── package.json              # Mobile application manifest
├── services/
│   ├── backend/                      # Node.js and Express API
│   │   ├── src/
│   │   │   ├── controllers/          # HTTP request handlers
│   │   │   ├── services/             # Business logic and integrations
│   │   │   ├── models/               # Data models and persistence helpers
│   │   │   ├── routes/               # API route definitions
│   │   │   ├── middleware/           # Auth, validation, tenant, and errors
│   │   │   ├── config/               # Runtime and infrastructure configuration
│   │   │   ├── utils/                # Shared utilities and security helpers
│   │   │   └── app.ts                # Express application setup
│   │   ├── sql/                      # PostgreSQL migrations
│   │   ├── test/                     # Backend test suites
│   │   ├── .env.example              # Backend environment template
│   │   └── package.json              # Backend manifest and scripts
│   └── enterprise-agent/             # Endpoint agent
│       ├── main.py                   # Agent process entrypoint
│       ├── enrollment.py             # Device enrollment workflow
│       ├── heartbeat.py              # Agent health reporting
│       ├── firewall_executor.py      # Firewall rule execution
│       ├── telemetry_reporter.py     # Endpoint telemetry reporting
│       ├── requirements.txt          # Python dependencies
│       └── .env.example              # Agent environment template
├── docs/
│   ├── ARCHITECTURE.md               # Platform architecture
│   ├── API_CONTRACT.md               # API reference and contracts
│   ├── DEPLOYMENT.md                 # Deployment and operations guide
│   ├── CONTRIBUTING.md               # Contribution standards
│   └── PROJECT_OVERVIEW.md           # Platform overview
├── .gitignore                        # Repository ignore rules
└── README.md                         # Platform documentation
```

---

## Detection Engines

CYBERGUARD includes six primary machine-learning detection engines:

| Engine | Input | Detection Focus | Output |
| :--- | :--- | :--- | :--- |
| **Phishing Detection** | Messages, email content, metadata | Social engineering and phishing indicators | Risk score and explanation |
| **URL Detection** | URLs, domains, redirects | Malicious, suspicious, and deceptive destinations | URL classification and confidence |
| **Deepfake Detection** | Images, video, and media metadata | Synthetic or manipulated media | Authenticity score and indicators |
| **Login Anomaly Detection** | Login events and account activity | Unusual access behavior and account compromise | Anomaly score and contributing factors |
| **Secret Exposure Detection** | Source text, logs, and files | API keys, tokens, passwords, and credentials | Secret type, severity, and remediation |
| **DDoS Detection** | Network and request telemetry | Abnormal traffic volume and request patterns | Attack likelihood and severity |

### Threat Severity Model

| Severity | Meaning | Typical Response |
| :--- | :--- | :--- |
| **Safe** | No meaningful security indicators detected | Continue monitoring |
| **Low** | Minor or low-confidence suspicious activity | Review and monitor |
| **Medium** | Credible indicators requiring investigation | Create or enrich an incident |
| **High** | Strong evidence of malicious activity | Escalate and begin response |
| **Critical** | Immediate or severe security threat | Trigger approved emergency response |

---

## Application Workflow

### Threat Detection Workflow

1. **Event Submission:** A user, service, or enterprise agent submits content, telemetry, or an indicator.
2. **Authentication:** The API validates the caller, tenant, role, and request signature.
3. **Normalization:** Input data is validated and normalized for analysis.
4. **Detection:** The appropriate ML detection engine evaluates the input.
5. **Threat Scoring:** Signals are combined into a normalized severity and confidence score.
6. **Explanation:** The platform generates a plain-English explanation of the result.
7. **Incident Correlation:** Related indicators and existing incidents are evaluated.
8. **Notification:** Relevant users receive dashboard, WebSocket, email, or mobile notifications.
9. **Response:** Authorized users may investigate, approve, or execute a response action.

### Security Operations Workflow

1. **Alert Creation:** A detection result creates or updates an incident.
2. **Triage:** An analyst reviews severity, evidence, indicators, and recommendations.
3. **Investigation:** The analyst uses the AI copilot, IOC engine, threat hunting, and correlation tools.
4. **Case Assignment:** The incident is assigned to an analyst or operations team.
5. **Recommendation Review:** Suggested containment and remediation actions are evaluated.
6. **Approval:** Sensitive actions are routed through the required L1, L2, or L3 approval level.
7. **Execution:** Approved playbooks, commands, or firewall actions are executed.
8. **Verification:** Execution results and endpoint responses are recorded.
9. **Closure:** The incident is resolved with a complete audit trail and investigation summary.

### Enterprise Agent Workflow

1. **Enrollment:** An endpoint agent enrolls using an authorized device and credential pair.
2. **Heartbeat:** The agent periodically reports health, version, and availability.
3. **Telemetry:** System and security events are sent to the backend for analysis.
4. **Command Polling:** The agent retrieves authorized commands from its queue.
5. **Execution:** Commands are validated and executed locally.
6. **Result Reporting:** The agent reports success, failure, output, and execution metadata.
7. **Audit:** The backend records the complete command lifecycle.

---

## Getting Started

### Prerequisites

Ensure the following tools are installed:

- **Node.js:** `v18.x` or higher — [Download Node.js](https://nodejs.org/)
- **npm:** Compatible with the installed Node.js version
- **Python:** `v3.9` or higher — [Download Python](https://www.python.org/)
- **PostgreSQL:** `v14.x` or higher — [Download PostgreSQL](https://www.postgresql.org/download/)
- **Redis:** Local Redis or a compatible Redis Cloud instance
- **Git:** [Download Git](https://git-scm.com/)
- **Docker:** Optional, for containerized development and deployment

External credentials may also be required for:

- Gemini API access
- PostgreSQL hosting
- Redis hosting
- Email notification delivery
- Push notification delivery

---

### Local Installation

Clone the repository:

```bash
git clone https://github.com/teamvisioncraft875-netizen/CyberGuard.git
cd CyberGuard
```

#### 1. Install Backend Dependencies

```bash
cd services/backend
npm install
```

#### 2. Install Web Dashboard Dependencies

```bash
cd ../../apps/web
npm install
```

#### 3. Install Mobile Application Dependencies

```bash
cd ../mobile
npm install
```

#### 4. Create the Python Agent Environment

```bash
cd ../../services/enterprise-agent
python -m venv venv
```

Activate the environment:

**Windows Command Prompt:**

```cmd
venv\Scripts\activate
```

**Windows PowerShell:**

```powershell
.\venv\Scripts\Activate.ps1
```

**Linux or macOS:**

```bash
source venv/bin/activate
```

Install the agent dependencies:

```bash
pip install -r requirements.txt
```

---

### Environment Variables

Never commit `.env` files or production credentials to source control. Use environment templates for local development.

#### Backend Environment

Create `services/backend/.env`:

| Variable | Required | Default / Example | Purpose |
| :--- | :---: | :--- | :--- |
| `DATABASE_URL` | **Required** | `postgresql://user:password@localhost:5432/cyberguard` | PostgreSQL connection string |
| `REDIS_URL` | **Required** | `redis://localhost:6379` | Redis connection string |
| `JWT_SECRET` | **Required** | Long random secret | Access and refresh token signing key |
| `GEMINI_API_KEY` | **Required** | Provider API key | AI copilot integration |
| `PORT` | Optional | `5000` | Backend HTTP port |
| `NODE_ENV` | Optional | `development` | Runtime environment |
| `CLIENT_URL` | Optional | `http://localhost:3000` | Allowed web application origin |
| `ACCESS_TOKEN_EXPIRES_IN` | Optional | `15m` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRES_IN` | Optional | `7d` | Refresh token lifetime |

Example:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/cyberguard
REDIS_URL=redis://localhost:6379
JWT_SECRET=replace-with-a-long-random-secret
GEMINI_API_KEY=replace-with-your-gemini-api-key
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:3000
```

#### Enterprise Agent Environment

Create `services/enterprise-agent/.env`:

| Variable | Required | Default / Example | Purpose |
| :--- | :---: | :--- | :--- |
| `BACKEND_URL` | **Required** | `http://localhost:5000` | Backend API base URL |
| `DEVICE_ID` | **Required** | Enrolled device identifier | Agent device identity |
| `CREDENTIAL_ID` | **Required** | Device credential identifier | Agent authentication |
| `CREDENTIAL_SECRET` | **Required** | Device credential secret | Agent authentication secret |
| `AGENT_VERSION` | Optional | `1.0.0` | Installed agent version |
| `HEARTBEAT_INTERVAL` | Optional | `30` | Heartbeat interval in seconds |

Example:

```env
BACKEND_URL=http://localhost:5000
DEVICE_ID=your-device-id
CREDENTIAL_ID=your-credential-id
CREDENTIAL_SECRET=your-credential-secret
AGENT_VERSION=1.0.0
```

#### Web Application Environment

The web application may require an API base URL depending on its runtime configuration:

```env
VITE_API_BASE_URL=http://localhost:5000
```

---

### Running the Platform

Run each application in a separate terminal.

#### Backend API

```bash
cd services/backend
npm run dev
```

The API starts at:

```text
http://localhost:5000
```

#### Web Dashboard

```bash
cd apps/web
npm run dev
```

The web dashboard starts at:

```text
http://localhost:3000
```

#### Enterprise Agent

Activate the Python environment first, then run:

```bash
cd services/enterprise-agent
python main.py
```

The agent begins enrollment, heartbeat reporting, telemetry collection, and command processing according to its configuration.

#### Mobile Application

```bash
cd apps/mobile
npm start
```

Use the Expo development tools to launch the application on a simulator or physical device.

---

## API Reference

The backend exposes REST endpoints for authentication, incidents, copilot workflows, SOAR operations, firewall automation, agents, and telemetry.

### Authentication

| Method | Endpoint | Description |
| :---: | :--- | :--- |
| `POST` | `/auth/signup` | Create a user account |
| `POST` | `/auth/login` | Authenticate and issue tokens |
| `POST` | `/auth/refresh` | Refresh an access token |
| `GET` | `/auth/me` | Retrieve the current user |

### Incidents

| Method | Endpoint | Description |
| :---: | :--- | :--- |
| `GET` | `/incidents` | List tenant incidents |
| `GET` | `/incidents/:id` | Retrieve incident details |
| `POST` | `/incidents/:id/acknowledge` | Acknowledge an incident |
| `GET` | `/incidents/:id/recommendations` | Retrieve recommended actions |

### AI Security Copilot

| Method | Endpoint | Description |
| :---: | :--- | :--- |
| `POST` | `/copilot/sessions` | Create a copilot session |
| `POST` | `/copilot/messages` | Send a message to the copilot |
| `GET` | `/copilot/sessions/:id` | Retrieve a copilot session |
| `POST` | `/copilot/investigate` | Start an AI-assisted investigation |

### SOAR Platform

| Method | Endpoint | Description |
| :---: | :--- | :--- |
| `GET` | `/soar/playbooks` | List available playbooks |
| `POST` | `/soar/playbooks/:id/execute` | Execute an authorized playbook |
| `GET` | `/soar/cases` | List security operations cases |
| `POST` | `/soar/cases/:id/approve` | Approve a case action |

### Firewall and Administration

| Method | Endpoint | Description |
| :---: | :--- | :--- |
| `GET` | `/admin/firewall-rules` | List managed firewall rules |
| `POST` | `/admin/firewall-rules` | Create a firewall rule |
| `DELETE` | `/admin/firewall-rules/:id` | Delete a firewall rule |
| `GET` | `/admin/agents` | List enrolled agents |
| `POST` | `/admin/agents/:id/firewall-commands` | Queue an agent firewall command |

### Enterprise Agents and Telemetry

| Method | Endpoint | Description |
| :---: | :--- | :--- |
| `POST` | `/agents/enroll` | Enroll an enterprise agent |
| `POST` | `/agents/:device_id/heartbeat` | Submit an agent heartbeat |
| `GET` | `/agents/:device_id/commands` | Retrieve pending commands |
| `POST` | `/agents/:device_id/commands/:cmd_id/result` | Submit command execution results |
| `GET` | `/agents/:device_id/protected-targets` | Retrieve protected targets |
| `POST` | `/telemetry/system-event` | Submit a system security event |

For complete request and response schemas, see [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md).

---

## Testing Strategy

CYBERGUARD uses automated testing to verify API contracts, security controls, service behavior, detection workflows, and endpoint integrations.

### Backend Tests

Run the backend test suite:

```bash
cd services/backend
npm test
```

Run a specific test file:

```bash
npm test -- test_firewall_integration_complete.js
```

Run tests with coverage:

```bash
npm test -- --coverage
```

### Test Coverage Areas

- Authentication and token lifecycle
- Role-based authorization
- Tenant isolation and PostgreSQL RLS behavior
- Request validation and error handling
- Detection engine results
- Threat scoring and explanations
- Incident creation and updates
- AI copilot sessions and investigations
- SOAR playbook execution
- Multi-level approval workflows
- Firewall rule lifecycle
- Enterprise agent enrollment
- Heartbeats and telemetry
- Command queue and result reporting
- Rate limiting and audit logging
- WebSocket alert delivery
- Notification dispatch

---

## Security Architecture

1. **JWT Authentication:** Access and refresh tokens provide authenticated session management with short-lived access credentials.
2. **Role-Based Access Control:** Administrative, analyst, and viewer roles restrict access to security-sensitive operations.
3. **Tenant Isolation:** Tenant context is validated in the API and enforced through PostgreSQL row-level security policies.
4. **Password Protection:** User passwords are hashed with `bcrypt` and are never stored in plaintext.
5. **Input Validation:** Request payloads, query parameters, identifiers, and command inputs are validated before processing.
6. **SQL Injection Protection:** Database access uses parameterized queries and safe database abstractions.
7. **Rate Limiting:** API and authentication endpoints are protected against excessive request volume.
8. **Credential Protection:** Agent credentials, API keys, tokens, and other sensitive values are encrypted or handled through protected configuration.
9. **Approval-Gated Automation:** Sensitive firewall, command, and SOAR operations require appropriate authorization and approval.
10. **Race-Condition Protection:** Approval and execution workflows prevent duplicate, stale, or conflicting actions.
11. **Append-Only Auditing:** Security events and administrative actions are preserved for investigation and accountability.
12. **Secure Endpoint Execution:** Agent commands are validated, scoped, logged, and reported with explicit execution results.
13. **Notification Security:** Alerts and notifications are sent only to authorized users and tenant members.
14. **Environment Hygiene:** Secrets and local configuration files are excluded from version control through repository ignore rules.

---

## Development Roadmap

```mermaid
flowchart LR
    P1["Phase 1<br/><b>Platform Foundation</b><br/>Architecture & Services"]
    P2["Phase 2<br/><b>Detection Intelligence</b><br/>ML Engines & Scoring"]
    P3["Phase 3<br/><b>Security Operations</b><br/>Incidents, IOC & Copilot"]
    P4["Phase 4<br/><b>Automation</b><br/>SOAR & Approvals"]
    P5["Phase 5<br/><b>Endpoint Defense</b><br/>Agents & Firewall"]
    P6["Phase 6<br/><b>Hardening & Scale</b><br/>Observability & Deployment"]

    P1 --> P2 --> P3 --> P4 --> P5 --> P6
```

### Phase 1: Platform Foundation

- [x] Establish multi-application repository structure
- [x] Implement Node.js and Express backend foundation
- [x] Configure PostgreSQL persistence
- [x] Configure Redis integration
- [x] Implement JWT authentication and RBAC
- [x] Establish tenant-aware service patterns

### Phase 2: Detection Intelligence

- [x] Implement phishing detection
- [x] Implement malicious URL detection
- [x] Implement deepfake detection
- [x] Implement login anomaly detection
- [x] Implement secret exposure detection
- [x] Implement DDoS detection
- [x] Add threat severity scoring
- [x] Add explainable security results

### Phase 3: Security Operations

- [x] Implement incident management
- [x] Implement IOC investigation
- [x] Implement threat correlation
- [x] Implement threat hunting workflows
- [x] Integrate the AI Security Copilot
- [x] Add analyst recommendations and case management

### Phase 4: Security Automation

- [x] Implement SOAR playbook management
- [x] Implement playbook execution
- [x] Implement multi-level approval workflows
- [x] Add race-condition protection
- [x] Add audit events for automated actions
- [ ] Expand playbook library and integrations

### Phase 5: Endpoint Defense

- [x] Implement enterprise agent enrollment
- [x] Implement agent heartbeats
- [x] Implement endpoint telemetry
- [x] Implement command queue and result reporting
- [x] Implement Windows firewall automation
- [x] Implement Linux firewall automation
- [x] Implement Guardian Mode
- [ ] Expand endpoint monitoring capabilities

### Phase 6: Hardening and Scale

- [x] Expand automated test coverage
- [x] Harden multi-tenant access controls
- [x] Improve operational error reporting
- [ ] Add comprehensive deployment automation
- [ ] Improve observability and service metrics
- [ ] Expand notification and integration providers
- [ ] Optimize high-volume telemetry processing

---

## Contributing Guidelines

To contribute safely and consistently:

1. **Create a focused branch:**
   - Features: `feature/short-description`
   - Bug fixes: `fix/short-description`
   - Detection engines: `feature/detection-engine-name`
   - Security changes: `security/short-description`
   - Documentation: `docs/short-description`
   - Refactoring: `refactor/short-description`

2. **Use clear commits:**
   - `feat: add URL reputation scoring`
   - `fix: prevent duplicate approval execution`
   - `security: restrict cross-tenant incident access`
   - `test: add firewall integration coverage`
   - `docs: update agent enrollment guide`

3. **Protect sensitive data:**
   - Never commit `.env` files.
   - Never commit API keys, private keys, passwords, or production tokens.
   - Use environment templates for local configuration.

4. **Validate changes locally:**
   - Run the smallest relevant test suite.
   - Run linting and type checks where available.
   - Verify tenant isolation for data-access changes.
   - Add regression coverage for security-sensitive behavior.

5. **Keep changes reviewable:**
   - Prefer small, atomic commits.
   - Document behavior changes.
   - Avoid unrelated formatting or refactoring in feature branches.
   - Include API contract changes in the documentation.

---

## License

This project is distributed under the license specified in the repository's [`LICENSE`](LICENSE) file.

---

## Acknowledgements

- Built with [React](https://react.dev/), [React Native](https://reactnative.dev/), and [Expo](https://expo.dev/).
- Backend services built with [Node.js](https://nodejs.org/) and [Express.js](https://expressjs.com/).
- Data persistence powered by [PostgreSQL](https://www.postgresql.org/).
- Caching and rate limiting powered by [Redis](https://redis.io/).
- Machine-learning workflows powered by [TensorFlow](https://www.tensorflow.org/) and [PyTorch](https://pytorch.org/).
- AI-assisted investigation powered by the [Gemini API](https://ai.google.dev/).
- Badges generated using [Shields.io](https://shields.io/) and [Skill Icons](https://skillicons.dev/).

---

<div align="center">
  <sub>CYBERGUARD — AI-powered cyber defense for modern threats.</sub>
</div>
```
