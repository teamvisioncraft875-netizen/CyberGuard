# CYBERGUARD

**AI-Powered Cyber Defense Platform**

Detect threats in seconds. Respond in minutes. Protect everyone.

CYBERGUARD is an enterprise-grade cybersecurity platform that combines real-time threat detection with autonomous security operations. It protects individual users from phishing, malware, and deepfakes while empowering enterprise SOCs with AI-assisted investigation and automated response.

## Overview

CyberGuard addresses the gap between traditional rule-based security tools and modern AI-generated attacks. With 6 production ML detection engines, an AI Security Copilot, SOAR automation, and enterprise agent deployment, CyberGuard delivers threat detection in seconds and response in minutes—compared to the 206-day industry average.

### Key Metrics

- 2-minute detection-to-response time
- 35+ production security services
- 98% security hardened
- 200+ test cases (all passing)
- 100% multi-tenant isolation

## Features

### Detection & Intelligence
- 6 Production ML Detection Engines (phishing, URL, deepfake, login anomaly, secret exposure, DDoS)
- Attack Surface Discovery (exposure mapping, risk scoring)
- Real-time threat scoring (Safe → Low → Medium → High → Critical)
- Explainable AI with plain-English threat explanations

### Enterprise Security Operations
- AI Security Copilot (conversational incident investigation)
- SOAR Platform (automated playbooks, case management)
- IOC Investigation Engine (IP, domain, URL, hash, email analysis)
- Threat Hunting and Incident Correlation
- Multi-level Approval Workflow (L1/L2/L3 with race-condition protection)

### Agent & Execution
- Enterprise Agent (Windows/Linux deployment)
- Real-time Endpoint Telemetry Collection
- Firewall Rule Automation (create, execute, delete)
- Guardian Mode (two-party consent for supervised users)
- Command Queue & Remote Execution

### Platform
- Multi-tenant architecture with RLS protection
- Append-only audit logging (50+ event types)
- JWT authentication + RBAC
- WebSocket real-time alerts
- Email and push notifications

## Tech Stack

**Frontend**
- React 18, TypeScript, Tailwind CSS, shadcn/ui
- React Native (Expo) for mobile
- Responsive design (mobile-first)

**Backend**
- Node.js 18+, Express.js
- PostgreSQL (multi-tenant, RLS)
- Redis (caching, rate limiting)
- TypeScript for type safety

**Machine Learning**
- Python 3.9+
- TensorFlow, PyTorch
- 6 trained detection models
- Gemini API for AI Copilot

**Agent**
- Python 3.9+
- PowerShell (Windows firewall)
- Bash/subprocess (Linux firewall)
- Thread-safe credential management

**DevOps**
- Docker
- PostgreSQL Cloud
- Redis Cloud
- Git for version control

## Project Structure

cyberguard/
├── apps/
│ ├── web/ # React dashboard (Port 3000)
│ └── mobile/ # React Native (Expo)
├── services/
│ ├── backend/ # Node.js API (Port 5000)
│ │ ├── src/
│ │ │ ├── controllers/
│ │ │ ├── services/ # 35+ business logic services
│ │ │ ├── models/
│ │ │ ├── routes/
│ │ │ └── middleware/
│ │ ├── sql/ # 15 database migrations
│ │ └── test/ # 35+ test suites
│ └── enterprise-agent/ # Python agent
│ ├── main.py
│ ├── enrollment.py
│ ├── heartbeat.py
│ ├── firewall_executor.py
│ └── telemetry_reporter.py
├── docs/
│ ├── ARCHITECTURE.md
│ ├── API_CONTRACT.md
│ ├── DEPLOYMENT.md
│ ├── CONTRIBUTING.md
│ └── PROJECT_OVERVIEW.md
└── README.md


## Getting Started

### Prerequisites

- Node.js v18+
- Python 3.9+
- PostgreSQL 14+
- Git

### Installation

```bash
# Clone repository
git clone https://github.com/teamvisioncraft875-netizen/CyberGuard.git
cd cyberguard

# Install dependencies
npm install

# Backend
cd services/backend
npm install

# Web dashboard
cd apps/web
npm install

# Mobile app
cd apps/mobile
npm install

# Python agent
cd services/enterprise-agent
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Environment Setup

Create `.env` files:

**services/backend/.env**

DATABASE_URL=postgresql://user:password@localhost:5432/cyberguard
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-secret-key
GEMINI_API_KEY=your-gemini-key
PORT=5000
NODE_ENV=development


**services/enterprise-agent/.env**

BACKEND_URL=http://localhost:5000
DEVICE_ID=your-device-id
CREDENTIAL_ID=your-credential-id
CREDENTIAL_SECRET=your-credential-secret
AGENT_VERSION=1.0.0


### Running Locally

**Terminal 1 - Backend API**
```bash
cd services/backend
npm run dev
# Listening on http://localhost:5000
```

**Terminal 2 - Web Dashboard**
```bash
cd apps/web
npm run dev
# Running on http://localhost:3000
```

**Terminal 3 - Enterprise Agent**
```bash
cd services/enterprise-agent
source venv/bin/activate
python main.py
# Agent running and heartbeating
```

**Terminal 4 - Mobile (Expo)**
```bash
cd apps/mobile
npm start
# Scan QR code with Expo Go app
```

## Testing

Run all test suites:
```bash
cd services/backend
npm test
```

Run specific test:
```bash
npm test -- test_firewall_integration_complete.js
```

Coverage report:
```bash
npm test -- --coverage
```

Status: 200+ test cases passing ✅

## API Endpoints

### Authentication

POST /auth/signup
POST /auth/login
POST /auth/refresh
GET /auth/me


### Incidents

GET /incidents
GET /incidents/:id
POST /incidents/:id/acknowledge
GET /incidents/:id/recommendations


### AI Copilot

POST /copilot/sessions
POST /copilot/messages
GET /copilot/sessions/:id
POST /copilot/investigate


### SOAR Platform

GET /soar/playbooks
POST /soar/playbooks/:id/execute
GET /soar/cases
POST /soar/cases/:id/approve


### Firewall (Admin)

GET /admin/firewall-rules
POST /admin/firewall-rules
DELETE /admin/firewall-rules/:id
GET /admin/agents
POST /admin/agents/:id/firewall-commands


### Enterprise Agent

POST /agents/enroll
POST /agents/:device_id/heartbeat
GET /agents/:device_id/commands
POST /agents/:device_id/commands/:cmd_id/result
GET /agents/:device_id/protected-targets
POST /telemetry/system-event


Full documentation: [docs/API_CONTRACT.md](docs/API_CONTRACT.md)

## Security

- JWT authentication (15m access, 7d refresh)
- bcrypt password hashing
- Role-based access control (admin, analyst, viewer)
- Row-level security for multi-tenant isolation
- SQL injection protection
- Rate limiting (100 req/15min per user)
- Append-only audit logging
- End-to-end encryption for sensitive data
- SOC2-aligned compliance

## Development Workflow

### Branching Strategy

main (production)
↑
└─ dev (integration)
├─ feature/detection-engines
├─ feature/copilot-integration
├─ feature/firewall-integration
├─ feature/soar-platform
└─ feature/mobile-app


### Pull Request Process

1. Create feature branch from `dev`
2. Make changes and commit
3. Open pull request
4. Mentor review and approval
5. Merge to `dev`
6. Periodic merge to `main` for production

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for detailed guidelines.

## Deployment

### Production Setup

```bash
# Backend build
npm run build
npm run start

# Frontend build
npm run build
# Deploy to Vercel

# Database migrations
npm run migrate
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for complete instructions.

## Documentation

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design and data flow
- [API_CONTRACT.md](docs/API_CONTRACT.md) - Complete API reference
- [BACKEND_STATUS_OCT3.md](docs/BACKEND_STATUS_OCT3.md) - Frontend team briefing
- [PROJECT_OVERVIEW.md](docs/PROJECT_OVERVIEW.md) - High-level feature overview
- [DEPLOYMENT.md](docs/DEPLOYMENT.md) - Production deployment guide
- [CONTRIBUTING.md](docs/CONTRIBUTING.md) - Development guidelines

## Project Status

| Component | Status | Details |
|-----------|--------|---------|
| Detection Engines | ✅ 95-100% | 6 ML models trained and deployed |
| AI Copilot | ✅ 95% | Investigation and recommendations |
| SOAR Platform | ✅ 95% | Playbooks, executions, approvals |
| Enterprise Agent | ✅ 100% | Enrollment, heartbeat, telemetry |
| Firewall Integration | ✅ 100% | Windows/Linux rule execution |
| Database | ✅ 98% | 15 migrations, RLS, audit logging |
| Testing | ✅ 100% | 200+ test cases passing |
| Security | ✅ 98% | Auth, encryption, rate limiting |

Overall: Production-Ready MVP (95%+)

## Team

- **Subrat Kumar Sahoo** - Backend Lead, Architecture, 35+ services
- **Subha sankar Sahu** - Full-Stack Engineer, Dashboard and mobile UI
- **Sudhansu Sekhar Khuntia** - ML/AI Engineer, Detection models, Copilot
- **Pritee sulagna Baral** - DevOps and Database, PostgreSQL, production hardening
- **Ahinsa Samal** - Systems Engineer, Agent development, firewall execution

## Support

- **GitHub Issues**: [Report bugs](https://github.com/teamvisioncraft875-netizen/CyberGuard/issues)
- **Documentation**: [Full docs](docs/)
- **Contributing**: See [CONTRIBUTING.md](docs/CONTRIBUTING.md)

## License

Built for Hackathon 2026 | Prototype/MVP | Active Development

---

Built with ❤️ by Team VisionCraft

Last updated: October 2026
