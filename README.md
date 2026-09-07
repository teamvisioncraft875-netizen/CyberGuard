# CyberGuard

**AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System**

CyberGuard is an AI-driven cybersecurity platform that detects phishing, deepfakes, digital impersonation, and account-takeover threats in near real time — providing risk scoring, plain-English explanations, and recommended response actions through a unified dashboard and mobile app.

---

## Problem Statement
Domain: **Cybersecurity + Artificial Intelligence**

Traditional rule-based security tools struggle against AI-generated phishing, deepfakes, and social engineering attacks. CyberGuard addresses this by combining AI/ML detection engines with explainable, human-readable threat analysis and response recommendations.

---

## Key Features
- AI-powered phishing & scam message detection
- Deepfake & digital impersonation detection (image/audio)
- Login & account-takeover anomaly detection
- Unified risk scoring (Safe → Low → Medium → High → Critical)
- Explainable AI — every alert includes a plain-English reason
- Recommended response actions per threat
- Real-time Command Dashboard (individual + enterprise views)
- Mobile app with push notifications & guardian mode for at-risk users
- Lightweight monitoring agent ("Guard App") for login/system telemetry

---

## Tech Stack

| Layer | Technology |
|---|---|
| Web Frontend | React, Tailwind CSS, shadcn/ui, Recharts, Framer Motion |
| Mobile App | React Native (Expo) |
| Backend (API Gateway) | Node.js, Express, PostgreSQL |
| AI/ML Service | Python, FastAPI |
| Database | PostgreSQL (Cloud) |
| Notifications | Firebase Cloud Messaging (FCM) |

---

## Project Structure

cyberguard/
├── apps/
│ ├── web/ # React dashboard
│ └── mobile/ # React Native app
├── services/
│ ├── backend/ # Node/Express API
│ └── ml-service/ # FastAPI detection engines
├── docs/ # Architecture, API contracts, reports
└── README.md


---

## Getting Started

### Prerequisites
- Node.js (v18+)
- Python (3.10+)
- PostgreSQL / cloud DB access

### Setup
```bash
# Clone the repo
git clone <repo-url>
cd cyberguard

# Backend
cd services/backend
npm install
npm run dev

# ML Service
cd services/ml-service
pip install -r requirements.txt --break-system-packages
uvicorn main:app --reload

# Web frontend
cd apps/web
npm install
npm run dev
```

---

## Branching & Contribution Workflow
- `main` — production-ready, protected
- `dev` — integration branch
- `feature/<task-name>` — one branch per task

All changes go through a Pull Request into `dev`, reviewed and approved by our mentor before merging. See `CONTRIBUTING.md` for full guidelines.

---

## Versioning
This project follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`), versioned independently for web (`web-vX.X.X`) and mobile (`mobile-vX.X.X`).

---

## Team

| Name | Role |
|---|---|
| Subha | Backend Lead |
| Subrat | AI/ML Engineer |
| Sudhanshu | Data Engineer |
| Ahinsa | Frontend (Web) |
| Pritee | Frontend (Mobile) / Docs |

---

## 📄 License
This project is built for [Hackathon Name] and is currently a prototype/MVP under active development.
