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

### Setup & Execution Guide

Before running, ensure all project dependencies are installed (`npm install` in root, backend, web, and mobile; `pip install -r requirements.txt` in `services/ml-service`).

#### 1. Backend Gateway (Port 5000)
```bash
npm run dev:backend
```

#### 2. Web Command Dashboard (Port 3000)
```bash
npm run dev:web
```

#### 3. AI/ML Detection Microservice (Port 8000)
```bash
cd services/ml-service
.\venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### 4. Mobile Application (React Native / Expo)
1. Install **Expo Go SDK 51** on your Android device via browser:
   - Download APK: [Expo Go SDK 51 (Exponent-2.31.2.apk)](https://d1ahtucjixef4r.cloudfront.net/Exponent-2.31.2.apk)
2. Connect your computer and mobile phone to the same Wi-Fi / mobile hotspot.
3. Start the mobile development server from project root:
```bash
npm run dev:mobile
```
4. Scan the generated QR code in Expo Go.

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
