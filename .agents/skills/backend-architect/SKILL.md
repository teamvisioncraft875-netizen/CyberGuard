---
name: backend-architect
description: Guides architecture, API gateway patterns, service orchestration, auth/RBAC, and layered design in Node.js/Express for CYBERGUARD. Activate when building or refactoring services/backend, structuring routes/controllers/middlewares, orchestrating FastAPI ML calls, or configuring JWT/RBAC.
---

# Backend Architect — CYBERGUARD API Gateway

This skill guides the design and implementation of the **Node.js / Express API Gateway** (`services/backend/`) serving as the central nervous system of CYBERGUARD.

> **Authoritative Context:** See [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md) and [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md).

---

## 1. Architectural Role & Boundaries
In the CYBERGUARD dual-backend system:
- **Node.js/Express is the Building Manager / Gateway:**
  - Handles client authentication (JWT) and RBAC (`individual`, `enterprise_admin`, `guardian`).
  - Validates and sanitizes incoming client requests.
  - Manages persistent database state in PostgreSQL.
  - Orchestrates calls to internal Python FastAPI detection services.
  - Pushes real-time incident events to React Dashboards via WebSockets.
  - Dispatches push notification triggers to Firebase Cloud Messaging (FCM).
- **Hard Boundary:** Web and mobile clients never connect to FastAPI directly. All traffic routes through this gateway.

---

## 2. Directory Structure & Layer Responsibilities
All code in `services/backend/src/` must adhere to this layered structure:

```
services/backend/src/
├── routes/        # URL route mappings and middleware binding ONLY (Zero business logic)
├── controllers/   # Request extraction, service orchestration, response return
├── middlewares/   # JWT authentication, role guards, payload validation, error handler
├── models/        # PostgreSQL queries/ORM schemas (User, Incident, Org, RiskScore)
├── services/      # FastAPI HTTP client, FCM notification dispatcher, telemetry processor
├── config/        # Centralized environment variables (JWT secrets, DB URLs, ports)
└── utils/         # Standard response wrappers, crypto helpers, risk level utilities
```

---

## 3. Implementation Patterns

### Route Definition Pattern (`src/routes/incidents.js`)
```javascript
const express = require('express');
const router = express.Router();
const incidentController = require('../controllers/incidentController');
const { verifyToken, requireRole } = require('../middlewares/authMiddleware');
const { validateScanRequest } = require('../middlewares/validationMiddleware');

// Route definitions only — NO inline handler logic
router.post('/scan', verifyToken, validateScanRequest, incidentController.scanContent);
router.get('/', verifyToken, incidentController.getIncidents);
router.get('/:id', verifyToken, incidentController.getIncidentById);

module.exports = router;
```

### Controller & FastAPI Orchestration (`src/controllers/incidentController.js`)
```javascript
const incidentModel = require('../models/incidentModel');
const mlServiceClient = require('../services/mlServiceClient');
const socketService = require('../services/socketService');

exports.scanContent = async (req, res, next) => {
  try {
    const { content, type, metadata } = req.body;
    const userId = req.user.id;

    // 1. Dispatch to internal FastAPI detection engine
    const analysis = await mlServiceClient.detectThreat({ content, type, metadata });

    // 2. Persist incident in PostgreSQL
    const incident = await incidentModel.create({
      userId,
      threatScenario: type,
      riskTier: analysis.risk_level,
      riskScore: analysis.risk_score,
      explanation: analysis.explanation,
      recommendedAction: analysis.recommended_action,
      mitreTechnique: analysis.mitre_technique,
      signals: analysis.signals
    });

    // 3. Broadcast real-time WebSocket event
    socketService.broadcastIncident(incident);

    // 4. Return standard response
    return res.status(201).json({ success: true, data: incident });
  } catch (error) {
    next(error);
  }
};
```

---

## 4. Engineering Standards Checklist
- [ ] Centralized configuration in `src/config/index.js` loading from `process.env`.
- [ ] No `.env` files committed.
- [ ] Protected endpoints use `verifyToken` middleware and check `req.user.role`.
- [ ] Internal calls to FastAPI (`http://127.0.0.1:8000`) handle timeouts and connection errors gracefully.
- [ ] All database mutations emit real-time WebSocket events to subscribed room clients.
