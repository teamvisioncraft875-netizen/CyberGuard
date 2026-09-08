---
name: websocket-integrator
description: Implements real-time WebSocket communication, live incident feeds, room multiplexing, and reconnection logic between Node.js Gateway and the React Command Dashboard. Activate when implementing live incident pushes, building real-time dashboard listeners, handling connection events, or configuring WebSocket rooms.
---

# WebSocket Integrator — Real-Time Live Feed Engine

This skill guides the implementation of low-latency, real-time event broadcasting between the **Node.js Gateway** (`services/backend/`) and the **React Command Dashboard** (`apps/web/`).

> **Authoritative Context:** See [.agents/PROJECT_CONTEXT.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/PROJECT_CONTEXT.md) and [.agents/rules/cyberguard.md](file:///c:/Users/subha/Downloads/CyberGuard/.agents/rules/cyberguard.md).

---

## 1. Architectural Role
In CYBERGUARD, admins and individual users should never need to refresh their browser to see incoming threats. As soon as an incident is processed by FastAPI and persisted in PostgreSQL, the Node.js Gateway emits a WebSocket event that renders on the dashboard within milliseconds.

---

## 2. Channel & Room Architecture

```
                    ┌─────────────────────────┐
                    │   Node.js Socket.io     │
                    └────────────┬────────────┘
                                 │
           ┌─────────────────────┴─────────────────────┐
           ▼                                           ▼
┌──────────────────────┐                    ┌──────────────────────┐
│  org:<org_id> Room   │                    │  user:<user_id> Room │
│  (Enterprise SOC)    │                    │  (Individual User)   │
└──────────────────────┘                    └──────────────────────┘
```

### Authentication on Handshake
Before accepting a connection, the server must verify the client's JWT token:
```javascript
// services/backend/src/services/socketService.js
const { verifyTokenString } = require('../utilities/jwtUtils');

io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.split(' ')[1];
  if (!token) return next(new Error('Authentication error: Missing token'));

  try {
    const user = verifyTokenString(token);
    socket.user = user;
    next();
  } catch (err) {
    next(new Error('Authentication error: Invalid token'));
  }
});
```

---

## 3. Event Catalog

| Event Name | Direction | Payload | Description |
|---|---|---|---|
| `subscribe` | Client → Server | `{ rooms: ['org:123'] }` | Join authorized tenant or user channel. |
| `incident:new` | Server → Client | `StandardIncidentPayload` | Broadcast immediately upon incident creation. |
| `incident:update` | Server → Client | `{ incidentId, status, resolvedBy }` | Emitted when an incident is triaged or resolved. |
| `telemetry:alert` | Server → Client | `{ deviceId, anomalyType, score }` | Emitted when Guard App flags abnormal system spike. |

---

## 4. Client Integration Pattern (`apps/web/src/hooks/useIncidentSocket.js`)

```javascript
import { useEffect } from 'react';
import { io } from 'socket.io-client';
import { useQueryClient } from '@tanstack/react-query';

export function useIncidentSocket(token, orgId) {
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!token) return;

    const socket = io(import.meta.env.VITE_WS_URL || 'http://localhost:5000', {
      auth: { token },
      transports: ['websocket'],
      reconnectionAttempts: 5,
      reconnectionDelay: 1000
    });

    socket.on('connect', () => {
      socket.emit('subscribe', { room: `org:${orgId}` });
    });

    socket.on('incident:new', (newIncident) => {
      // Optimistically prepend to incident feed cache
      queryClient.setQueryData(['incidents', orgId], (oldData) => {
        if (!oldData) return [newIncident];
        return [newIncident, ...oldData];
      });
      // Invalidate dashboard metric aggregations
      queryClient.invalidateQueries(['dashboard-metrics', orgId]);
    });

    return () => socket.disconnect();
  }, [token, orgId, queryClient]);
}
```

---

## 5. Reliability & Performance Best Practices
1. **Reconnection Resilience:** Always configure automatic reconnection with exponential backoff on client sockets.
2. **Payload Size:** Do not send huge raw model tensor outputs over WebSockets. Send the clean `StandardIncidentPayload` with summarized signals.
3. **Room Segregation:** Always check `socket.user.orgId` before permitting a socket to subscribe to `org:<org_id>`. Never broadcast cross-tenant data.
