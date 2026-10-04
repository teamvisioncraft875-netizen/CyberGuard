# CYBERGUARD Enterprise Agent v1 (Python)

A lightweight host security agent designed for enterprise fleet monitoring, telemetry reporting, and centralized incident response orchestration.

---

## Architecture Overview

The Enterprise Agent operates as a non-intrusive host service structured around three autonomous background loops:

```
                          ┌───────────────────────────────────────┐
                          │   CYBERGUARD Backend (Express/Node)   │
                          └───────▲───────────────▲───────────────▲
                                  │               │               │
     POST /agents/enroll          │               │               │
   ┌──────────────────────────────┘               │               │
   │                                              │               │
┌──┴───────────────────────────────────────────┐  │               │
│               Enterprise Agent               │  │               │
│                                              │  │               │
│  ┌──────────────────┐  POST /agents/heartbeat│  │               │
│  │ Heartbeat Worker ├────────────────────────┘  │               │
│  │ (Every 60s)      │                           │               │
│  └──────────────────┘  POST /telemetry/sys-evt  │               │
│  ┌──────────────────┐                           │               │
│  │ Telemetry Worker ├───────────────────────────┘               │
│  │ (Process/Net/OS) │                                           │
│  └──────────────────┘  GET /agents/commands                     │
│  ┌──────────────────┐  POST /agents/commands/:id/result        │
│  │ Command Worker   ├───────────────────────────────────────────┘
│  │ (Safe Skeleton)  │
│  └──────────────────┘
└──────────────────────────────────────────────┘
```

1. **Heartbeat Loop (every 60s)**: Sends liveness pings with active socket counts, refreshes online status on backend, and checks for pending commands.
2. **Telemetry Collector Loop (every 60s)**: Gathers non-intrusive operating system metrics (open connection count, top 10 processes by CPU/memory, hostname, current user) and posts to `/api/v1/telemetry/system-event`.
3. **Command Poller & Handler Loop (every 60s / event-driven)**: Polls `/api/v1/agents/:device_id/commands`, validates payloads, safely logs incoming security actions, and posts execution receipts.

---

## Security Boundary & Credential Handling

- **Zero Secret Disk Persistence**: `credential_secret` received during enrollment is held **strictly in memory** during agent runtime. It is NEVER written to the local credentials file or logged.
- **Identity Storage**: `~/.cyberguard/agent_creds.json` persists only non-sensitive identifiers (`device_id`, `credential_id`, `organization_id`).
- **Secret Redaction**: `logger.py` actively intercepts and sanitizes tokens, passwords, and secrets before outputting to stdout or disk logs.
- **No Intrusive Hooks**: Agent v1 executes in user-space with no process termination, no kernel drivers, and no file dumping.

---

## Phase C Note: Firewall Command Handling

In **Phase B (this release)**, all network containment commands (`temporary_block_ip`, `block_ip`, `block_domain`) are:
1. Validated for IP address or domain syntax.
2. Formatted and logged safely to the audit log.
3. Reported back to the backend command queue with `status="received_not_executed"` and `reason="firewall_integration_pending"`.

> **Note for Phase C**: Live firewall execution (Windows Filtering Platform / `netsh advfirewall` / Linux `iptables`) will be integrated in Phase C.

---

## Configuration Reference

Environment variables can be provided via shell exports or a local `.env` file:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CYBERGUARD_BACKEND_URL` | `http://localhost:3000` | Target CYBERGUARD gateway endpoint |
| `ENROLLMENT_TOKEN` | *None* | One-time token issued by admin for initial host enrollment |
| `AGENT_NAME` | `socket.gethostname()` | Custom device name identifier |
| `AGENT_VERSION` | `1.0.0` | Agent release version reported in heartbeats |
| `HEARTBEAT_INTERVAL` | `60` | Heartbeat interval in seconds |
| `TELEMETRY_INTERVAL` | `60` | Telemetry gathering interval in seconds |
| `COMMAND_POLL_INTERVAL`| `60` | Command queue polling interval in seconds |
| `AGENT_CREDS_PATH` | `~/.cyberguard/agent_creds.json` | Path to non-secret credentials cache |

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment
Create a `.env` file in `services/enterprise-agent/`:
```bash
CYBERGUARD_BACKEND_URL=http://localhost:3000
ENROLLMENT_TOKEN=enroll_your_token_from_admin
```

### 3. Launch Agent
```bash
python main.py
```

### 4. Stopping the Agent
Press `Ctrl+C` or send `SIGTERM`. The agent intercepts the signal, signals all worker threads, and exits cleanly.

---

## Logging Output

- **Console (stdout)**: Formatted timestamps and message bodies with secret redaction.
- **Log File**: Written to `~/.cyberguard/agent.log`.
- **Sample Log Line**:
  ```text
  [2026-10-03 12:30:00] [INFO] Heartbeat sent, status=online, commands_pending=1, next_in=60s
  [2026-10-03 12:30:01] [INFO] [FIREWALL ACTION QUEUED] Command 4d8b-90e1 received target IP '198.51.100.14'. Execution withheld: Firewall integration pending in Phase C.
  [2026-10-03 12:30:01] [INFO] Command 4d8b-90e1 reported back with status='received_not_executed'
  ```

---

## Running the Automated Test Suite

A standalone test suite validates enrollment, credentials, heartbeat, OS metrics collection, telemetry reporting, command polling, safe firewall handling, and graceful shutdown:

```bash
python test_enterprise_agent_v1.py
```
