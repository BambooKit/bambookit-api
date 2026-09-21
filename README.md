# BambooKit API — Autonomous Agent Control Plane Gateway

The central backend API and orchestration engine for **BambooKit** — the AI Agent Control Plane and persistent software engineering environment.

## Architecture

```text
Web / Android / Desktop / CLI
             │
             ▼
      ┌─────────────────┐
      │  BambooKit API  │
      │                 │
      │ Authentication  │
      │ Workspaces      │
      │ Projects        │
      │ Agents          │
      │ Tasks           │
      │ Events          │
      │ Approvals       │
      │ Permissions     │
      │ Providers/BYOK  │
      │ Devices         │
      │ Deployments     │
      │ Usage/Budgets   │
      │ Notifications   │
      │ Audit Logs      │
      │ Realtime        │
      └────────┬────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
   PostgreSQL      Redis/Queue
                      │
                      ▼
               BambooKit Worker
                      │
                      ▼
                Coding Agent
```

---

## Key Features

- **Hono & Node.js Engine**: High-performance typed HTTP API with OpenAPI document generation (`/openapi.json`).
- **PostgreSQL & Drizzle ORM**: Relational schema across 16 domain entities with UUID foreign keys, constraints, and cascading rules.
- **Tenant Workspace Isolation**: Every query and mutation is strictly scoped to the authenticated user's workspace.
- **Dangerous Action Human Approval Gates**: Strict interceptor for production deployments, package installs, and schema changes with authorization scopes (`ONCE`, `TASK`, `PROJECT`, `SESSION`).
- **Immutable Event Sourcing & Agent Replay**: Append-only event stream supporting time-travel replay scrubbers.
- **True BYOK Secret Protection**: Hardware-vault encrypted credentials using AES-256-GCM. Plaintext keys are never returned or logged.
- **Realtime Server-Sent Events (SSE)**: Channel-based telemetry feed (`/v1/realtime/stream?channel=workspace:...`) with workspace validation.
- **Cloud Worker Interface (`/v1/internal/*`)**: Task leasing, heartbeat checks, and event ingestion for `bambookit-worker`.

---

## Getting Started

### 1. Prerequisites
- Node.js >= 20.x
- PostgreSQL (or Docker)

### 2. Environment Setup
```bash
cp .env.example .env
npm install
```

### 3. Running PostgreSQL (Optional Docker)
```bash
docker compose up -d
```

### 4. Running the Development Server
```bash
npm run dev
```
The server will start on `http://localhost:8080`.

### 5. Verification Commands
```bash
# Typecheck
npm run typecheck

# Unit & Integration Tests (10 tests)
npm test

# Production Build
npm run build
```

---

## API Route Map

| Category | Endpoint | Description |
| :--- | :--- | :--- |
| **Health** | `GET /health` | Service health status |
| **Spec** | `GET /openapi.json` | OpenAPI 3.0 specification |
| **Auth** | `POST /v1/auth/register` | Register new user & workspace |
| **Auth** | `POST /v1/auth/login` | Authenticate developer |
| **Workspaces** | `GET /v1/workspaces/current` | Active workspace details |
| **Projects** | `GET /v1/projects` | List workspace projects |
| **Projects** | `POST /v1/projects` | Register project repository |
| **Agents** | `GET /v1/agents` | List active autonomous agents |
| **Agents** | `POST /v1/agents` | Provision new agent runtime |
| **Tasks** | `GET /v1/tasks` | List agent execution tasks |
| **Tasks** | `POST /v1/tasks` | Dispatch autonomous task |
| **Approvals** | `GET /v1/approvals` | List pending dangerous action gates |
| **Approvals** | `POST /v1/approvals/:id/respond` | Approve or reject dangerous action |
| **Events** | `GET /v1/events` | Agent Replay event stream |
| **Providers** | `GET /v1/providers` | BYOK provider statuses (masked) |
| **Providers** | `PATCH /v1/providers/:id` | Update AES-256 encrypted API key |
| **Devices** | `GET /v1/devices` | Registered Android & Desktop connectors |
| **Deployments** | `GET /v1/deployments` | Environment promotions and commits |
| **Usage** | `GET /v1/usage` | Token spend & budget firewall limits |
| **Activity** | `GET /v1/activity` | Immutable audit log trail |
| **Realtime** | `GET /v1/realtime/stream` | Server-Sent Events live event stream |
| **Worker Internal** | `POST /v1/internal/tasks/claim` | Ephemeral worker task lease |
| **Worker Internal** | `POST /v1/internal/tasks/:id/events` | Worker telemetry ingestion |

---

## License

© 2026 BambooKit Inc. All rights reserved.
