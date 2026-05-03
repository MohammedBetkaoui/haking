# Guardian — Incident Reporting System

Guardian is an incident reporting platform built around an Electron reporting app, a React IT dashboard, and a Node.js backend with ISO 27035 workflow tracking, SLA monitoring, append-only audit trails, scheduled compliance reports, and multi-channel notifications.

## Architecture

```
┌──────────────────────┐    WebSocket + REST     ┌─────────────────────┐
│  Guardian Bar        │ ─────────────────────► │  Node.js Backend    │
│  (Electron + React)  │                         │  Express + Socket.io│
│  Employee App        │                         │  Scheduler + PDF    │
└──────────────────────┘                         └──────────┬──────────┘
                                                            │
┌──────────────────────┐    WebSocket + REST     ┌──────────▼──────────┐
│  SOC Dashboard       │ ─────────────────────► │  MySQL 8            │
│  (React + Recharts)  │                         │  guardian_db        │
│  Port 3000           │                         └──────────┬──────────┘
└──────────────────────┘                                    │
                                                            ▼
                                         Slack / Teams / Discord / Email / SMS / SIEM
```

## Core Capabilities

- Employee desktop reporting with anonymous mode and automatic system metadata capture.
- ISO 27035-inspired workflow phases with SLA due dates, warning state, breach state, and automatic escalation.
- Append-only audit logs and workflow history with chained hashes.
- IT assignee directory with manager hierarchy for escalation routing.
- Dashboard views for incident operations, SLA monitoring, and monthly PDF compliance reporting.
- Scheduled monthly PDF generation and API-driven manual regeneration.
- Multi-channel notifications through collaboration webhooks, SMTP email, SMS webhook providers, and generic SIEM HTTP ingestion.

## Quick Start

### Prerequisites

- Node.js 20+
- npm 10+
- Docker Desktop or a local MySQL 8 instance

### Local development

1. Start MySQL.

```bash
docker compose up mysql -d
```

2. Start the backend.

```bash
cd backend
copy .env.example .env
npm install
npm run db:migrate
npm run dev
```

3. Start the dashboard.

```bash
cd dashboard
npm install
npm run dev
```

4. Start the Electron app.

```bash
cd electron-app
npm install
npm run dev
```

### Full Docker demo stack

```bash
docker compose up --build
```

- Dashboard: http://localhost:3000
- Backend: http://localhost:4000
- MySQL: localhost:3306

## Scheduled Jobs

- SLA monitor: controlled by `SLA_CRON`, defaults to every minute.
- Monthly report generation: controlled by `REPORT_CRON`, defaults to `0 5 1 * *`.
- Optional immediate execution at startup: `SLA_RUN_ON_START=true` and `REPORT_RUN_ON_START=true`.

Generated PDFs are stored in `backend/generated-reports` by default, or the path set in `REPORT_OUTPUT_DIR`.

## Demo Directory Seed

`npm run db:migrate` seeds a minimal IT hierarchy if those records do not already exist:

- DPO
- SOC manager
- SOC N1 analyst
- SOC N2 / IT analyst

This seed enables immediate testing of assignment and auto-escalation without manual user provisioning.

## Environment Variables

### Backend runtime

| Variable | Description |
|----------|-------------|
| `PORT` | API port, default `4000` |
| `NODE_ENV` | Environment mode |
| `CORS_ORIGIN` | Allowed dashboard origin |
| `DB_HOST` | MySQL host |
| `DB_PORT` | MySQL port |
| `DB_USER` | MySQL user |
| `DB_PASS` | MySQL password |
| `DB_NAME` | MySQL database name |

### Scheduler and reporting

| Variable | Description |
|----------|-------------|
| `SCHEDULER_TIMEZONE` | Cron timezone, default `UTC` |
| `SLA_CRON` | SLA monitor cron expression |
| `REPORT_CRON` | Monthly report cron expression |
| `SLA_RUN_ON_START` | Run SLA monitor once at boot |
| `REPORT_RUN_ON_START` | Run report generator once at boot |
| `REPORT_OUTPUT_DIR` | PDF output directory |

### Notifications

| Variable | Description |
|----------|-------------|
| `WEBHOOK_DISCORD_URL` | Discord webhook |
| `WEBHOOK_SLACK_URL` | Slack incoming webhook |
| `WEBHOOK_TEAMS_URL` | Microsoft Teams webhook |
| `SMTP_HOST` | SMTP host |
| `SMTP_PORT` | SMTP port |
| `SMTP_SECURE` | `true` for SMTPS |
| `SMTP_USER` | SMTP username |
| `SMTP_PASS` | SMTP password |
| `ALERT_EMAIL_FROM` | Sender address |
| `ALERT_EMAIL_TO` | Comma-separated email recipients |
| `SMS_WEBHOOK_URL` | SMS provider HTTP endpoint |
| `SMS_API_KEY` | SMS provider API key |
| `SMS_AUTH_HEADER` | Optional custom auth header name |
| `SMS_FROM` | SMS sender name |
| `ALERT_SMS_TO` | Comma-separated phone recipients |
| `SIEM_ENDPOINT` | Generic SIEM ingestion endpoint |
| `SIEM_TOKEN` | SIEM bearer token |
| `SIEM_SOURCE` | Source name sent to the SIEM |

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/report` | Submit a new incident |
| `GET` | `/api/incidents` | List incidents with status, severity, assignee, or workflow filters |
| `GET` | `/api/incidents/stats` | Dashboard metrics |
| `GET` | `/api/incidents/:id` | Incident detail, audit trail, checklist, workflow history |
| `PATCH` | `/api/incidents/:id/status` | Advance workflow state |
| `PATCH` | `/api/incidents/:id/assignment` | Assign an incident to an IT user |
| `PATCH` | `/api/incidents/:id/checklist/:step` | Update checklist completion |
| `GET` | `/api/incidents/:id/export` | JSON compliance export |
| `GET` | `/api/users/assignees` | IT directory for assignment |
| `GET` | `/api/reports/monthly` | List generated monthly reports |
| `POST` | `/api/reports/monthly/generate` | Generate or regenerate a monthly PDF report |
| `GET` | `/api/reports/monthly/:id/download` | Download a generated PDF |
| `GET` | `/health` | Health check |

## WebSocket Events

| Event | Direction | Payload |
|-------|-----------|---------|
| `join:admins` | Client → Server | Join the admin room |
| `incident:new` | Server → Admins | New incident summary |
| `incident:updated` | Server → Admins | Incremental incident state updates |

## Compliance Notes

- `audit_logs` and `workflow_events` are append-only through SQL triggers.
- Each audit row is chained through a SHA-256 hash.
- Notification deliveries are tracked in `notification_deliveries`.
- Monthly reports are archived in `monthly_reports` with their generated summary payload.

## Detection Positioning and Standards

### Security flow before and inside ISO 27035

```text
┌─────────────────────────────────────────────────────┐
│  DETECTION (before ISO 27035)                      │
│                                                     │
│  ISO 27001  -> defines WHAT to monitor             │
│  NIST CSF   -> Identify + Detect framework          │
│  IEC 62443  -> industrial / OT monitoring model     │
│                                                     │
│  Practical tools:                                   │
│  • SIEM (Splunk, Elastic)      -> correlates logs   │
│  • IDS/IPS (Snort, Suricata)   -> monitors network  │
│  • EDR (Defender, CrowdStrike) -> monitors endpoints│
│  • Log Watcher                 -> monitors system   │
└─────────────────────────────────────────────────────┘
                        |
                        v
┌─────────────────────────────────────────────────────┐
│  INCIDENT HANDLING (ISO 27035 starts here)         │
│                                                     │
│  Detect -> Report -> Assess -> Respond -> Learn     │
│                                                     │
│  This is the full scope covered by ISO 27035        │
└─────────────────────────────────────────────────────┘
```

### Simple summary

| Standard / Tool | Role |
|-----------------|------|
| SIEM / IDS / EDR | Detects incident signals |
| ISO 27001 | Defines governance and monitoring policy |
| ISO 27035 | Handles the incident after detection |
| NIST SP 800-61 | Practical incident response playbook |
| Law 18-07 | Legal notification obligation |

### Hackathon context for this project

For this project, the desktop app acts as the initial detection layer when users submit incident signals. It replaces a full SIEM/IDS stack in low-maturity environments, then feeds the ISO 27035 workflow in a realistic and valid way for organizations that are not yet fully instrumented.
