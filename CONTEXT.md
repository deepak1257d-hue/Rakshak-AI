# AEGIS: Continuous Threat Exposure Management (CTEM) Platform
## Project Context & Technical Architecture Summary

---

## 1. Executive Summary

**AEGIS** is a Continuous Threat Exposure Management (CTEM) application with a Next.js frontend and FastAPI backend. It supports workspace-scoped targets, ownership verification, scans, findings, risk summaries, and approval records.

The backend orchestrates scanners through MCP and records approval decisions through authenticated API routes. Missing scanners and the not-yet-implemented GitHub integration are reported as unavailable; they do not produce synthetic findings or pull-request links.

---

## 2. System Architecture & Tech Stack

```
   ┌──────────────────────────────────────────────────────────────┐
   │                   AEGIS FRONTEND (Next.js 15)                │
   │  Tailwind CSS • Real-time WebSockets • Dark Cybersecurity UI │
   └──────────────────────────────┬───────────────────────────────┘
                                  │ HTTP / REST / WS
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                   AEGIS BACKEND (FastAPI)                    │
   │   Async SQLAlchemy • SQLite / PostgreSQL • Pydantic v2       │
   └──────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │           LANGGRAPH MULTI-AGENT ORCHESTRATION GRAPH          │
   │                                                              │
   │  [Planner] ──► [Executor] ──► [Untrusted Parser]             │
   │                     ▲                  │                     │
   │                     │ (Retry/Loop)     ▼                     │
   │                 [Verifier] ◄───────────┘                     │
   │                     │ (Empirical Proof)                      │
   │                     ▼                                        │
   │                [Reasoning] ──► [Reporter]                    │
   │                                    │                         │
   │                                    ▼                         │
   │                        [Review / Approval Gate]              │
   │                                    │                         │
   │                                    ▼                         │
   │                 [Authenticated API; GitHub unavailable]      │
   └──────────────────────────────┬───────────────────────────────┘
                                  │
          ┌───────────────────────┴───────────────────────┐
          ▼                                               ▼
┌───────────────────────────────┐       ┌───────────────────────────────┐
│       MCP TOOL LAYER          │       │    LANGFUSE OBSERVABILITY     │
│ Python MCP SDK Server Sandboxes│      │ OpenTelemetry Tracing, Token  │
│ • Nmap (Port & Recon)         │       │ Tracking & Cost Analytics     │
│ • OWASP ZAP (Web Baseline)    │       └───────────────────────────────┘
│ • Nuclei (CVE Templates)      │
│ • Trivy (SCA & Container)     │
│ • GitHub (PR dispatch not implemented)│
└───────────────────────────────┘
```

### Technology Matrix
- **Backend Core:** Python 3.12+, FastAPI, Async SQLAlchemy, SQLite (`aegis.db`), Pydantic v2.
- **Workflow & AI Agents:** LangGraph (`StateGraph`), `MemorySaver` by default, optional PostgreSQL checkpointer via `POSTGRES_CHECKPOINT_URL`.
- **Tool Protocol:** Model Context Protocol (MCP) Python SDK servers for isolated tool execution.
- **Observability:** Langfuse v3 SDK, OpenTelemetry span exporting, automated token and latency auditing.
- **Frontend App:** Next.js 15.5, React 18, TypeScript, Tailwind CSS, Lucide React, Recharts.
- **Containerization:** Multi-stage Dockerfiles (`backend/Dockerfile`, `frontend/Dockerfile`) and unified root `docker-compose.yml`.

---

## 3. The 8-Stage Multi-Agent Workflow Pipeline

Every audit cycle executes through eight strictly sequenced and validated stages:

1. **Asset Management & Hardened Ownership Gatekeeper:**
   - Enforces cryptographic ownership verification before any scanner or MCP tool is permitted to run.
   - Verification methods:
     1. **DNS TXT Record:** Looks for record matching `aegis-verification=<token>`.
     2. **HTML Meta Tag:** Looks for supported AEGIS/Rakshak verification meta tags over verified HTTPS.
     3. **HTTP Well-Known File (`HTTP_FILE`):** Looks for a supported verification file over verified HTTPS.
   - **HTTP verification restrictions:**
     - HTTPS certificate verification is enabled; redirects are not followed.
     - DNS resolution rejects non-public addresses and pins each request to a resolved public IP while preserving the original Host header and TLS SNI.
   - **Strict Token Security:**
     - Raw tokens and arbitrary prefixes are rejected.
     - Tokens are compared using constant-time `hmac.compare_digest` to prevent timing attacks.
     - Legacy token formats are accepted only on supported verification endpoints and logged.
   - **Strict Server-Controlled Lab Mode:**
     - Client-controlled `simulate` parameter has been permanently removed and forbidden (requests with `simulate=True` fail with HTTP 400).
     - No keyword or substring matching (e.g. `test`, `demo`, `cyber`, `vercel.app`, `netlify.app` are not bypassed and must undergo real verification).
     - Lab bypass is allowed **only** if `settings.ENV == "development"` AND the host matches an exact entry in `settings.DEV_LAB_HOSTS` (`["localhost", "127.0.0.1", "juice-shop.cyber.local"]`).
     - The application **refuses to start** (raises critical runtime/validation error) if lab mode hosts are configured when `ENV != "development"`.
     - Targets verified via lab bypass are flagged with `verification_method="LAB"`, `is_lab=True`, and carry a `"LAB - not proven ownership"` badge in UI and reports.
   - Any scan attempted on unverified assets is aborted immediately with `HTTP 403 Forbidden`.

2. **Planner Agent:**
   - Evaluates the target profile and formulates a multi-phase audit plan (`AuditPlan`).
   - Assigns scoped tasks to specific tools based on an immutable agent allowlist (`AGENT_TOOL_ALLOWLISTS`).

3. **Executor Agent (MCP Tool Layer):**
   - Dispatches execution tasks to isolated MCP servers:
     - `nmap_port_scan`: Network discovery and version banner identification.
     - `zap_baseline_scan`: HTTP headers, cookie security, and baseline web vulnerabilities.
     - `nuclei_scan`: Template-based fuzzing and CVE signature matching.
     - `trivy_scan`: Software Composition Analysis (SCA) for third-party dependencies.
   - If a scanner binary is absent or exits unsuccessfully, the phase is marked failed/unavailable and results may be partial; no simulated findings are emitted.
   - Enforces scope limits: restricts scan duration, bounds rate limits, and rejects destructive flags.

4. **Untrusted Parser Agent (Prompt Injection Neutralization):**
   - Assumes all tool outputs (HTTP banners, error pages, SQL errors) could contain adversarial injection payloads.
   - Strips hostile prompts, overrides, and hidden markdown instructions (replacing them with `[REDACTED_PROMPT_INJECTION]`).
   - Coerces unstructured raw outputs into strictly validated `SanitizedFindingSchema` Pydantic models.

5. **Verifier Agent (Reachability & False-Positive Elimination):**
   - Demands empirical proof of reachability before confirming any finding.
   - If evidence is inconclusive and loop count is under the bound (`loop_count < 2`), routes back to the Planner for targeted re-testing.

6. **System Reasoning Engine:**
   - Uses a curated CVSS v3.1 base score only for CVEs present in the local catalog; it scales that value by 10 for display.
   - No exposure, authentication, exploit-availability, or compensating-control modifiers are applied. Findings without a catalogued CVE have no numeric score.
   - Produces remediation suggestions; these are not automatically applied.

7. **Human-in-the-Loop (HITL) Approval Gate:**
   - The workflow may interrupt to present patches, but workflow-thread decisions are not authenticated and cannot authorize dispatch.
   - The authenticated `/api/v1/reports/remediate/decision` route records approval/rejection and binds approval to the user, finding, repository, and patch hash.
   - GitHub PR creation is not implemented. Dispatch attempts return unavailable; no PR is claimed as created.

8. **Reporter Agent & Telemetry Export:**
   - Reports verified findings, partial execution status, and measured CVSS base scores; unavailable scores and remediation-time estimates remain null.
   - Attaches trace identifiers/URLs when configured; absent telemetry is not replaced with sample values.

---

## 4. Security Guardrails & Defense Boundaries

| Defense Boundary | Mechanism | Failure Mode / Handling |
| :--- | :--- | :--- |
| **Cryptographic Ownership Proof** | Strict DNS TXT, HTML meta tag, or `/.well-known` file check via `hmac.compare_digest` | Immediate refusal (HTTP 400) & pre-scan abort (HTTP 403) across all MCP servers |
| **Strict Server-Controlled Lab Mode** | Allowed ONLY if `ENV == "development"` and domain matches exact `DEV_LAB_HOSTS` | Refuses startup in prod with error; client `simulate` parameter strictly forbidden |
| **Least-Privilege Tools** | Per-agent permission table (`AGENT_TOOL_ALLOWLISTS`) | `ToolAuthorizationError` if an agent calls an unauthorized tool |
| **Scope Limits** | `validate_scope_limits()` checking flags, ports, and duration | Rejects destructive scans (e.g. `-D`, aggressive modes) |
| **CORS** | Explicit allowlist from `CORS_ORIGINS` (default: `http://localhost:3000`) | Preflights from unlisted origins are rejected |
| **Prompt Injection Defense** | Input sanitization & token redaction in untrusted parser | Neutralizes injection payloads to `[REDACTED_PROMPT_INJECTION]` |
| **Scanner Resilience** | Exponential backoff (`execute_with_exponential_backoff`) | Falls back to alternative tools (e.g. ZAP &rarr; Nuclei) & partial results |
| **HITL Approval** | Authenticated API records approver, finding, workspace, and patch hash | Workflow-thread decisions cannot authorize dispatch; GitHub PR creation is unavailable |

---

## 5. Database Schema & API Endpoints

### Models
- **`workspaces`**: Multi-tenant isolation boundary (`id`, `name`, `slug`, `created_at`).
- **`users`**: Role-based access control (`SECURITY_ANALYST`, `AUDITOR`, `ADMIN`) with bcrypt password hashing.
- **`target_assets`**: Registered domains/URLs, verification tokens, method (`DNS_TXT`, `HTML_META`, `HTTP_FILE`, `LAB`), status (`PENDING`, `VERIFIED`, `REVOKED`), and last verified timestamp.
- **`scan_runs`**: Scan executions (`QUEUED`, `RUNNING`, `COMPLETED`, `PARTIAL`, `FAILED`), progress percentages, stages, and Langfuse `trace_id`.
- **`findings`**: Individual findings, nullable scaled CVSS base score and score source, severity, reachability proof, and remediation patch.
- **`audit_logs`**: Security action records, including approver identity and remediation patch hash. The current schema does not store raw workflow state.
- **Startup migrations:** Add `audit_logs.remediation_hash`, `findings.score_source`, and `scan_runs.trace_id`/`trace_url` when missing; legacy unverified scores are cleared. No separate Alembic migration is present.

### Primary API Routes
- `POST /api/v1/auth/register` & `POST /api/v1/auth/token` &ndash; JWT Authentication.
- `GET /api/v1/targets` & `POST /api/v1/targets` &ndash; Asset intake and listing.
- `GET /api/v1/targets/{id}` &ndash; Direct single-target asset retrieval with dynamically evaluated `lab_mode` eligibility.
- `POST /api/v1/targets/{id}/verify` &ndash; Hardened ownership verification (`DNS_TXT`, `HTML_META`, `HTTP_FILE`, or `LAB` for allowlisted hosts in dev). Client `simulate` parameter forbidden.
- `POST /api/v1/scans` & `GET /api/v1/scans/{id}` &ndash; Scan dispatch and progress.
- `WS /api/v1/scans/{id}/ws` &ndash; Live scan telemetry; JWT identity and workspace/scan ownership are validated before acceptance.
- `GET /api/v1/reports/executive-summary/{scan_id}` &ndash; Executive audit report, ownership badges, and Langfuse trace link.
- `POST /api/v1/reports/remediate/decision` &ndash; Authenticated approval/rejection recording and attempted dispatch. GitHub dispatch currently returns unavailable.
- `POST /api/v1/reports/remediate/github-pr` &ndash; Requires a matching approval from the authenticated user; cannot bypass the decision route.

---

## 6. Frontend Application Architecture

The frontend is a Next.js 15 application styled with Tailwind CSS in a dark cybersecurity palette:
- **`src/app/page.tsx`**: Landing screen with authentication (JWT login/register) and rapid target intake.
- **`src/app/websites/page.tsx`**: Target inventory dashboard displaying backend target and verification data.
- **`src/app/websites/[id]/page.tsx`**: 6-step target detail view:
  1. *Target Registration*
  2. *Ownership Verification* (DNS TXT, HTML Meta tag, and canonical well-known file with legacy AEGIS path fallback, plus development-only lab verification)
  3. *Scanning Pipeline* (Real-time telemetry, phase timeline, and console output)
  4. *Vulnerabilities & Risk Scorecard* (Interactive filters and severity breakdown; numeric score only when catalog data exists)
  5. *Remediation & HITL* (Patch review and authenticated approval; GitHub PR creation is unavailable)
  6. *Executive Summary & Audit Trail* (Backend summary and optional Langfuse trace data)
- **`src/components/ScanningPipeline.tsx`**: Live scanner UI with WebSocket real-time updates and graceful polling fallback.
- **`src/components/VulnerabilitiesView.tsx`**: Vulnerability table and scorecard with conspicuous `"LAB - not proven ownership"` banner when inspecting lab-verified targets.
- **`src/components/FindingSideDrawer.tsx`**: Slide-out drawer presenting backend-provided evidence, optional score, and patch preview.
- **`src/lib/api.ts`**: Typed API client handling JWT tokens, REST endpoints, verification methods, and authenticated WebSocket connections.

---

## 7. Containerization & Orchestration

The platform includes full Docker containerization:
- **`backend/Dockerfile`**: Python slim image with Nmap, curl, git, CA certificates, and a FastAPI healthcheck. Other scanner binaries are not bundled.
- **`frontend/Dockerfile`**: Multi-stage Node.js image building Next.js 15 into a production runner.
- **`docker-compose.yml`**: Unified single-command deployment running:
  - `backend` (FastAPI + LangGraph + Python MCP SDK on port 8000)
  - `frontend` (Next.js on port 3000)
  - `juice-shop` (OWASP Juice Shop test target on port 3005)
  - `langfuse-web` (Langfuse UI on port 3001)
  - `langfuse-worker`, `langfuse-db` (Postgres 16), `clickhouse`, `redis`

---

## 8. Current Project Health & Verification Status

- **Backend:** `61 passed, 1 skipped` across the full test suite. The skipped case is a legacy workflow-thread dispatch test; authenticated REST approval and non-authoritative workflow-thread behavior are tested separately. Python sources and tests compile.
- **Frontend:** Standalone validation passed all five assertions: TypeScript, 2 Vitest tests, production build, ESLint, and an HTTP 200 probe of `/`. Results are recorded in `frontend/.tsupgrader/runtime-validation/standalone-result.json`.
- **Workspace diagnostics:** No Pylance error-severity diagnostics after adding the backend import path for the root demo script.
- **Containers:** Both Compose files parse as YAML. Docker Compose runtime validation could not run because Docker is not installed in this environment.
- **Deployment configuration:** Set `CORS_ORIGINS` to a JSON list of exact frontend origins when deploying outside the localhost default.
- **PostgreSQL:** Checkpointer initialization failure and resource cleanup are unit-tested; live PostgreSQL connectivity has not been tested.
- **Scanner availability:** Nmap is installed in the backend image; ZAP, Nuclei, and Trivy require separate installation. Missing tools are surfaced as unavailable.
- **GitHub:** A real GitHub API integration and PR creation are not implemented.

---

## 9. Development & Operations Guide

### Prerequisites
- Python 3.12+ (the current workspace virtual environment is at the repository root in `.venv`)
- Node.js 18+ and npm
- Docker & Docker Compose

### Running via Docker Compose (Recommended)
```powershell
docker compose up -d
```
- Create the root `.env` from `.env.example` and replace required placeholders first. `NEXT_PUBLIC_API_BASE` is injected at frontend build time and must use a URL reachable by the browser (default: `http://localhost:8000/api/v1`).
- Frontend UI: `http://localhost:3000`
- Backend API Docs: `http://localhost:8000/docs`
- Langfuse Observability: `http://localhost:3001`
- OWASP Juice Shop Target: `http://localhost:3005`

### Running Locally (Without Docker)

**Backend** (create/configure the root `.env` first; the application requires `SECRET_KEY`):
```powershell
cd "backend"
$env:PYTHONPATH = "."
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Frontend:**
```powershell
cd "frontend"
Copy-Item .env.example .env.local
npm run dev
```

**Running Tests:**
```powershell
cd "backend"
$env:PYTHONPATH = "."
..\.venv\Scripts\python.exe -m pytest tests
```

**Running the End-to-End Demonstration Script:**
```powershell
.\.venv\Scripts\python.exe scripts\demo_scan.py --target "juice-shop.cyber.local"
```
The target must already exist in the backend database and have verified ownership. The script runs available tools only; it does not create a simulated target, approval, or pull request. Optional PostgreSQL workflow checkpoints require `POSTGRES_CHECKPOINT_URL` and a reachable PostgreSQL database.
