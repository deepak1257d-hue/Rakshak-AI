# AEGIS AI / Rakshak AI – Enterprise CTEM Platform

Continuous Threat Exposure Management (CTEM) and Autonomous Security Orchestration Platform.
Integrates Multi-Agent LangGraph verification, Model Context Protocol (MCP) tool execution, real GitHub Pull Request remediation, PostgreSQL checkpoint persistence, and OWASP DAST/SCA auditing.

---

## 🚀 How to Run the Platform

### 1. Prerequisites
- **Python:** 3.12+ (or 3.11+)
- **Node.js:** 18+ (LTS) & npm
- **Docker & Docker Compose:** Optional for containerized deployment (PostgreSQL, Redis, ClickHouse, Langfuse, Juice Shop)
- **Security Scanners:** Nmap, OWASP ZAP, Nuclei, Trivy (see installation guide below)

---

### 2. Local Development Quickstart

#### A. Backend Setup
1. **Navigate to the root and activate the Python virtual environment:**
   ```powershell
   # Windows PowerShell
   .\.venv\Scripts\Activate.ps1
   # Linux/macOS
   source .venv/bin/activate
   ```
2. **Install Python dependencies:**
   ```bash
   pip install -r backend/requirements.txt
   ```
3. **Configure Environment Variables:**
   Copy `.env.example` to `.env`:
   ```powershell
   Copy-Item .env.example .env
   ```
   Set your `SECRET_KEY` and any integration credentials (such as `GITHUB_TOKEN`, `OPENAI_API_KEY`, etc.).

4. **Start the FastAPI Backend:**
   ```powershell
   $env:PYTHONPATH="backend"
   .\.venv\Scripts\python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```
   Backend will be running at [http://localhost:8000](http://localhost:8000)
   - Interactive Swagger API docs: [http://localhost:8000/docs](http://localhost:8000/docs)
   - Healthcheck: [http://localhost:8000/health](http://localhost:8000/health)
   - Scanner Healthcheck: [http://localhost:8000/health/scanners](http://localhost:8000/health/scanners)

#### B. Frontend Setup
1. **Navigate to frontend directory:**
   ```powershell
   cd frontend
   npm install
   ```
2. **Run the Next.js Development Server:**
   ```powershell
   npm run dev
   ```
   Frontend will be running at [http://localhost:3000](http://localhost:3000).

---

### 3. Docker Compose Full Stack Deployment

To run the complete production stack (Backend, Frontend, PostgreSQL, Redis, ClickHouse, Langfuse Observability, and OWASP Juice Shop target):

```powershell
# 1. Validate configuration
docker compose config

# 2. Build and launch services in background
docker compose up -d --build

# 3. Check status
docker compose ps

# 4. View logs
docker compose logs -f backend
```

---

## 🛠️ Security Scanner Binaries Installation

AEGIS integrates with real security scanners via the MCP layer. If a binary is missing on the system, AEGIS detects this safely and marks the scanner as `UNAVAILABLE` without failing or generating synthetic findings.

### Windows Installation
- **Nmap:** `winget install Insecure.Nmap` or download from [https://nmap.org/download.html](https://nmap.org/download.html)
- **OWASP ZAP:** `winget install OWASP.ZAP` or download installer from [https://www.zaproxy.org/download/](https://www.zaproxy.org/download/)
- **Nuclei:** `winget install ProjectDiscovery.Nuclei` or via Go: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
- **Trivy:** `winget install AquaSecurity.Trivy` or `scoop install trivy`

### Linux (Ubuntu/Debian) Installation
```bash
# Nmap
sudo apt-get update && sudo apt-get install -y nmap

# OWASP ZAP
sudo apt-get install -y zaproxy

# Nuclei
sudo apt-get install -y nuclei || binary from https://github.com/projectdiscovery/nuclei/releases

# Trivy
sudo apt-get install -y wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install -y trivy
```

---

## 🔐 GitHub Pull Request Remediation Setup

AEGIS features an automated Human-in-the-Loop (HITL) remediation workflow:
1. Create a GitHub Personal Access Token (classic or fine-grained) with `repo` permissions (Read and Write to repository contents and pull requests).
2. Set the token in `.env`:
   ```env
   GITHUB_TOKEN=ghp_your_secure_personal_access_token
   GITHUB_API_URL=https://api.github.com
   ```
3. When a security finding is approved in the dashboard by an Analyst or Admin, AEGIS:
   - Validates repository ownership and branch existence.
   - Checks for existing open duplicate PRs.
   - Creates a dedicated branch (`aegis/remediation-<finding>`).
   - Commits the exact approved patch diff.
   - Opens a Pull Request with complete vulnerability details and CVSS scoring.
   - Auto-merge is strictly disabled.

---

## 🐘 PostgreSQL LangGraph Checkpoint Recovery

For enterprise deployments requiring persistent multi-turn workflow checkpoints across server restarts:
1. Provide a standard PostgreSQL connection URI in `.env`:
   ```env
   POSTGRES_CHECKPOINT_URL=postgresql://user:password@localhost:5432/aegis_checkpoints
   ```
2. AEGIS initializes `PostgresSaver.from_conn_string()` and creates the necessary checkpoint schemas automatically.
3. If `POSTGRES_CHECKPOINT_URL` is set but connection fails, AEGIS raises an explicit `RuntimeError` rather than silently degrading to in-memory state.

---

## 🌐 Production CORS Configuration

The backend enforces strict CORS validation:
- Set `CORS_ORIGINS` in `.env` as comma-separated strings or JSON arrays:
  ```env
  CORS_ORIGINS=https://app.your-domain.com,https://your-domain.vercel.app,http://localhost:3000
  ```
- **Security Rules:**
  - Wildcard (`*`) is strictly rejected in production when credentials are enabled.
  - Paths, query strings, and fragments in origins are rejected at startup.

---

## 🧪 Running the Verification Test Suite

```powershell
# 1. Run all backend tests (80+ tests)
$env:PYTHONPATH="backend"
.\.venv\Scripts\python -m pytest -v

# 2. Run frontend unit tests
cd frontend
npm test -- --run

# 3. Verify TypeScript compilation
npx tsc --noEmit

# 4. Verify Next.js production build
npm run build
```
