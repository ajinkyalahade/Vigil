# Vigil

> Your Mac's always-on security co-pilot — scan, surface, and fix with AI.

Vigil is a local-first macOS security dashboard that continuously audits your machine's security posture. It surfaces misconfigurations, vulnerable packages, exposed secrets, and open ports — then uses AI to walk you through fixing them, one step at a time, with you in control every step of the way.

No cloud. No telemetry. Runs entirely on `127.0.0.1`.

---

## Screenshots

### Overview — security grade at a glance
![Overview](docs/screenshots/overview.png)

### Scans — choose your scanners and run
![Scans](docs/screenshots/scans.png)

### Findings — every issue tracked across runs
![Findings](docs/screenshots/findings.png)

### Analytics — trends over time
![Analytics](docs/screenshots/analytics.png)

---

## How it works

### 1. Run a scan
Pick from 11 built-in scanners and hit **Run Scan**. Vigil inspects your system in seconds — firewall state, SSH key permissions, open TCP ports, shell history secrets, outdated Homebrew packages, pip/npm CVEs, and more.

### 2. Review findings
Every finding is categorised by severity (Critical → Info), tagged with the scanner that found it, and persisted across runs so you can track what's new, what's regressed, and what you've already fixed.

### 3. Let AI explain and fix it
Click any finding to get an AI-generated resolution powered by Claude. Vigil doesn't just tell you what's wrong — it produces a structured, step-by-step remediation plan with exact commands to run.

### 4. Human-in-the-loop execution
Each step is presented one at a time. You review the command, approve it, and Vigil executes it. Nothing runs without your explicit confirmation. If a step fails, the AI adapts.

### 5. Track your posture over time
The Analytics view shows High/Critical trends across all your scan runs, so you can see whether your security posture is improving.

---

## Features

| Feature | Details |
|---|---|
| **11 built-in scanners** | macOS hardening, SSH hygiene, env secrets, shell history, launch agents, network config, TCP ports, Homebrew, pip, npm, CVE lookups |
| **CVE detection** | OSV.dev integration — checks every installed pip and npm package against the vulnerability database |
| **AI remediation** | Claude-powered fix plans with exact shell commands, context-aware explanations, and step-by-step execution |
| **Human-in-the-loop** | You approve every command before it runs — no silent changes to your system |
| **Trend analytics** | Track Critical / High / Medium / Low / Info counts over time across all scan runs |
| **Safe by default** | Metadata-only scans; no file content reads by default. Binds to `127.0.0.1` only |
| **Offline capable** | Disable OSV and AI features to run fully air-gapped |

---

## Quickstart

### Backend (FastAPI + Python ≥ 3.10)
```bash
cd backend
python3.12 -m venv .venv
source .venv/bin/activate
pip install -U pip setuptools wheel
pip install -e ".[dev]"
cp .env.example .env          # add your Anthropic API key for AI features
python -m uvicorn security_check.app:app --reload --host 127.0.0.1 --port 8000
```

### Frontend (React + Vite)
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Open `http://localhost:5173`.

---

## AI-powered remediation setup

To enable AI fix suggestions and step-by-step execution, add your Anthropic API key to `backend/.env`:

```
SC_ANTHROPIC_API_KEY=sk-ant-...
```

AI features are optional — all scanning works without them.

---

## What gets scanned

| Scanner | Category | What it checks |
|---|---|---|
| macOS Hardening | config | Firewall, Gatekeeper, SIP, FileVault |
| SSH Permissions | config | `~/.ssh` key/config file permission hygiene |
| Environment Variable Secrets | secrets | Common secret patterns in your shell environment |
| Shell History Secrets | secrets | Leaked credentials in bash/zsh history |
| Launch Agents & Login Items | config | Unexpected persistence mechanisms |
| Network Configuration | config | DNS, proxy, interface security settings |
| Listening TCP Ports | network | All open ports via `lsof` |
| Homebrew Outdated | inventory | Outdated formulae and casks |
| pip Inventory | inventory | Installed Python packages |
| npm Global Inventory | inventory | Globally installed npm packages |
| OSV Vulnerabilities | CVEs | Known CVEs for all inventoried pip/npm packages |

---

## Configuration

| Env var | Default | Description |
|---|---|---|
| `SC_DB_PATH` | `data/security-check.db` | SQLite database path |
| `SC_ANTHROPIC_API_KEY` | — | Anthropic API key for AI features |
| `SC_ANTHROPIC_MODEL` | `claude-sonnet-4-5-20250929` | Model used for resolutions |
| `SC_API_TOKEN` | — | Optional Bearer token to protect the API |
| `SC_OSV_API_BASE` | `https://api.osv.dev` | Set empty to disable CVE lookups |
| `SC_DISABLE_AI_RESOLUTION` | `false` | Disable AI features entirely |
| `SC_EXECUTION_ENABLED` | `true` | Allow step execution from the UI |
| `SC_CORS_ORIGINS` | Vite dev server | Allowed CORS origins |

---

## Extending Vigil

Adding a new scanner takes three steps:

1. Create a scanner under `backend/src/security_check/scanners/`
2. Register it in `backend/src/security_check/runner.py` (`default_registry()`)
3. Restart the backend — it appears in the UI automatically

---

## Safety

- Backend binds to `127.0.0.1` only — never exposed to the network
- Scanners read metadata (versions, permissions, ports) — no file content by default
- OSV checks send `package@version` to the OSV API — no file paths or personal data
- AI execution is opt-in per step — you approve every command before it runs
- Do not run Vigil against machines you don't own or have explicit permission to assess
