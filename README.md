# Vigil

Local-first macOS security admin dashboard:
- React dashboard UI (run scans, view findings, trends, diffs)
- FastAPI backend (scanner orchestration, SQLite storage)
- Safe-by-default scanners (metadata only; no secret-content reads by default)

## Quickstart (dev)

### 1) Backend (FastAPI)
```bash
cd backend
python3.12 -m venv .venv  # or any Python >= 3.10
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e ".[dev]"
cp .env.example .env  # optional
python -m uvicorn security_check.app:app --reload --host 127.0.0.1 --port 8000
```

### 2) Frontend (React)
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Open `http://localhost:5173`.

## What it scans (today)
- macOS hardening posture (firewall, Gatekeeper, SIP, FileVault) — best effort
- SSH permission hygiene (`~/.ssh` metadata only)
- Homebrew outdated packages (not CVE-aware)
- pip and global npm inventory (from the environment you run the backend in)
- Listening TCP ports (lsof, best-effort)
- OSV vulnerability lookups for inventoried pip/npm packages (requires internet access)

## Safety notes
- Backend is intended to bind to `127.0.0.1` only.
- No default “deep scans” of file contents. The app focuses on versions/config/permissions/ports.
- OSV vulnerability checks send `package@version` queries to the configured OSV API endpoint; disable by setting `SC_OSV_API_BASE=` if you want fully offline scans.
- Do not run scans on machines you do not own or have explicit permission to assess.

## Useful env vars
- `SC_DB_PATH` (default: `data/security-check.db`)
- `SC_CORS_ORIGINS` (default allows Vite dev server)
- `SC_API_TOKEN` (if set, requires `Authorization: Bearer <token>` on all `/api/*`)
- `SC_OSV_API_BASE` (set empty to disable OSV)

## Extending scanners
1. Add a scanner under `backend/src/security_check/scanners/`
2. Register it in `backend/src/security_check/runner.py` (`default_registry()`)
3. Restart the backend
