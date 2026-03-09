#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BACKEND_PY="${ROOT_DIR}/backend/.venv/bin/python"

if [[ ! -x "${BACKEND_PY}" ]]; then
  echo "Backend virtualenv not found at backend/.venv."
  echo ""
  echo "Create it:"
  echo "  cd backend"
  echo "  python3.12 -m venv .venv   # or any Python >= 3.10"
  echo "  source .venv/bin/activate"
  echo "  python -m pip install -U pip setuptools wheel"
  echo "  python -m pip install -e \".[dev]\""
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm not found on PATH. Install Node.js/npm first."
  exit 1
fi

if [[ ! -d "${ROOT_DIR}/frontend/node_modules" ]]; then
  echo "Frontend dependencies missing (frontend/node_modules not found)."
  echo ""
  echo "Install them:"
  echo "  cd frontend"
  echo "  npm install"
  exit 1
fi

BACKEND_PID=""

cleanup() {
  if [[ -n "${BACKEND_PID}" ]] && kill -0 "${BACKEND_PID}" >/dev/null 2>&1; then
    kill "${BACKEND_PID}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

echo "Starting backend: http://127.0.0.1:8000"
(
  cd "${ROOT_DIR}/backend"
  export PYTHONPATH="${ROOT_DIR}/backend/src"
  exec "${BACKEND_PY}" -m uvicorn security_check.app:app --reload --host 127.0.0.1 --port 8000
) &
BACKEND_PID="$!"

echo "Starting frontend: http://localhost:5173"
cd "${ROOT_DIR}/frontend"
npm run dev

