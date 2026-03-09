.PHONY: dev-backend dev-frontend test-backend test-frontend

dev-backend:
	cd backend && ./.venv/bin/python -m uvicorn security_check.app:app --reload --host 127.0.0.1 --port 8000

dev-frontend:
	cd frontend && npm run dev

test-backend:
	cd backend && ./.venv/bin/python -m pytest -q

test-frontend:
	cd frontend && npm test
