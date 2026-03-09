# Vigil (Backend)

## Dev
Create a virtualenv, then install:
- `python -m pip install -U pip setuptools wheel`
- `python -m pip install -e ".[dev]"`

Run:
- `python -m uvicorn security_check.app:app --reload --host 127.0.0.1 --port 8000`

Environment:
- Copy `.env.example` → `.env` (optional)
