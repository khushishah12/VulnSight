# VulnSight

VulnSight is a small, local-first web application vulnerability assessment and
remediation platform for the OWASP Top 10:2025.

This repository currently contains the **Step 4 backend and database**:

- React + TypeScript + Tailwind CSS frontend.
- FastAPI + Pydantic REST API.
- SQLAlchemy async + asyncpg database layer with connection pooling and TLS.
- Ten normalized tables managed by Alembic and migrated to Neon.
- Scan, finding, remediation, verification, report, and audit APIs.
- API and database health checks.
- A frontend status page that verifies the connection chain.

No vulnerability scanners, crawler, or authentication have been implemented
yet. Starting a scan runs a clearly labeled placeholder that performs no
network requests and creates no findings.

## Requirements

- Node.js 22+ and npm 11+
- Python 3.13+ (`py` launcher on Windows)
- Git
- A Neon PostgreSQL project and connection string

## First-time setup

```powershell
cd D:\projects\VULNDETECTOR

# Backend virtual environment and dependencies
py -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt

# Frontend dependencies
cd frontend
npm install
cd ..
```

Create `backend/.env` from the example and add your Neon direct connection
string:

```powershell
Copy-Item backend\.env.example backend\.env
notepad backend\.env
```

Apply the database migration once:

```powershell
cd backend
.\.venv\Scripts\alembic.exe upgrade head
cd ..
```

## Run locally

Terminal 1 — backend:

```powershell
cd D:\projects\VULNDETECTOR\backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Terminal 2 — frontend:

```powershell
cd D:\projects\VULNDETECTOR\frontend
npm run dev
```

Open:

- Frontend: <http://127.0.0.1:5173>
- API docs: <http://127.0.0.1:8000/docs>
- API health: <http://127.0.0.1:8000/api/v1/health>
- Database health: <http://127.0.0.1:8000/api/v1/health/db>

The React app calls `/api/v1` through Vite's development proxy. It never
receives the database connection string. FastAPI is the only component that
talks to Neon.

## Verify

```powershell
cd D:\projects\VULNDETECTOR\backend
.\.venv\Scripts\python.exe -m pytest -q

cd ..\frontend
npm run build
```

## Documentation

- Requirements: `docs/SRS.md`
- Architecture: `docs/architecture.md`
- Step 3 setup guide: `docs/setup.md`
- Database architecture and schema: `docs/database.md`
- API reference and scan lifecycle: `docs/api.md`
