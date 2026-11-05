# VulnSight — Step 3 Setup and Foundation

| Field | Value |
|---|---|
| Project | VulnSight — Web Application Vulnerability Assessment Platform |
| Step | 3 — Development environment and foundation |
| Status | Complete — React, FastAPI, and Neon verified locally through the direct endpoint |
| Date | 05 November 2026 |
| Scope | Environment setup, project skeleton, health checks, and first end-to-end connection |
| Not in scope | Database tables, authentication, scanners, reports |

> **Checkpoint rule:** this step stops once React, FastAPI, and the Neon health
> check work. No vulnerability scanner or database schema is implemented here.
>
> **Step 4 update:** the database schema, models, migrations, and API are now
> implemented. See [`database.md`](./database.md) and [`api.md`](./api.md).
> Statements below that describe tables or migrations as "future" apply only to
> the Step 3 checkpoint.

---

## 1. What Was Verified on This Machine

These checks were run before setup:

```powershell
node --version
npm --version
py --version
git --version
code --version
```

| Tool | Detected | Notes |
|---|---|---|
| Node.js | `v22.20.0` | Satisfies Vite 8's Node requirement |
| npm | `11.14.1` | Installs frontend packages |
| Python | `3.13.7` through `py` | `python` is currently a Microsoft Store alias, so use `py` |
| pip | `26.3` inside the new virtual environment | Installs backend packages |
| Git | `2.54.0` | Version control |
| VS Code | Installed | `code` command is available |
| Postman | Not detected | Optional; `/docs` and `Invoke-RestMethod` are enough |
| GitHub CLI (`gh`) | Not detected | Optional; the GitHub website can create the repository |

The project was scaffolded with:

| Package | Installed version |
|---|---|
| React | 19.3.1 |
| TypeScript | 7.0.2 |
| Vite | 8.3.6 |
| Tailwind CSS | 4.3.4 |
| FastAPI | 0.162.0 |
| Uvicorn | 0.54.0 |
| Pydantic Settings | 2.16.2 |
| SQLAlchemy | 2.1.8 |
| asyncpg | 0.32.0 |
| Alembic | 1.20.1 |
| pytest | 9.2.0 |

Version numbers can move over time. `backend/requirements.txt` pins the backend
versions used for this foundation.

---

## 2. Tool Guide

### 2.1 Node.js

- **What it does:** runs JavaScript outside the browser and provides the runtime
  for frontend build tools.
- **Why VulnSight needs it:** Vite, React's development server, TypeScript, and
  Tailwind all run on Node.js during development and build time.
- **Install on Windows:** download the LTS installer from
  <https://nodejs.org>, or run:
  ```powershell
  winget install OpenJS.NodeJS.LTS
  ```
- **Verify:**
  ```powershell
  node --version
  ```
  You should see a version such as `v22.20.0`.

### 2.2 npm

- **What it does:** installs and manages JavaScript packages and runs project
  scripts.
- **Why VulnSight needs it:** installs React, Vite, TypeScript, Tailwind, and
  their plugins, then runs `npm run dev` and `npm run build`.
- **Install:** npm is included with Node.js. Do not install it separately.
- **Verify:**
  ```powershell
  npm --version
  ```
  You should see a version such as `11.14.1`.

### 2.3 React

- **What it does:** builds the browser interface from reusable components.
- **Why VulnSight needs it:** the user will use React pages to add targets,
  start scans, review findings, read remediation, and download reports.
- **Install:** it is a project dependency, not a global program:
  ```powershell
  cd D:\projects\VULNDETECTOR\frontend
  npm install
  ```
- **Verify:** `react` appears in `frontend/package.json`, and
  `npm run build` succeeds.

### 2.4 TypeScript

- **What it does:** adds static types to JavaScript so mistakes are caught
  before the page runs.
- **Why VulnSight needs it:** API responses, findings, scan states, and
  remediation data have many fields. Types make those contracts easier to
  change safely.
- **Install:** included in the Vite React TypeScript template and installed by
  `npm install`.
- **Verify:**
  ```powershell
  cd D:\projects\VULNDETECTOR\frontend
  npx tsc --version
  ```
  The build command also runs TypeScript: `npm run build`.

### 2.5 Tailwind CSS

- **What it does:** provides utility classes for styling directly in JSX.
- **Why VulnSight needs it:** it keeps the small MVP interface consistent
  without a large custom CSS system.
- **Install:** already installed as a project dependency:
  ```powershell
  cd D:\projects\VULNDETECTOR\frontend
  npm install tailwindcss @tailwindcss/vite
  ```
- **Verify:** `frontend/src/styles/globals.css` starts with
  `@import "tailwindcss";`, and the build produces a CSS file with styles.

### 2.6 Python

- **What it does:** runs the backend, scanner modules, and database code.
- **Why VulnSight needs it:** FastAPI, SQLAlchemy, asyncpg, Alembic, and the
  future vulnerability checks are Python.
- **Install:** on Windows, install Python 3.13 from
  <https://www.python.org/downloads/windows/> and enable **Add python.exe to
  PATH**. The Microsoft Store alias can be disabled in **Settings → Apps →
  Advanced app settings → App execution aliases**.
- **Verify:**
  ```powershell
  py --version
  ```
  This machine returns `Python 3.13.7`. If `python --version` opens the
  Microsoft Store, use `py` until the alias is fixed.

### 2.7 Python virtual environment

- **What it does:** creates an isolated Python installation for one project.
- **Why VulnSight needs it:** backend packages stay separate from other Python
  projects and from the system interpreter.
- **Create it:**
  ```powershell
  cd D:\projects\VULNDETECTOR
  py -m venv backend\.venv
  ```
- **Activate it:**
  ```powershell
  cd D:\projects\VULNDETECTOR\backend
  .\.venv\Scripts\Activate.ps1
  ```
  If PowerShell blocks the script for the current session:
  ```powershell
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\.venv\Scripts\Activate.ps1
  ```
- **Verify:**
  ```powershell
  python --version
  pip --version
  ```
  The Python path should contain `backend\.venv`.

### 2.8 FastAPI

- **What it does:** a Python web framework for building the REST API.
- **Why VulnSight needs it:** every browser request goes through FastAPI. It
  validates input, enforces authorization, starts scans, and is the only
  component allowed to talk to Neon.
- **Install:** inside the activated virtual environment:
  ```powershell
  cd D:\projects\VULNDETECTOR
  backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
  ```
- **Verify:**
  ```powershell
  backend\.venv\Scripts\python.exe -c "import fastapi; print(fastapi.__version__)"
  ```
  This foundation uses FastAPI `0.162.0`.

### 2.9 Uvicorn

- **What it does:** runs the FastAPI application as an HTTP server.
- **Why VulnSight needs it:** during local development it serves the API on
  `127.0.0.1:8000` and can reload when Python files change.
- **Install:** included in `requirements.txt` as `uvicorn[standard]`.
- **Verify:**
  ```powershell
  cd D:\projects\VULNDETECTOR\backend
  .\.venv\Scripts\Activate.ps1
  uvicorn --version
  ```
- **Run:**
  ```powershell
  uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
  ```

### 2.10 Neon Serverless PostgreSQL

- **What it does:** provides managed PostgreSQL with separated compute and
  storage, branching, and a pooled connection endpoint.
- **Why VulnSight needs it:** durable storage for targets, scans, findings,
  evidence, remediation, verification results, reports, and activity records.
- **Install:** create an account and project at
  <https://console.neon.tech>. There is no local server to install.
- **Verify:** use the Neon SQL editor or the health endpoint after configuring
  `DATABASE_URL`.

### 2.11 SQLAlchemy

- **What it does:** an ORM and database toolkit that maps Python objects to
  relational tables and generates parameterized SQL.
- **Why VulnSight needs it:** repositories use it to read and write scan data
  without scattering raw SQL through the application.
- **Install:** included in `requirements.txt`.
- **Verify:**
  ```powershell
  cd D:\projects\VULNDETECTOR\backend
  .\.venv\Scripts\python.exe -c "import sqlalchemy; print(sqlalchemy.__version__)"
  ```

### 2.12 asyncpg

- **What it does:** an asynchronous PostgreSQL driver. SQLAlchemy uses it to
  speak the database protocol.
- **Why VulnSight needs it:** FastAPI is asynchronous, and the app should not
  block a worker while waiting for a database response.
- **Install:** included in `requirements.txt`.
- **Verify:**
  ```powershell
  cd D:\projects\VULNDETECTOR\backend
  .\.venv\Scripts\python.exe -c "import asyncpg; print(asyncpg.__version__)"
  ```

### 2.13 Alembic

- **What it does:** version control for the database structure.
- **Why VulnSight needs it:** each future table or column change becomes a
  reviewable migration instead of an undocumented manual edit.
- **Install:** included in `requirements.txt`. The scaffold is initialized in
  `backend/alembic/`.
- **Verify:**
  ```powershell
  cd D:\projects\VULNDETECTOR\backend
  .\.venv\Scripts\alembic.exe --version
  ```
- **Do not run migrations yet:** there is no database schema to migrate.
  Migrations must use the **direct** Neon endpoint, not the pooled endpoint.
  (Step 4 now provides the initial schema; see [`database.md`](./database.md).)

### 2.14 VS Code

- **What it does:** the code editor and integrated terminal.
- **Why VulnSight needs it:** one place to edit Python and TypeScript, run
  terminals, debug FastAPI, and inspect the project.
- **Install:** <https://code.visualstudio.com>, or:
  ```powershell
  winget install Microsoft.VisualStudioCode
  ```
- **Recommended extensions:**
  - Python (`ms-python.python`)
  - Pylance (`ms-python.vscode-pylance`)
  - Tailwind CSS IntelliSense (`bradlc.vscode-tailwindcss`)
- **Open the project:**
  ```powershell
  cd D:\projects\VULNDETECTOR
  code .
  ```
- **Select the interpreter:** Command Palette → **Python: Select
  Interpreter** → `backend\.venv\Scripts\python.exe`.

### 2.15 Git

- **What it does:** records project history and enables collaboration.
- **Why VulnSight needs it:** protects work, supports branches, and keeps
  secrets out of the repository when `.gitignore` is correct.
- **Install:** <https://git-scm.com/download/win>, or:
  ```powershell
  winget install Git.Git
  ```
- **Verify:**
  ```powershell
  git --version
  ```
- **One-time identity setup:**
  ```powershell
  git config --global user.name "Your Name"
  git config --global user.email "you@example.com"
  ```

### 2.16 GitHub

- **What it does:** hosts the Git repository remotely and supports backup,
  review, and collaboration.
- **Why VulnSight needs it:** keeps the project accessible and creates a
  professional history for the demonstration.
- **Install:** create an account at <https://github.com>. Optionally install
  the CLI:
  ```powershell
  winget install GitHub.cli
  gh auth login
  ```
- **Verify:**
  ```powershell
  git remote -v
  ```
  after creating the remote.
- **Important:** create the repository **empty** on GitHub. Do not add a
  README, `.gitignore`, or license during creation, because this project already
  has them.

### 2.17 Postman (optional)

- **What it does:** sends HTTP requests and inspects responses.
- **Why VulnSight needs it:** useful for testing API endpoints without the
  React interface, especially 4xx errors, pagination, and future scan calls.
- **Install:** download from <https://www.postman.com/downloads/>. Do not
  install it if the built-in FastAPI docs are enough for you.
- **Verify:** open Postman, create a request to
  `http://127.0.0.1:8000/api/v1/health`, and send it.
- **Alternative:** FastAPI provides interactive docs at
  <http://127.0.0.1:8000/docs>.

---

## 3. Neon PostgreSQL Setup

Neon account access and database credentials were **not** assumed or
preconfigured. Complete these steps yourself.

### Step 1 — Create the Neon account

1. Open <https://console.neon.tech>.
2. Sign up with GitHub, Google, or email.
3. Verify your email if Neon asks you to.

### Step 2 — Create the VulnSight project

1. Choose **New Project**.
2. Project name: `VulnSight`.
3. Postgres version: keep the default supported version unless you have a
   reason to change it.
4. Region: choose the region closest to you.
5. Create the project.

Neon creates a default branch, a database, and a role.

### Step 3 — Create the development branch

1. Open the project.
2. Go to **Branches**.
3. Create a branch named `development` from the default branch.
4. Select `development` before copying the connection string.

A Neon branch is an isolated, copy-on-write view of the same project. You can
develop against `development` without changing the default branch.

For a solo local MVP, you can also use the default branch. The important rule
is to be consistent and to use a **non-production branch** while developing.

### Step 4 — Understand branch, database, and role

| Concept | Meaning in Neon |
|---|---|
| **Project** | The container for branches, databases, roles, and settings |
| **Branch** | An isolated database state; useful for development and experiments |
| **Database** | A logical PostgreSQL database, commonly named `neondb` |
| **Role** | The PostgreSQL login identity and its privileges |
| **Compute endpoint** | The server process that accepts connections for a branch |

The same branch can contain multiple databases and roles. The same project can
contain multiple branches.

### Step 5 — Copy the direct connection string

1. Select the `development` branch.
2. Open **Connect** (or **Connection Details**).
3. Choose your database and role.
4. Turn **Connection pooling off** so you copy the **direct** endpoint.
5. Copy the full connection string.

It will look roughly like this, with fake values:

```text
postgresql://vulnsight_owner:YOUR_PASSWORD@ep-example-123456.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require
```

The real string contains a secret. Do not paste it into chat, screenshots,
GitHub, issue trackers, or frontend code.

### Step 6 — Pooled vs direct connection strings

| Endpoint | Host pattern | What it is | Use in this MVP |
|---|---|---|---|
| **Direct** | `ep-example-123.region.aws.neon.tech` | A direct connection to the branch compute | Yes |
| **Pooled** | `ep-example-123-pooler.region.aws.neon.tech` | PgBouncer in transaction mode | Not yet |

Use the **direct** endpoint for:

- the long-lived FastAPI process;
- Alembic migrations;
- queries that depend on session state.

The pooled endpoint is designed for many short-lived clients, such as
serverless functions. In transaction mode, session-level behavior is limited:
`SET`, `LISTEN/NOTIFY`, session advisory locks, temporary tables with
`PRESERVE`, and SQL-level prepared statement control are not reliable. asyncpg
prepared-statement caching also needs special handling behind PgBouncer.

For this Lean MVP there is one backend process, so the direct endpoint avoids
an unnecessary class of problems.

### Step 7 — Understand TLS and SSL

Neon requires encrypted connections and rejects unencrypted clients.

The backend:

- converts the URL to `postgresql+asyncpg://`;
- removes libpq-only parameters such as `sslmode` and `channel_binding`;
- creates a certificate-verifying TLS context using `certifi`;
- passes that context to asyncpg.

Do not use `sslmode=disable`. Do not disable certificate verification to make a
local error go away. If certificate verification fails, fix the certificate or
network configuration.

### Step 8 — Store the string in backend environment variables

The local file is:

```text
D:\projects\VULNDETECTOR\backend\.env
```

It is already created from `backend/.env.example`, and it is ignored by Git.
Open it and set one line:

```dotenv
DATABASE_URL=postgresql://USER:PASSWORD@HOST/DATABASE?sslmode=require
```

Rules:

- Use the **direct** endpoint unless you intentionally change the architecture.
- Keep the whole URL on one line.
- Do not put the URL in `frontend/.env`, a `VITE_*` variable, or any React file.
- Do not commit `.env`.
- Restart the backend after changing it.

### Step 9 — Verify the database connection

Start the backend from the `backend` directory:

```powershell
cd D:\projects\VULNDETECTOR\backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In a second terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health/db
```

Expected response:

```json
{
  "status": "ok",
  "database": "connected",
  "latency_ms": 32.51
}
```

The exact latency varies. A first query can be slower if Neon compute was idle.

If the response is `503`, check:

1. `backend/.env` exists and contains `DATABASE_URL=`.
2. There are no extra quotes or spaces around the URL.
3. You copied the URL for the selected `development` branch.
4. You used the direct endpoint, not the `-pooler` endpoint.
5. The role has access to the selected database.
6. The password is the current password, URL-encoded if it contains special
   characters.
7. The backend was restarted after editing `.env`.
8. Your network allows outbound TLS to Neon on port 5432.

Then open the frontend:

```powershell
cd D:\projects\VULNDETECTOR\frontend
npm run dev
```

Visit <http://127.0.0.1:5173>. The Neon card should show **Connected**.

---

## 4. Project Structure

```text
VULNDETECTOR/
├── .gitignore                  Secrets, Python, Node, and editor files
├── README.md                   Quick start
├── docs/
│   ├── SRS.md                  Approved Lean MVP requirements
│   ├── architecture.md         System architecture
│   ├── setup.md                This guide
│   └── archive/                Superseded documents
├── backend/
│   ├── .env                    Local secrets, ignored by Git
│   ├── .env.example            Safe template for other developers
│   ├── requirements.txt        Pinned backend dependencies
│   ├── pytest.ini              Test discovery and async test settings
│   ├── alembic.ini             Alembic configuration
│   ├── alembic/
│   │   ├── env.py              Loads DATABASE_URL and enables TLS
│   │   ├── script.py.mako      Migration template
│   │   └── versions/           Future migration files
│   ├── app/
│   │   ├── main.py             FastAPI app, CORS, lifespan, router mounting
│   │   ├── api/
│   │   │   ├── router.py       Versioned top-level router
│   │   │   └── routes/
│   │   │       └── health.py   API and database health endpoints
│   │   ├── core/
│   │   │   └── config.py       Typed settings loaded from backend/.env
│   │   ├── db/
│   │   │   ├── base.py         SQLAlchemy declarative base
│   │   │   ├── engine.py       Async engine and session factory
│   │   │   └── url.py          Neon URL normalization
│   │   ├── schemas/
│   │   │   └── health.py       Pydantic response models
│   │   ├── models/             Future SQLAlchemy table models
│   │   ├── services/           Future business services
│   │   ├── auth/               Future authentication
│   │   ├── security/           Future SSRF, scope, and secret utilities
│   │   ├── recon/              Future crawler and inventory
│   │   ├── scanners/           Future modular vulnerability checks
│   │   ├── findings/           Future normalization and persistence
│   │   ├── remediation/        Future remediation catalog
│   │   ├── verification/       Future targeted rescan logic
│   │   └── reports/            Future HTML/JSON report renderers
│   └── tests/
│       └── test_health.py      Foundation smoke tests
└── frontend/
    ├── .env.example            Safe frontend configuration template
    ├── package.json            Frontend scripts and dependencies
    ├── vite.config.ts          React, Tailwind, and /api proxy
    ├── public/                 Static assets
    └── src/
        ├── main.tsx            React entry point
        ├── App.tsx             Top-level composition
        ├── api/                HTTP client and endpoint functions
        ├── components/         Reusable UI pieces
        ├── hooks/              Reusable React state and effects
        ├── layouts/            Page shells and navigation
        ├── pages/              Route-level screens
        ├── styles/             Tailwind import and global styles
        ├── types/              TypeScript contracts for API data
        └── utils/              Small pure helpers
```

### Why the folders exist

- **`api/routes`** keeps HTTP concerns separate from business logic. A route
  validates input and calls a service.
- **`core`** holds settings and cross-cutting concerns so secrets are loaded in
  one place.
- **`db`** is the only layer that knows how to create engines, sessions, and
  future SQLAlchemy models.
- **`models` vs `schemas`:** SQLAlchemy models represent database tables;
  Pydantic schemas represent API input and output. They must remain separate so
  database structure is never leaked to the browser.
- **`services`** will hold use cases such as starting a scan or verifying a fix.
- **`security`** will hold scope guards, SSRF checks, URL validation, and
  redaction — not general UI code.
- **`recon` and `scanners`** are separate because discovery is not the same as
  assessment.
- **`findings`, `remediation`, and `verification`** have different lifecycles
  and should not be mixed into route handlers.
- **`reports`** is isolated so HTML, JSON, and future PDF renderers share one
  data snapshot.
- **`tests`** mirrors backend behavior and will eventually cover scanners with
  fixtures, not live targets.
- **Frontend `api`, `hooks`, `types`** keep network calls, state, and contracts
  out of presentational components.

---

## 5. Initialization Commands

These commands reproduce the foundation on a clean machine.

### 5.1 Root directory

```powershell
cd D:\projects
New-Item -ItemType Directory -Force VULNDETECTOR
cd VULNDETECTOR
```

### 5.2 Backend virtual environment

```powershell
py -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install --upgrade pip
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

### 5.3 Frontend

```powershell
npm create vite@latest frontend -- --template react-ts
cd frontend
npm install
npm install tailwindcss @tailwindcss/vite
cd ..
```

### 5.4 Alembic scaffold

From the backend directory, with the virtual environment available:

```powershell
cd backend
.\.venv\Scripts\alembic.exe init -t async alembic
cd ..
```

The generated `alembic/env.py` was adjusted to load `DATABASE_URL` from the
backend settings and to use TLS. No migration files exist yet.

### 5.5 Git initialization

```powershell
cd D:\projects\VULNDETECTOR
git init -b main
git add .
git status
git commit -m "chore: initialize VulnSight foundation"
```

Before committing, confirm that `backend/.env` is not listed:

```powershell
git check-ignore -v backend\.env
git status --short
```

### 5.6 GitHub repository

1. Open <https://github.com/new>.
2. Repository name: `VulnSight` (or your preferred name).
3. Choose **Private** unless you intentionally want it public.
4. Do **not** add a README, `.gitignore`, or license.
5. Create the repository.
6. Connect and push:

```powershell
cd D:\projects\VULNDETECTOR
git remote add origin https://github.com/YOUR_USERNAME/VulnSight.git
git branch -M main
git push -u origin main
```

If Git asks for credentials, sign in through the browser or use a personal
access token. Never put a token in the repository.

---

## 6. Run the Applications

### Terminal 1 — backend

```powershell
cd D:\projects\VULNDETECTOR\backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected output includes:

```text
Uvicorn running on http://127.0.0.1:8000
```

### Terminal 2 — frontend

```powershell
cd D:\projects\VULNDETECTOR\frontend
npm run dev
```

Expected output includes:

```text
Local: http://127.0.0.1:5173/
```

Open <http://127.0.0.1:5173>.

The Vite development server proxies `/api` to `http://127.0.0.1:8000`, so the
browser uses a relative URL and no CORS setup is needed for normal local work.

---

## 7. Testing Checkpoint

| Check | How to verify | Expected |
|---|---|---|
| Frontend starts | Open `http://127.0.0.1:5173` | VulnSight status page renders |
| Backend starts | `http://127.0.0.1:8000/docs` | FastAPI Swagger UI loads |
| API health | `Invoke-RestMethod http://127.0.0.1:8000/api/v1/health` | `status: ok`, service, version, environment |
| Frontend → backend | API card on the status page | **Online** |
| Backend → Neon | `http://127.0.0.1:8000/api/v1/health/db` | `status: ok`, `database: connected` |
| Frontend → Neon health | Neon card on the status page | **Connected** |
| No credentials in frontend | Search the built JS for `postgresql://`, `neon.tech`, `sslmode=`, and `channel_binding=` | No matches |
| `.env` excluded from Git | `git check-ignore -v backend\.env` | `.gitignore` rule is reported |
| Backend tests | `cd backend; .\.venv\Scripts\python.exe -m pytest -q` | All tests pass |
| Frontend build | `cd frontend; npm run build` | Build completes without errors |

### Credential-leak check

```powershell
cd D:\projects\VULNDETECTOR\frontend
npm run build
Select-String -Path dist\assets\*.js -Pattern "postgresql://","postgres://","neon.tech","sslmode=","channel_binding=" -SimpleMatch
```

The search should return nothing. The frontend only knows the relative
`/api/v1` path. The words `DATABASE_URL` and `PostgreSQL` can appear in the
page's explanatory text; those are labels, not credentials. What must never
appear is a connection scheme, host, query parameter, password, or token.

For a stronger check, search for the actual values from `backend/.env` (without
printing them):

```powershell
cd D:\projects\VULNDETECTOR
$envLine = Get-Content backend\.env | Where-Object { $_ -match '^DATABASE_URL=' }
$url = ($envLine -split '=', 2)[1]
$secret = [regex]::Match($url, '://[^:]+:([^@]+)@').Groups[1].Value
$hostName = [regex]::Match($url, '@([^/]+)/').Groups[1].Value
if ($secret) { Select-String -Path frontend\dist\assets\* -Pattern $secret -SimpleMatch }
if ($hostName) { Select-String -Path frontend\dist\assets\* -Pattern $hostName -SimpleMatch }
```

Neither search should return a match. Do not paste the URL or the extracted
values into chat or an issue.

### Git check

```powershell
cd D:\projects\VULNDETECTOR
git status --short
```

`backend/.env` must not appear. If it does, stop and fix `.gitignore` before
committing.

---

## 8. Troubleshooting

### `python` opens the Microsoft Store

Use the launcher:

```powershell
py --version
py -m venv backend\.venv
```

After activating the virtual environment, `python` should resolve to
`backend\.venv\Scripts\python.exe`.

### PowerShell blocks `Activate.ps1`

For the current terminal only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### `ModuleNotFoundError: No module named 'app'`

Run Uvicorn from the `backend` directory, or use:

```powershell
cd D:\projects\VULNDETECTOR\backend
uvicorn app.main:app --reload
```

### Port 8000 is already in use

```powershell
Get-NetTCPConnection -LocalPort 8000
```

Stop the process using that port, or choose another port. If you change the
backend port, update the Vite proxy target in `frontend/vite.config.ts`.

### Frontend shows API offline

1. Confirm the backend terminal is still running.
2. Open `http://127.0.0.1:8000/api/v1/health` directly.
3. Confirm Vite is proxying `/api` to port 8000.
4. Restart both servers after changing configuration.

### Database health returns 503

The API intentionally returns a generic message and logs only the exception
type. Review the backend terminal for the actual failure. The most common causes
are a missing `DATABASE_URL`, a copied pooled endpoint, a branch mismatch, a
wrong role/password, or a network/TLS problem.

### TLS or certificate errors

- Do not disable certificate verification.
- Confirm the Neon hostname is correct and current.
- Confirm the system clock is accurate.
- If you are behind a corporate TLS-inspecting proxy, install the proxy's root
  certificate in the environment used by Python. Do not work around it by
  accepting any certificate.

### Neon compute was idle

The first connection after idle can take longer. Refresh the database card or
call the health endpoint again. This is expected with serverless compute.

### Alembic says `DATABASE_URL is not configured`

Fill in `backend/.env`. Alembic intentionally fails clearly instead of using a
placeholder production URL.

---

## 9. Security Rules Established in This Step

- The React browser never connects to Neon.
- The browser only receives JSON from FastAPI.
- `DATABASE_URL` lives only in `backend/.env`.
- The frontend contains no `VITE_*` database variables.
- `.env` is ignored by Git.
- Database health errors are generic; the backend does not return connection
  details or credentials.
- The backend uses TLS with certificate verification.
- Alembic uses a separate direct connection for migrations.
- SQLAlchemy parameter binding will be used for all values; no string-built SQL.
- No scanner code exists yet, so no target can be contacted.

---

## 10. What Is Intentionally Not Built Yet

- Database tables or Alembic revision files.
- Authentication and session handling.
- Target allowlist and SSRF protection logic.
- Crawler and scanner modules.
- Findings, remediation, verification, and reports.
- Scan jobs or background workers.
- Any OWASP check.

The next step is the detailed database schema and data model, after this
foundation is approved and the Neon connection is confirmed.

---

## 11. Final Checkpoint

The foundation was verified complete on 05 November 2026:

- [x] `http://127.0.0.1:5173` renders the VulnSight status page.
- [x] `http://127.0.0.1:8000/docs` loads.
- [x] `/api/v1/health` returns `status: ok`.
- [x] `/api/v1/health/db` returns `status: ok` and `database: connected`.
- [x] The frontend displays **Online** and **Connected**.
- [x] `backend/.env` is ignored by Git.
- [x] The frontend bundle contains no database credentials.
- [x] `pytest` passes and `npm run build` succeeds.

Do not start the database schema or scanner implementation until this checkpoint
is green.
