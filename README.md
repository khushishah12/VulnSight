# VulnSight 🛡️
**Enterprise-Grade Web Application Vulnerability Assessment & Fix Verification Platform**

[![Python Version](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.162.0-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6.svg)](https://www.typescriptlang.org/)
[![PostgreSQL](https://img.shields.io/badge/Database-Neon%20Serverless%20PostgreSQL-336791.svg)](https://neon.tech/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-v4.0-38B2AC.svg)](https://tailwindcss.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 1. Project Overview & Problem Statement

### The Problem
Modern web engineering teams face a critical disconnect between finding vulnerabilities and remediating them:
1. **Generic, Context-Free Scanner Reports**: Traditional DAST scanners output massive PDF catalogs of obscure alerts without actionable, framework-specific code fixes.
2. **Dangerous Verification Assumptions**: Many tools assume that if a secondary probe does not reproduce an alert, the flaw is "fixed"—overlooking server crashes, timeouts, and route renames (violating the core principle: *Absence of evidence is not evidence of absence*).
3. **SSRF and Scanner Abuse Risks**: Poorly constrained scanners can inadvertently be weaponized by operators to probe internal cloud metadata (`169.254.169.254`) or private subnets.

### The Solution: VulnSight
**VulnSight** is an enterprise-grade security operations console designed for authorized penetration testing, vulnerability discovery, and developer-centric remediation against the **OWASP Top 10:2025**. It pairs non-destructive active testing with an intelligent **Remediation Center** and an automated **Fix Verification Engine** that provides positive defensive proof before marking issues as resolved.

---

## 2. Core Feature Matrix

| Feature | Description | Implementation Details |
|---|---|---|
| **Pre-Flight Target & Scope Control** | Multi-tier defense against scanner abuse and unintended infrastructure scanning. | Hostname allowlists (`SCAN_ALLOWED_HOSTS`), RFC1918 private IP blocking, cloud metadata (`169.254.169.254`) interception, and DNS rebinding protection. |
| **Modular OWASP Top 10:2025 Detection** | Safe, polite, non-destructive active probes evaluating web applications. | Comprehensive checks for A01 (Broken Access Control), A02 (Misconfiguration), A04 (Crypto Failures), A05 (Injection / Reflected XSS), A07 (Auth), and A10 (Error Handling). |
| **Intelligent Remediation Center** | Actionable fix guidance for development teams. | Root-cause analysis, conceptual exploitation flows, step-by-step roadmaps, and side-by-side vulnerable vs. secure code across **Node.js/Express, FastAPI, Django, Java/Spring, and SQL**. |
| **Automated Fix Verification** | Re-tests remediated endpoints with evidence delta analysis. | Emits 4 strict verdicts (**Fixed**, **Vulnerability persists**, **Inconclusive**, **Verification failed**). Enforces the rule that server errors (HTTP 500) never equal a fix. |
| **Publication-Grade PDF Reporting** | Generates audit-ready executive deliverables. | ReportLab 5.1 document compiler featuring posture scores, letter grades, redacted evidence, OWASP coverage grids, and running footers with SHA-256 hashes. |
| **Enterprise SecOps Interface** | Professional, dark-slate operations dashboard. | 13 dedicated views built with React 19, TypeScript, and Tailwind CSS v4, adhering to cybersecurity design standards (CrowdStrike / Snyk style). |

---

## 3. Architecture & Data Flow

```mermaid
graph TD
    subgraph Frontend ["SecOps Console (React 19 + TypeScript + Tailwind CSS v4)"]
        Dashboard["Security Dashboard & Posture Gauge"]
        NewScan["Target & Scope Configuration"]
        LiveScan["Live Telemetry & Pipeline Tracker"]
        Findings["Findings Triage & Redacted Evidence"]
        Remediation["Remediation Center (5 Framework Stacks)"]
        VerifyUI["Fix Verification Audit Console"]
        ReportsUI["PDF Deliverable Access"]
    end

    subgraph Backend ["FastAPI Core Services (Python 3.13)"]
        FastAPIApp["FastAPI REST API & Security Headers Middleware"]
        ScopeValidator["SSRF & Scope Boundary Validator"]
        ReconEngine["Reconnaissance & Crawler Engine (HTTPX + BS4)"]
        ScannerEngine["OWASP Top 10 Detection Engine"]
        VerifyEngine["Fix Verification Runner"]
        ReportLabEngine["ReportLab PDF Document Compiler"]
    end

    subgraph DataTier ["Persistence & Cloud Infrastructure"]
        Engine["SQLAlchemy 2.0 Async Engine + asyncpg"]
        NeonDB[("Neon Serverless PostgreSQL 17")]
    end

    Dashboard --> FastAPIApp
    NewScan --> FastAPIApp
    LiveScan --> FastAPIApp
    Findings --> FastAPIApp
    Remediation --> FastAPIApp
    VerifyUI --> FastAPIApp
    ReportsUI --> FastAPIApp

    FastAPIApp --> ScopeValidator
    FastAPIApp --> ReconEngine
    FastAPIApp --> ScannerEngine
    FastAPIApp --> VerifyEngine
    FastAPIApp --> ReportLabEngine

    ScopeValidator --> Engine
    ReconEngine --> Engine
    ScannerEngine --> Engine
    VerifyEngine --> Engine
    ReportLabEngine --> Engine
    Engine --> NeonDB
```

---

## 4. Technology Stack

### Backend
- **Python 3.13** with strict type hints.
- **FastAPI 0.162**: Asynchronous REST API framework.
- **Pydantic v2 & Pydantic Settings**: Schema validation and settings management.
- **SQLAlchemy 2.0 (Async) + asyncpg 0.32**: Database ORM and PostgreSQL driver with connection pooling.
- **Alembic 1.20**: Database migration management.
- **ReportLab 5.1**: Publication-grade PDF document compiler.
- **HTTPX 0.28**: Async HTTP client with manual redirect interception for SSRF safety.
- **BeautifulSoup4**: Safe HTML reconnaissance and form parameter discovery.

### Frontend
- **React 19.0**: Client UI framework.
- **TypeScript 5.8**: Full type safety with strict compiler flags (`noUnusedLocals`, `verbatimModuleSyntax`).
- **Tailwind CSS v4**: Utility-first styling with modern CSS variables.
- **Vite 8.3**: Client build tool and development server with API proxying.

### Database
- **Neon Serverless PostgreSQL 17**: Cloud database with branching, SSL encryption (`sslmode=require`), and partial unique indexes.

---

## 5. Security Posture Score Calculation

VulnSight uses an internal risk scoring formula clearly documented in the dashboard:

$$\text{Security Posture Score} = \max\left(0, 100 - [15 \times N_{\text{crit}} + 8 \times N_{\text{high}} + 3 \times N_{\text{med}} + 1 \times N_{\text{low}}]\right)$$

### Letter Grade Spectrum
- **Grade A ($90 - 100$)**: Minimal Exposure – Robust defensive posture with zero Critical or High findings.
- **Grade B ($75 - 89$)**: Low Exposure – Minor hygiene issues or low-impact misconfigurations.
- **Grade C ($60 - 74$)**: Elevated Risk – Moderate findings present; remediation recommended within 14 days.
- **Grade D ($40 - 59$)**: Substantial Risk – Multiple high-severity exposures requiring immediate triage.
- **Grade F ($0 - 39$)**: Critical Posture – Active critical findings; immediate incident-level remediation required.

---

## 6. Installation & Local Setup

### Prerequisites
- **Python 3.13+**
- **Node.js 22+ & npm 11+**
- **Neon Serverless PostgreSQL Account** (or local PostgreSQL 16+)

### 1. Clone the Repository
```powershell
git clone https://github.com/khushishah12/VulnSight.git
cd VulnSight
```

### 2. Configure Backend Virtual Environment
```powershell
# Create Python virtual environment
py -3.13 -m venv backend\.venv

# Activate virtual environment
.\backend\.venv\Scripts\activate

# Install dependencies
python -m pip install -r backend\requirements.txt
```

### 3. Set Up Environment Variables
Create `backend/.env` using the provided example:
```powershell
Copy-Item backend\.env.example backend\.env
```
Edit `backend/.env` to include your Neon PostgreSQL connection string:
```ini
APP_NAME=VulnSight API
APP_VERSION=0.1.0
APP_ENV=development
FRONTEND_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# Direct Neon connection string (SSL required)
DATABASE_URL=postgresql://USER:PASSWORD@ep-example.region.aws.neon.tech/neondb?sslmode=require

# Strict scope allowlist
SCAN_ALLOWED_HOSTS=127.0.0.1,localhost,::1
SCAN_MAX_TARGETS=10
SCAN_ALLOW_LOOPBACK_FOR_TESTING=true
SCAN_EXECUTOR_MODE=recon
```

### 4. Run Database Migrations
```powershell
cd backend
.\.venv\Scripts\alembic.exe upgrade head
cd ..
```

### 5. Install Frontend Dependencies & Build
```powershell
cd frontend
npm install
npm run build
cd ..
```

---

## 7. Running the Platform Locally

### Terminal 1: Backend API
```powershell
cd backend
.\.venv\Scripts\activate
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
*API Documentation will be accessible at: `http://127.0.0.1:8000/docs`*

### Terminal 2: Frontend Console
```powershell
cd frontend
npm run dev
```
*Console will be accessible at: `http://localhost:5173`*

---

## 8. API Endpoints Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | API liveness probe |
| `GET` | `/api/v1/health/db` | Database connectivity & pool telemetry |
| `POST` | `/api/v1/scans` | Create and initialize a new scan session |
| `GET` | `/api/v1/scans` | List historical scans with status filters |
| `GET` | `/api/v1/scans/{id}` | Retrieve scan progress and session summary |
| `POST` | `/api/v1/scans/{id}/cancel` | Cooperatively cancel an in-flight scan |
| `GET` | `/api/v1/scans/{id}/findings` | Retrieve all findings discovered in a scan |
| `GET` | `/api/v1/findings/{id}` | Deep dive finding details with redacted evidence |
| `GET` | `/api/v1/findings/{id}/remediation` | Retrieve multi-stack remediation guide |
| `POST` | `/api/v1/findings/{id}/verify` | Dispatch automated safe fix verification |
| `POST` | `/api/v1/reports` | Compile a new JSON, HTML, or PDF deliverable |
| `GET` | `/api/v1/reports/{id}/download` | Stream and download generated report file |

---

## 9. Running Automated Tests

VulnSight maintains a comprehensive test suite covering unit tests, SSRF boundary defenses, fix verification logic, and PDF generation:

```powershell
cd backend
.\.venv\Scripts\pytest.exe tests/test_pdf_report.py tests/test_fix_verification.py tests/test_scanners_owasp.py tests/test_remediation.py tests/test_db_url.py -v
```

---

## 10. Limitations & Non-Goals

1. **Explicit Scope Boundary**: VulnSight strictly blocks unlisted hostnames and cloud metadata addresses. It cannot be used to scan arbitrary, unauthorized external targets.
2. **Safe Non-Destructive Testing**: VulnSight deliberately omits denial-of-service, persistent data tampering, or dangerous injection exploits. All injection probes utilize harmless, benign canaries (`vsight<safe_v>`).
3. **Point-in-Time Assessment**: Automated findings represent the state of the target at the execution timestamp. Complex multi-step business logic vulnerabilities may require supplementary manual penetration testing.

---

## 11. License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
