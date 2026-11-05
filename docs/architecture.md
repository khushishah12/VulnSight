# VulnSight — System Architecture Design

| Field | Value |
|---|---|
| Project | VulnSight — Web Application Vulnerability Assessment Platform |
| Document | System Architecture Design |
| Version | 1.0 — Step 2 baseline |
| Status | Draft for approval |
| Date | 05 November 2026 |
| Inputs | Approved Lean MVP requirements (`docs/SRS.md`) and proposed technology stack |
| Out of scope | Application code, detailed database schema, deployment scripts, CI/CD configuration |

> **Scope note.** The approved Lean MVP is deliberately small: one local admin, unauthenticated scanning, eight checks, and HTML/JSON reports. The proposed stack also mentions OSV dependency checks, fix verification, and ReportLab PDFs. This architecture supports all of them, but marks clearly which parts belong to the Lean MVP and which are Version 2 or optional. Nothing here changes the approved MVP unless you approve the change.

---

## 1. Architectural Style

VulnSight will use a **modular monolith**:

- One React frontend.
- One FastAPI backend application, organized into clear internal modules.
- One database: Neon PostgreSQL.
- A scan worker that can run in the same deployment as the API for the Lean MVP.

This is not a set of microservices. The 13 components in this document are **logical modules inside one codebase**, not 13 separately deployed services. That is an intentional decision:

- Easier for one developer to build and debug.
- Fewer network failure points.
- Simpler deployment.
- Clear module boundaries still allow a worker or scanner to be split out later.

The design uses **asynchronous I/O** where it matters: web requests, database access, crawling, and scanner HTTP calls. CPU-heavy work, such as PDF rendering or large report generation, should eventually move to a worker so it does not block API responses.

---

## 2. Beginner-Friendly Foundations

### 2.1 Client-server architecture

Think of a restaurant:

- The **client** is the customer: it asks for something and displays the result.
- The **server** is the kitchen: it validates the order, does the work, and returns the result.
- The **database** is the storage room: it keeps the durable records.

In VulnSight:

- The **React frontend** is the client. It runs in the browser.
- The **FastAPI backend** is the server. It contains the business logic and scanner orchestration.
- **Neon PostgreSQL** is the database. It stores targets, scans, findings, evidence, verification results, and reports metadata.

The browser must never talk directly to the database. If it did, database credentials would be exposed to every user, and the browser could bypass authorization rules.

### 2.2 Frontend and backend responsibilities

**React frontend responsibilities**

- Render pages, forms, tables, and finding details.
- Validate input for a good user experience.
- Call the backend REST API.
- Show scan progress by polling.
- Display findings, evidence, remediation, and coverage.
- Handle authentication state through secure cookies.
- Never contain database credentials, scanner logic, or secret keys.

**FastAPI backend responsibilities**

- Authenticate and authorize every request.
- Validate URLs and scan scope.
- Enforce target allowlists and SSRF protection.
- Run reconnaissance and scanner modules.
- Normalize, deduplicate, redact, and persist findings.
- Generate reports.
- Enforce rate limits and scan budgets.
- Record activity and audit events.
- Be the only component that talks to Neon.

### 2.3 REST APIs

REST is a convention for communication over HTTP:

- The client sends a request to a URL.
- The server returns JSON and an HTTP status code.
- Each request contains enough information to be understood on its own.

Examples of VulnSight API groups:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/v1/auth/login` | Sign in |
| `POST` | `/api/v1/auth/logout` | Sign out |
| `GET` | `/api/v1/auth/me` | Get current session/user |
| `POST` | `/api/v1/targets` | Add an authorized target |
| `GET` | `/api/v1/targets` | List targets |
| `DELETE` | `/api/v1/targets/{id}` | Delete a target and its data |
| `POST` | `/api/v1/scans` | Start a scan |
| `GET` | `/api/v1/scans` | List scan history |
| `GET` | `/api/v1/scans/{id}` | Get status and summary |
| `POST` | `/api/v1/scans/{id}/cancel` | Cancel a scan |
| `GET` | `/api/v1/findings` | List/filter findings |
| `GET` | `/api/v1/findings/{id}` | Get finding details |
| `PATCH` | `/api/v1/findings/{id}/status` | Mark false positive or restore |
| `GET` | `/api/v1/findings/{id}/remediation` | Get remediation guidance |
| `POST` | `/api/v1/findings/{id}/verify` | Request a targeted rescan |
| `GET` | `/api/v1/verifications/{id}` | Get verification result |
| `POST` | `/api/v1/scans/{id}/reports` | Generate a report |
| `GET` | `/api/v1/reports/{id}` | Download or view a report |

Important API conventions:

- Prefix everything with `/api/v1` so future breaking changes can be versioned.
- Use JSON request and response bodies.
- Use `202 Accepted` when a scan starts in the background.
- Use `401` for “not signed in,” `403` for “not allowed,” `404` for “not found,” `409` for a conflicting state such as an already-running scan, `422` for invalid input, and `429` for rate limiting.
- Publish an OpenAPI description so the frontend and backend contracts stay visible.
- Paginate scan and finding lists. Never return an unlimited history.

### 2.4 Database architecture

A relational database stores data in tables with rows and columns, and uses keys to link related records. PostgreSQL is a mature relational database with ACID transactions:

- **Atomic:** a transaction either fully succeeds or fully rolls back.
- **Consistent:** data moves from one valid state to another.
- **Isolated:** concurrent transactions do not silently corrupt each other.
- **Durable:** committed data survives a crash.

VulnSight’s **logical data domains** are:

- identity and sessions;
- targets and scan scope;
- scans and scan status;
- reconnaissance inventory;
- findings and evidence;
- remediation content;
- fix-verification results;
- reports;
- activity/audit events.

The detailed schema — tables, columns, indexes, and constraints — is intentionally not designed in this step. The architecture only requires:

- the database is the source of truth for scan state and results;
- findings are linked to scans and targets;
- evidence is redacted before persistence;
- old scans can be deleted according to retention policy;
- transactions are short, especially during long-running scans.

### 2.5 ORM and database drivers

An **ORM** (Object-Relational Mapper) translates between Python objects and database rows. SQLAlchemy is the ORM.

A **database driver** is the low-level library that actually speaks the PostgreSQL network protocol. `asyncpg` is the driver.

A useful analogy:

- SQLAlchemy is the translator who writes the request in the database’s language.
- `asyncpg` is the courier who carries it over the network.
- Neon is the records office that stores and returns the data.

Pydantic is separate: it validates API request and response data. It is not the ORM and must not be used as a database model.

### 2.6 Database migrations

A migration is **version control for the database structure**. When a new column or table is needed, a migration describes the change from the old structure to the new one.

Alembic will manage migrations:

- Every schema change is a versioned migration.
- Migrations are applied in order.
- A migration can be reviewed before it runs.
- Migrations use a **direct** Neon connection, not a transaction-pooled connection.
- The runtime application user should not be the same as the migration/owner user.

### 2.7 How Neon PostgreSQL works

Neon is a managed, PostgreSQL-compatible service that separates compute from storage:

- **Compute** runs PostgreSQL: it parses queries, executes transactions, and uses RAM/local cache.
- **Storage** is durable and independent of any one compute node.
- Compute can scale, restart, or go idle without losing data.
- Neon can scale compute up and down, and can scale to zero when idle.
- Neon supports branching: a copy-on-write clone of database state for development, testing, or preview environments.
- Neon provides a pooled connection endpoint in addition to a direct endpoint.

“Serverless” does **not** mean there is no server. It means the provider manages and elastically allocates the compute, and you pay for usage rather than a permanently fixed server.

### 2.8 Traditional PostgreSQL hosting vs Neon

| Aspect | Traditional PostgreSQL hosting | Neon Serverless PostgreSQL |
|---|---|---|
| Compute | Fixed instance or manually scaled server | Elastic compute; can autoscale and scale to zero |
| Storage | Attached to the database instance | Separated from compute and durable |
| Idle cost | Usually pay while the instance runs | Can be lower because compute can idle |
| Cold start | Usually none; instance is always on | Possible when compute wakes from idle |
| Scaling | Manual or scheduled | Managed autoscaling and read replicas |
| Branching | Usually copy/restore or separate instances | Copy-on-write branches are a first-class feature |
| Connections | Direct; connection limits depend on instance | Direct plus PgBouncer pooled endpoint |
| Operations | You or a managed provider handle patching/backups | Neon manages the platform; you still manage schema and queries |
| Best fit | Predictable, always-on workloads; full infrastructure control | Prototypes, variable workloads, branch-based development, serverless deployment |
| Latency | Predictable when warm | Very good when warm; cold starts must be considered |

For VulnSight, Neon is a good fit because the project is small, benefits from branching for development, and does not need a permanently large database instance. The architecture still treats it as ordinary PostgreSQL through SQLAlchemy and asyncpg.

---

## 3. High-Level Architecture

```mermaid
flowchart LR
    U[User Browser] -->|HTTPS| FE[React SPA<br/>TypeScript + Tailwind]
    FE -->|REST /api/v1<br/>JSON + session cookie| API[FastAPI API]
    API --> AUTH[Authentication &<br/>Authorization]
    API --> ORCH[Scan Orchestration]
    API --> FIND[Finding Management]
    API --> REM[Remediation]
    API --> VER[Fix Verification]
    API --> REP[Report Generation]
    ORCH --> RECON[Reconnaissance Engine]
    ORCH --> SCAN[OWASP Scanner Modules]
    RECON -->|HTTPX, scoped| TARGET[Authorized Target]
    SCAN -->|safe checks| TARGET
    SCAN -.->|V2 dependency checks| OSV[OSV API]
    AUTH --> DAL[SQLAlchemy Async<br/>Repositories]
    ORCH --> DAL
    FIND --> DAL
    VER --> DAL
    REP --> DAL
    DAL -->|asyncpg + TLS| DB[(Neon PostgreSQL)]
```

### Explanation

- The **browser** only talks to the React app and the FastAPI API.
- The **React app** never receives database credentials and never opens a database connection.
- **FastAPI** is the single entry point for all business operations.
- The **scan orchestrator** coordinates reconnaissance and scanner modules.
- The **recon engine** and **scanner modules** make outbound HTTP requests to the authorized target.
- **Findings, remediation, verification, and reports** all read and write through the database layer.
- **Neon** is reachable only from the backend.
- The **OSV API** is a future external dependency-intelligence source; it is not used for URL-only scanning in the Lean MVP.

### Deployment shape

For the Lean MVP, the simplest deployment is:

- React static build served behind a reverse proxy.
- FastAPI served behind the same reverse proxy at `/api`.
- One scan worker process.
- Neon over TLS.

Keeping the frontend and API on the **same origin** avoids unnecessary CORS complexity and makes secure session cookies easier.

---

## 4. Detailed Component Interaction

```mermaid
flowchart TB
    subgraph Browser[Browser]
        UI[React + TypeScript + Tailwind]
    end

    subgraph Backend[FastAPI Modular Monolith]
        ROUTER[API Routing Layer]
        AUTHZ[AuthN / AuthZ]
        VAL[Pydantic Validation]
        ORCH[Scan Orchestrator]
        RECON[Recon Engine]
        REG[Scanner Registry]
        S1[Headers & Cookies]
        S2[HTTPS / Login Transport]
        S3[CORS / Directory / Version]
        S4[Reflected XSS / Error Handling]
        FM[Finding Management]
        REM[Remediation Service]
        FV[Fix Verification]
        REPORT[Report Service]
        REPO[Repositories]
    end

    DB[(Neon PostgreSQL)]
    TARGET[Authorized Target]
    OSV[OSV API]

    UI -->|REST| ROUTER
    ROUTER --> AUTHZ
    AUTHZ --> VAL
    VAL --> ORCH
    VAL --> FM
    VAL --> FV
    VAL --> REPORT
    ORCH --> RECON
    ORCH --> REG
    REG --> S1
    REG --> S2
    REG --> S3
    REG --> S4
    RECON --> TARGET
    S1 --> TARGET
    S2 --> TARGET
    S3 --> TARGET
    S4 --> TARGET
    S1 --> FM
    S2 --> FM
    S3 --> FM
    S4 --> FM
    FM --> REM
    FV --> ORCH
    REPORT --> FM
    REPORT --> REM
    FM --> REPO
    REPO --> DB
    REG -. V2 .-> OSV
```

### Explanation

1. **React** sends an authenticated REST request.
2. **API routing** maps the request to a use case.
3. **AuthN/AuthZ** proves who the user is and whether they may perform the action.
4. **Pydantic** validates and normalizes the request body.
5. A scan request goes to the **scan orchestrator**.
6. The orchestrator calls **reconnaissance** to build a list of pages, forms, and parameters.
7. The **scanner registry** selects the checks to run.
8. Each scanner returns structured findings; scanners do not write directly to the database.
9. **Finding management** normalizes, deduplicates, redacts, and persists findings.
10. **Remediation** attaches plain-language guidance.
11. **Fix verification** requests a targeted rescan through the orchestrator and compares the result.
12. **Report generation** builds a snapshot and renders HTML, JSON, or PDF.
13. **Repositories** use SQLAlchemy and asyncpg to talk to Neon.
14. **OSV** is called only by a future dependency scanner when dependency data is available.

---

## 5. Component Responsibilities

| Component | Responsibility | Technology | Input | Output |
|---|---|---|---|---|
| **React frontend** | UI, forms, dashboards, polling, display of findings and reports | React, TypeScript, Tailwind CSS | REST JSON, session cookie | API requests, rendered UI |
| **FastAPI backend** | Application entry point, business logic, validation, orchestration, error handling | Python, FastAPI, Pydantic | HTTP requests, service calls | JSON responses, scan jobs |
| **API routing layer** | Versioned endpoints, dependencies, status codes, pagination, OpenAPI contract | FastAPI routers | HTTP request | Service call |
| **Authentication and authorization** | Login, session management, CSRF, role/object checks | FastAPI dependencies, secure cookies, password hashing | Credentials, session cookie | Authenticated principal and decision |
| **Scan orchestration** | Owns scan lifecycle, budgets, timeouts, cancellation, check selection, result aggregation | Python async services | Validated scan request | Scan state, collected findings |
| **Reconnaissance engine** | Fetch seed page, parse links/forms, build scoped inventory, enforce crawl limits | HTTPX, BeautifulSoup | Target URL and scope | Pages, forms, parameters, headers, cookies |
| **OWASP scanner modules** | Run one safe check each; return evidence and mapping; no direct DB writes | Python modules, HTTPX | Recon inventory and scope | Structured findings |
| **Finding management** | Normalize, fingerprint, deduplicate, redact, score, persist, query | Python services, SQLAlchemy | Raw scanner output | Stored findings and API DTOs |
| **Remediation service** | Map check IDs to plain-language fixes, references, and severity context | Rule/catalog service | Finding/check ID | Remediation guidance |
| **Fix verification service** | Request targeted rescan, compare old/new evidence, record result | Python service + orchestrator | Finding ID, scope | Verification status |
| **Report generation** | Build report snapshot and render HTML/JSON/PDF | Python renderers, ReportLab for PDF | Scan/findings/remediation data | Report artifact and metadata |
| **SQLAlchemy database layer** | Async engine/session, repositories, transactions, mapping | SQLAlchemy 2.x async, asyncpg | Service queries/commands | ORM objects, persisted data |
| **Neon PostgreSQL** | Durable relational storage, transactions, backups, branching | Neon Serverless PostgreSQL | SQL over TLS | Rows, query results, durability |
| **Authorized target** | External web application being assessed | HTTP/HTTPS | Scoped requests | HTTP responses |
| **OSV API (V2)** | External open-source vulnerability intelligence | HTTPS API | Package name, version, ecosystem | Known advisories |

---

## 6. Communication Paths

### 6.1 Browser to FastAPI

- HTTPS only.
- JSON request/response.
- Session cookie is `HttpOnly`, `Secure`, and `SameSite`.
- State-changing requests also require a CSRF token.
- The frontend does not trust its own authorization checks; the backend is authoritative.

### 6.2 FastAPI internal modules

- Modules call each other through Python interfaces inside one process.
- There is no network hop between the router, orchestrator, scanner registry, and finding service.
- This keeps the Lean MVP simple.
- Modules must not reach across boundaries directly: a scanner does not write to the database; it returns findings to the orchestrator/finding service.

### 6.3 FastAPI to Neon

- SQLAlchemy async engine and sessions.
- asyncpg driver.
- TLS-encrypted PostgreSQL connection.
- Credentials come from server-side secrets, never from the browser.
- Short transactions; no open transaction while waiting for a target scan.

### 6.4 Scanner to target

- HTTPX with explicit timeouts, redirect policy, response-size limits, and rate limiting.
- Every request passes through the scope guard.
- No JavaScript execution.
- No destructive methods or payloads.
- The target sees only the minimum requests needed for the selected checks.

### 6.5 Scanner to OSV

- Optional, Version 2.
- HTTPS request containing only package name/version/ecosystem.
- Timeout and fallback: an OSV outage must not fail the whole scan.
- Cache results to reduce calls and rate-limit pressure.

### 6.6 Report service

- Reads a snapshot of the scan and findings.
- Applies the same redaction rules as the UI.
- Renders HTML, JSON, or PDF.
- ReportLab runs in-process for small reports; large PDF generation should move to a worker later.

---

## 7. Database Communication Flow

```mermaid
sequenceDiagram
    autonumber
    participant B as React Browser
    participant A as FastAPI API
    participant S as Service Layer
    participant R as Repository
    participant O as SQLAlchemy Async
    participant P as asyncpg
    participant N as Neon PostgreSQL
    participant M as Alembic

    B->>A: HTTPS REST + session cookie
    A->>A: Authenticate, authorize, validate
    A->>S: Call use case
    S->>R: Query or command
    R->>O: ORM operation
    O->>P: Async SQL + bound parameters
    P->>N: TLS connection
    N-->>P: Result rows
    P-->>O: Driver result
    O-->>R: ORM objects
    R-->>S: Domain data
    S-->>A: Response DTO
    A-->>B: JSON
    M->>N: Direct TLS migration connection (separate)
    Note over B,N: Browser never connects to Neon. Credentials stay server-side.
```

### Explanation

1. React sends an HTTP request. It has no database driver and no database credentials.
2. FastAPI authenticates the session and checks authorization.
3. Pydantic validates request data.
4. The service layer performs the use case.
5. The repository isolates database access from business logic.
6. SQLAlchemy turns ORM operations into SQL.
7. asyncpg sends the SQL and bound parameters over TLS to Neon.
8. Neon executes the query and returns rows.
9. Results flow back as ORM objects, then domain data, then response DTOs.
10. Alembic uses a **separate direct connection** for migrations. It is not part of the request path.

### Key database decisions

- **No long transactions during scanning.** A scan can take minutes. Holding a database transaction open would waste connections and risk timeouts.
- **Persist progress in short transactions.** Scan state, findings, and verification results are written as they become available.
- **Bind every parameter.** Do not build SQL with string concatenation.
- **Use repositories.** Routers and scanners do not contain SQL.
- **Use separate database roles.** The runtime role has only the privileges it needs; the migration role is separate.
- **Use pagination.** Scan history and findings will grow.

---

## 8. Neon Integration

### 8.1 How FastAPI connects to Neon

FastAPI does not connect to Neon directly. The chain is:

> FastAPI → SQLAlchemy async engine → asyncpg → TLS → Neon PostgreSQL

The backend reads the database URL from a server-side secret. A simplified connection string looks like:

```text
postgresql://USER:PASSWORD@HOST/DATABASE?sslmode=verify-full
```

For SQLAlchemy with asyncpg, the scheme changes:

```text
postgresql+asyncpg://USER:PASSWORD@HOST/DATABASE
```

The exact SSL arguments depend on the driver. The important rule is: **use TLS with certificate and hostname verification; do not disable certificate checks.**

### 8.2 What a Neon connection string contains

| Part | Meaning |
|---|---|
| `postgresql` | PostgreSQL protocol |
| `USER` | Database role name |
| `PASSWORD` | Secret for that role |
| `HOST` | Neon endpoint hostname |
| `DATABASE` | Database name |
| `sslmode=verify-full` | Require TLS and verify the certificate and hostname |
| `channel_binding=require` | Optional extra protection for SCRAM authentication |

Neon shows two host styles:

- **Direct endpoint:** `ep-example-123456.region.aws.neon.tech`
- **Pooled endpoint:** `ep-example-123456-pooler.region.aws.neon.tech`

The `-pooler` suffix means the connection goes through Neon’s PgBouncer pool.

Never commit a real connection string. Never put it in a React environment variable, because frontend environment variables are shipped to the browser.

### 8.3 How SQLAlchemy communicates with Neon

SQLAlchemy:

- manages an async engine and connection pool;
- opens an `AsyncSession` for a unit of work;
- maps Python objects to tables;
- sends parameterized SQL through asyncpg;
- handles transactions and rollbacks.

The ORM models are not sent directly to React. API responses use separate Pydantic schemas. This avoids leaking database structure and prevents accidental mass assignment.

### 8.4 How asyncpg fits

asyncpg is the PostgreSQL driver under SQLAlchemy’s async engine. It:

- opens TCP/TLS connections;
- authenticates with the database;
- sends queries and receives rows;
- supports asynchronous I/O so one backend process can handle many waiting operations.

asyncpg does not replace SQLAlchemy. SQLAlchemy provides the ORM, session, and repository structure; asyncpg provides the wire protocol.

### 8.5 Why SSL/TLS matters

Without TLS, anyone who can observe the network could see:

- database usernames and passwords;
- scanned evidence and findings;
- session data;
- personal information.

TLS creates an encrypted tunnel. Certificate verification prevents an attacker from impersonating the database server. Neon requires TLS; VulnSight should use the strongest practical verification mode, ideally `verify-full`, plus channel binding where supported.

### 8.6 What connection pooling means

Opening a PostgreSQL connection is relatively expensive. A connection pool keeps a small number of reusable connections open and lends them to requests.

Think of a taxi stand:

- Without a pool, every request calls a new taxi.
- With a pool, a limited number of taxis are shared, and requests wait briefly if all are busy.

Pooling reduces connection overhead and protects the database from connection exhaustion. But pools must be sized carefully:

- Too small: requests wait.
- Too large: the database runs out of connections.
- SQLAlchemy pool plus Neon pool can become **double pooling** if both are large.

### 8.7 Direct or pooled Neon endpoint?

For the **Lean MVP**, the recommended default is:

- **Direct Neon endpoint** for the long-lived FastAPI process.
- A small SQLAlchemy pool, because the app has one backend instance and one scan at a time.
- **Direct endpoint for Alembic migrations**, always.

Use the **pooled endpoint** when:

- you deploy many short-lived backend instances;
- you use serverless functions or a platform that opens a connection per request;
- connection churn is high;
- you need many client connections but a small database connection limit.

With Neon’s pooled endpoint:

- PgBouncer runs in transaction mode.
- Connections return to the pool after each transaction.
- Session-level features such as `SET`, `LISTEN/NOTIFY`, temporary tables with `PRESERVE`, and session-level advisory locks are not reliable.
- SQL-level `PREPARE`/`DEALLOCATE` is not supported.
- asyncpg prepared statement caching needs care. If you use the pooled endpoint with asyncpg, disable or carefully configure the prepared statement cache, or use the direct endpoint. For the simple MVP, the direct endpoint avoids this class of problem.

If you later move to a serverless API platform, switch to the pooled endpoint and revisit the asyncpg settings. Do not guess: test migrations, prepared statements, and transaction behavior against the chosen endpoint.

### 8.8 Protecting database credentials

- Store secrets in a secret manager or protected environment variables.
- Never put credentials in source code, Git, logs, screenshots, or the frontend bundle.
- Use a dedicated runtime database role with only the required privileges.
- Use a separate migration/owner role.
- Rotate credentials if exposure is suspected.
- Restrict network access to Neon where the platform supports it.
- Enable TLS and verify certificates.
- Never log the full connection string.
- Never return database errors to the browser.

### 8.9 React must never connect directly to Neon

The React app must not have:

- a PostgreSQL driver;
- a Neon connection string;
- a database username or password;
- direct SQL access.

If it did, any user could read or modify data by inspecting the browser, bypass authorization, and steal credentials. All database access goes through FastAPI, which enforces authentication, authorization, validation, and audit logging.

---

## 9. End-to-End Workflow

```mermaid
flowchart TD
    A[User submits authorized URL] --> B[React POST /api/v1/scans]
    B --> C[FastAPI: auth, validation, allowlist]
    C -->|rejected| X[4xx error + audit]
    C -->|accepted| D[Create scan, return 202 Accepted]
    D --> E[Scan Orchestrator]
    E --> F[Recon Engine: crawl max 20 pages]
    F --> G[Scanner Registry: 8 safe checks]
    G --> H[Collect findings + evidence]
    H --> I[Normalize, dedupe, redact, map OWASP]
    I --> J[Persist via SQLAlchemy -> Neon]
    J --> K[React polls GET /scans/id]
    K --> L[User views finding + remediation]
    L --> M[User requests verification]
    M --> N[Targeted rescan of affected URL/check]
    N --> O[Compare old vs new evidence]
    O --> P[Store verification result]
    P --> Q[Status: fixed / still present / inconclusive]
```

### Step 1 — User enters an authorized website URL

React validates the URL for usability: scheme, hostname, no obvious mistakes. This is not a security decision. The browser sends the URL, target name, and authorization confirmation to FastAPI.

### Step 2 — React sends a request to FastAPI

The request uses HTTPS, the session cookie, and a CSRF token. React does not connect to Neon and does not start any scan logic itself.

### Step 3 — Backend validates the target and authorization

FastAPI:

- authenticates the session;
- validates the request with Pydantic;
- normalizes the URL;
- allows only HTTP/HTTPS;
- rejects credentials embedded in the URL;
- checks the target against the allowlist;
- checks authorization confirmation;
- applies SSRF and private-address rules;
- records the attempt in the activity log.

If validation fails, the API returns a clear 4xx error and does not start a scan.

### Step 4 — Scan orchestration starts reconnaissance

The orchestrator:

- creates the scan record;
- sets the budget: 20 pages, depth 2, 5 minutes, 2 requests per second;
- sets state to queued;
- returns `202 Accepted` with a scan ID;
- starts or hands off the scan worker.

The request does not stay open for the entire scan. This is important because scans can take minutes.

### Step 5 — Reconnaissance

The recon engine:

- fetches the seed page with HTTPX;
- extracts same-origin links and forms with BeautifulSoup;
- records URLs, parameters, headers, and cookies;
- enforces depth, page, size, and time limits;
- follows redirects only after scope revalidation;
- does not execute JavaScript.

The output is a scope-safe inventory, not a list of vulnerabilities.

### Step 6 — Individual scanners perform checks

The scanner registry runs the 8 MVP checks:

1. security headers;
2. cookie flags;
3. HTTPS and login transport;
4. CORS wildcard;
5. directory listing;
6. version disclosure;
7. reflected XSS canary;
8. verbose error handling.

Each scanner:

- receives only the scoped inventory;
- uses harmless requests;
- has its own timeout;
- returns structured results;
- cannot write directly to the database;
- cannot call outside the scope guard.

### Step 7 — Findings and evidence are processed

Finding management:

- normalizes titles and descriptions;
- deduplicates by check + URL;
- assigns severity and confidence;
- maps to OWASP Top 10:2025 and CWE where applicable;
- redacts cookies, authorization headers, tokens, and personal data;
- attaches remediation guidance and references;
- stores short, redacted evidence.

### Step 8 — SQLAlchemy stores information in Neon

The repository layer writes scan status and findings in short transactions. The app does not hold a transaction open while waiting for the target. If a check fails, the scan can complete with partial results and a clear warning.

### Step 9 — React retrieves scan results

React polls `GET /api/v1/scans/{id}` and then `GET /api/v1/findings`. The backend enforces authorization on every request and returns paginated DTOs, not raw database rows. Polling is sufficient for the Lean MVP; Server-Sent Events or WebSockets can replace it later.

### Step 10 — User opens a vulnerability and views remediation

The finding detail page shows:

- affected URL and parameter;
- evidence;
- severity and confidence;
- OWASP category and CWE;
- remediation steps;
- references;
- false-positive control.

Remediation is deterministic and reviewable in the MVP. It is not AI-generated.

### Step 11 — User fixes the issue and requests verification

The user selects a finding and requests verification. The backend checks that the finding and target are in scope, then asks the fix-verification service to rescan the affected URL with the relevant check.

This should be a **targeted rescan**, not a full crawl. It is faster and reduces load on the target.

### Step 12 — Verification results are stored in Neon

The verification service compares the old and new evidence:

- **fixed:** the issue was not observed in this targeted check.
- **still present:** the same evidence is observed.
- **inconclusive:** the page changed, the check could not run, or the result is ambiguous.

The result is stored, the finding status is updated, and the activity log records the action. A clean verification means “not observed in this check at this time,” not “the whole application is secure.”

---

## 10. Security Architecture

### 10.1 Unauthorized scanning

**Risk:** someone uses VulnSight to attack a third-party site.

**Controls:**

- Authentication on every scan endpoint.
- Explicit authorization confirmation.
- Operator-managed target allowlist in the Lean MVP.
- Future DNS/HTML ownership verification for public targets.
- Per-user and global quotas.
- Full activity logging.
- Immediate scan cancellation and account suspension.
- Clear acceptable-use policy.

### 10.2 SSRF

**Risk:** the scanner is tricked into requesting internal services, cloud metadata, or arbitrary ports.

**Controls:**

- Allow only `http` and `https`.
- Reject URLs containing credentials.
- Canonicalize the hostname and reject unusual IP representations.
- Resolve DNS and check every returned IPv4/IPv6 address.
- Block loopback, private, link-local, multicast, reserved, documentation, and cloud-metadata ranges.
- Block non-standard ports by default.
- Follow redirects manually and revalidate every hop.
- Limit response size and time.
- Disable environment proxies for scanner traffic.
- Use an egress firewall or dedicated scan network.
- For higher assurance, route scans through a dedicated egress proxy with an allowlist.

### 10.3 DNS rebinding

**Risk:** the attacker’s DNS answer is safe during validation, then changes to an internal address when the actual request is made. This is a time-of-check/time-of-use attack.

**Controls:**

- Resolve the hostname before the request.
- Validate every returned address.
- Pin the connection to the validated IP instead of re-resolving inside the HTTP client.
- Revalidate redirects and new hostnames.
- Use a custom HTTPX transport or egress proxy that enforces the validated destination.
- Do not rely only on a hostname string check.

This is one of the reasons a dedicated egress gateway is recommended for a production scanner. For the Lean MVP, allowlisting lab targets and blocking private ranges reduces risk substantially.

### 10.4 Private IP scanning

**Risk:** the scanner reaches internal networks or cloud metadata.

**Controls:**

- Deny private and special-use ranges by default.
- Allow localhost/private lab addresses only in an explicitly enabled **lab mode**.
- Keep the lab allowlist operator-controlled.
- Apply network policy so the scanner container cannot reach unrelated internal services.
- Log every blocked destination.

### 10.5 Excessive requests

**Risk:** the scanner accidentally performs a denial-of-service attack or gets the user blocked.

**Controls:**

- Per-target rate limit (default 2 requests per second).
- Global concurrency limit.
- Page, depth, time, and response-size budgets.
- Backoff on 429/5xx and network errors.
- Cancellation token checked between requests.
- Circuit breaker after repeated failures.
- One scan at a time in the Lean MVP.

### 10.6 Database credential leakage

**Controls:**

- Server-side secret storage only.
- No credentials in React, Git, logs, reports, or error messages.
- Separate runtime and migration roles.
- Least privilege.
- TLS with certificate verification.
- Credential rotation.
- Restricted network access to Neon where available.
- Audit access to secrets.

### 10.7 SQL injection

**Controls:**

- SQLAlchemy parameter binding for all values.
- No string-concatenated SQL.
- Any raw SQL requires review and parameterization.
- Pydantic validation at the boundary.
- Least-privilege database role.
- Separate migration role.
- Error messages do not expose SQL or schema details.
- Dependency and code review for database libraries.

### 10.8 Sensitive evidence leakage

**Risk:** scan evidence contains cookies, tokens, personal data, or secrets.

**Controls:**

- Redact at capture time, before persistence.
- Never store full response bodies by default.
- Cap evidence size.
- Encrypt data at rest through Neon and platform controls.
- Restrict evidence access by authorization.
- Exclude secrets from logs and reports.
- Apply retention and deletion.
- Treat reports as confidential by default.

### 10.9 Unauthorized access to scan history

**Controls:**

- Authenticate every API request.
- Authorize every object access, not just the route.
- Scope queries to the current workspace/user.
- Do not rely on unguessable IDs alone.
- Prevent IDOR by checking ownership on the server.
- Paginate and filter on the server.
- Log access to sensitive results.
- Use secure session cookies and CSRF protection.

### 10.10 Additional web security

- React escapes output by default; avoid unsafe HTML injection.
- Use a Content-Security-Policy on the frontend.
- Restrict CORS to the known frontend origin.
- Rate-limit login.
- Hash the admin password with Argon2id.
- Rotate sessions after login.
- Do not expose stack traces to users.
- Keep dependencies patched and run SCA.

---

## 11. Future Scalability

### 11.1 Additional OWASP scanners

Use a scanner plugin contract:

- stable check ID;
- metadata (OWASP category, CWE, severity, confidence, safe payload rules);
- `run(context)` interface;
- timeout and resource limits;
- structured finding output;
- independent tests;
- enable/disable flags;
- versioned check sets.

The registry selects checks by scan profile. New checks do not require changes to the API contract.

### 11.2 Background scanning tasks

The Lean MVP can run one scan in a worker process. For growth:

- introduce a durable job queue;
- run multiple workers;
- add retries with backoff;
- add dead-letter handling;
- make scan start idempotent;
- publish progress events;
- support cancellation across workers;
- separate risky/heavy checks into isolated workers.

### 11.3 Multiple simultaneous scans

- Add per-target locks so the same target is not scanned twice at once.
- Add global and per-user concurrency limits.
- Use a queue with fairness.
- Store job state durably in PostgreSQL.
- Apply backpressure when the queue is full.
- Keep API instances stateless so they can scale horizontally.

### 11.4 More users

- Add RBAC (Admin, Analyst, Viewer).
- Add workspace/tenant scoping to every query.
- Use a shared session store or signed session tokens.
- Add SSO/OIDC.
- Add per-user quotas and audit.
- Keep authorization checks at the service layer.
- Size SQLAlchemy and Neon pools for the number of API instances.

### 11.5 Larger scan histories

- Paginate all lists.
- Add indexes for common filters.
- Apply retention and archival.
- Partition very large tables if needed.
- Move large report/evidence artifacts to object storage.
- Use Neon read replicas for read-heavy reporting.
- Cache dashboard aggregates.
- Keep hot operational data separate from historical data.

### 11.6 Additional reporting features

- Keep a renderer interface: HTML, JSON, PDF, CSV, SARIF.
- Generate large reports asynchronously.
- Store report artifacts in object storage with signed, expiring links.
- Snapshot the findings used in a report so it remains reproducible.
- Add templates and branding.
- Add compliance mappings without claiming certification.
- Test accessibility and print layout.

### 11.7 What not to do yet

- Do not split into microservices.
- Do not add a message broker before there is real concurrency.
- Do not add a data warehouse before scan history is large.
- Do not add AI before deterministic remediation is solid.
- Do not over-pool the database.
- Do not expose the scanner directly to the internet.

---

## 12. Important Architectural Decisions

| ID | Decision | Reason | Consequence |
|---|---|---|---|
| AD-01 | Modular monolith, not microservices | One developer, small MVP | Simpler build; modules can be extracted later |
| AD-02 | React SPA + FastAPI REST API | Clear separation, standard tooling | Requires API contracts and auth |
| AD-03 | Server-side session cookie, not JWT in localStorage | Safer against token theft via XSS; simpler for same-origin SPA | Needs CSRF protection and same-origin deployment |
| AD-04 | SQLAlchemy async + asyncpg | Async I/O, strong ORM/repository structure | Must manage sessions and pooling carefully |
| AD-05 | Neon PostgreSQL | Managed Postgres, branching, low idle cost | Cold starts and connection limits matter |
| AD-06 | Direct Neon endpoint for the MVP FastAPI process | Avoid PgBouncer/asyncpg prepared-statement complexity | Revisit when scaling to many instances |
| AD-07 | Scan work runs outside the request | Scans take minutes; API must stay responsive | Needs worker/job state and polling |
| AD-08 | Scanner plugin registry | Add checks without rewriting orchestration | Requires stable check contract |
| AD-09 | Redact before persistence | Evidence can contain secrets | Slightly more work at write time |
| AD-10 | Report renderer abstraction | HTML/JSON/PDF share one data snapshot | More structure, less duplication |
| AD-11 | Polling for MVP progress | Simple and reliable | Higher request volume than SSE; acceptable at small scale |
| AD-12 | OSV and full fix verification are V2 | They need dependency data and more scan modes | Lean MVP stays small |
| AD-13 | No JavaScript rendering in MVP crawler | Simpler and safer | Some SPA routes are not discovered |
| AD-14 | Same-origin deployment | Simpler cookies/CORS | Frontend and API share a domain/reverse proxy |

---

## 13. Scope Alignment With the Lean MVP

| Requested component | Lean MVP status | Recommendation |
|---|---|---|
| React frontend | In MVP | Build the 5–6 screens needed for the demo |
| FastAPI backend | In MVP | Modular monolith |
| API routing | In MVP | Versioned REST + OpenAPI |
| Auth/authz | Single admin in MVP | Session cookie; design for future RBAC |
| Scan orchestration | In MVP | One scan at a time |
| Recon engine | In MVP | 20 pages, depth 2, no JavaScript |
| Modular OWASP scanners | 8 checks in MVP | Plugin contract from the start |
| Finding management | In MVP | Normalize, dedupe, redact, status |
| Remediation service | In MVP | Deterministic catalog |
| Fix verification | Simple version possible; full version V2 | Recommend a targeted rescan after MVP core works |
| Report generation | HTML/JSON in MVP | Add ReportLab PDF as a small optional increment |
| SQLAlchemy layer | In MVP | Async engine + repositories |
| Neon | In MVP | Direct endpoint, small pool |
| OSV dependency checks | V2 | Needs manifest/SBOM input; not a URL-only check |

**Honest limitation:** OSV cannot meaningfully assess a website’s dependencies from a URL alone. It needs a dependency manifest or SBOM. It belongs to the Version 2 source/dependency scanning mode.

---

## 14. Architecture Summary

VulnSight is a **modular monolith**:

- **React + TypeScript + Tailwind** provides the browser UI.
- **FastAPI + Pydantic** provides the API, validation, authentication, orchestration, and business logic.
- **Scan orchestration** runs outside the request and coordinates reconnaissance plus modular checks.
- **HTTPX + BeautifulSoup** perform scoped, non-destructive crawling and observation.
- **Finding management** normalizes, deduplicates, redacts, and persists results.
- **Remediation** supplies deterministic, beginner-friendly fixes.
- **Fix verification** performs a targeted rescan and compares evidence.
- **Report generation** renders HTML/JSON, with ReportLab for PDF.
- **SQLAlchemy async + asyncpg** is the only database access path.
- **Neon PostgreSQL** stores durable state and results.
- **React never connects to Neon.**

The main flow is:

> User → React → FastAPI → authorization and validation → scan orchestrator → recon and scanners → finding management → SQLAlchemy → Neon → React.

The security boundary is the FastAPI API and the scanner egress path, not the browser.

### Approval requested

| Decision | Status |
|---|---|
| Modular monolith architecture | ☐ |
| React SPA + FastAPI REST API | ☐ |
| Session-cookie authentication for MVP | ☐ |
| SQLAlchemy async + asyncpg | ☐ |
| Neon as the database | ☐ |
| Direct Neon endpoint for the MVP | ☐ |
| One scan worker, no queue in MVP | ☐ |
| 8 scanner modules with plugin contract | ☐ |
| OSV, full fix verification, and PDF phased as described | ☐ |
| Permission to proceed to Step 3 | ☐ |

**Step 2 stops here.** No application code or detailed database schema has been written. I will wait for approval before designing the database schema or implementation plan.
