# VulnSight — Database Architecture and Schema

| Field | Value |
|---|---|
| Step | 4 — Backend and Neon database |
| Status | Schema implemented, migrated to Neon, and verified |
| Migration | `2f6893bcadd8_initial_schema.py` |
| Database | Neon Serverless PostgreSQL (direct endpoint) |

This document explains the database technology, the design of each table, and
the Alembic workflow. API endpoints and testing are in
[`api.md`](./api.md).

---

## 1. How the Pieces Fit Together

```text
Browser (React)
   |  HTTPS/JSON, never a database credential
   v
FastAPI route  ── validates input with Pydantic schemas
   |
   v
Service layer  ── business rules, transactions, audit entries
   |
   v
SQLAlchemy ORM ── models -> parameterized SQL, identity map, relationships
   |
   v
asyncpg driver ── PostgreSQL wire protocol over TLS
   |
   v
Neon PostgreSQL (direct endpoint)
```

Alembic is a separate, offline tool. It connects directly to Neon with the same
`DATABASE_URL`, compares the live schema with `Base.metadata`, and applies
versioned migration scripts. It does not run inside the FastAPI process.

---

## 2. Core Concepts

### 2.1 What is an ORM?

An **Object-Relational Mapper** maps:

- a Python class to a database table;
- a Python object to a row;
- an attribute to a column;
- an object reference to a foreign-key relationship.

Instead of writing `SELECT ... FROM findings WHERE id = ...` by hand and
copying columns into dictionaries, the application works with `Finding` objects.
The ORM still produces real SQL; it removes repetitive translation code and
helps keep queries parameterized.

### 2.2 Why SQLAlchemy?

- **Mature and explicit.** It supports both ORM queries and raw SQL when needed.
- **Relationships.** `ScanSession.findings` and `Finding.scan` are declared once
  and reused.
- **Safety.** Values are bound as parameters, which prevents SQL injection.
- **Async support.** `sqlalchemy.ext.asyncio` integrates with FastAPI.
- **Alembic integration.** Alembic can compare the ORM metadata with the live
  database and generate migrations.
- **Portability.** The same models work with another PostgreSQL provider.

### 2.3 What is asyncpg?

`asyncpg` is a fast, asynchronous PostgreSQL driver. SQLAlchemy does not speak
the PostgreSQL network protocol itself; it delegates that work to a **DBAPI**
driver. Here the driver is `asyncpg`, selected by the `postgresql+asyncpg://`
URL scheme.

`asyncpg` is **not** an ORM. It executes SQL and returns rows. SQLAlchemy sits
above it.

### 2.4 Why asynchronous database operations?

FastAPI handles requests on an event loop. A synchronous driver would block that
loop while waiting for Neon, preventing other requests from progressing. With
`asyncpg`, a request waiting on the network yields control, so the server can
process other work.

The benefit is **concurrency**, not raw speed. One query is still one query. A
single local user will not notice a large difference, but the pattern avoids a
blocking design that becomes painful when scans and reports run concurrently.

### 2.5 What are database models?

Models are Python classes that describe persistent tables:

```python
class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "findings"
    ...
```

They define columns, types, keys, constraints, indexes, and relationships. They
belong to the database layer and must not be returned directly to the browser.

### 2.6 What are Pydantic schemas?

Pydantic schemas describe the **API contract**: what a request may contain and
what a response will contain. For example:

- `ScanCreate` accepts a name, profile, and target list.
- `ScanDetail` returns IDs, counts, and timestamps.
- `FindingDetail` nests evidence, remediation, and verification history.

Keeping models and schemas separate means:

- database columns are not automatically exposed;
- secrets and internal fields stay internal;
- API changes do not silently alter the schema;
- input validation happens before a service touches the database.

`ORMModel` sets `from_attributes=True`, so a schema can be built from a model
instance after the service has loaded what the response needs.

### 2.7 What are database migrations?

A migration is a versioned, repeatable description of a schema change:

```text
empty database -> 2f6893bcadd8 (initial schema) -> future revision -> ...
```

Instead of manually running `CREATE TABLE` in a production console, the change
is stored in Git, reviewed, and applied by a tool. This gives:

- an audit trail of schema changes;
- consistent environments;
- a rollback path;
- no "works on my machine" schema drift.

### 2.8 What is Alembic?

Alembic is the migration tool for SQLAlchemy. It reads model metadata, compares
it with the database, and writes a revision file. `alembic upgrade head` applies
pending revisions; `alembic downgrade <revision>` reverses them.

### 2.9 How does FastAPI communicate with Neon?

1. A request reaches a FastAPI route.
2. A FastAPI dependency (`get_session`) yields an `AsyncSession`.
3. The route calls a service.
4. The service uses the session to build a `select(...)`, insert, or update.
5. SQLAlchemy compiles that to SQL and sends it through `asyncpg`.
6. `asyncpg` writes it on a TLS connection to Neon.
7. Rows come back, SQLAlchemy builds model objects, the service commits, and the
   route returns a Pydantic response.
8. The connection returns to the pool.

### 2.10 Session vs connection

| Concept | Meaning | Lifetime |
|---|---|---|
| **Connection** | A real network socket and PostgreSQL session | Reused from the pool for many requests |
| **Session** | A unit of work: identity map, pending changes, transaction | One request, or one short service task |
| **Transaction** | An atomic set of statements, `BEGIN` to `COMMIT`/`ROLLBACK` | Usually one session operation |

A session checks out a connection when it first needs one and returns it when
the session closes. Committing ends the transaction but does not necessarily
close the connection. Pooling avoids paying connection setup cost on every
request.

The dependency does **not** auto-commit. Services commit explicitly so they
control transaction boundaries and audit records.

---

## 3. Connection Configuration

### 3.1 Secret handling

- The real URL lives only in `backend/.env`.
- `.env` is ignored by Git.
- `.env.example` contains placeholders only.
- The React app has no database variable and never receives the URL.
- Logs report exception types, not credentials or connection details.
- API errors are generic.

### 3.2 URL normalization

Neon displays a URL such as:

```text
postgresql://user:password@ep-example.region.aws.neon.tech/neondb?sslmode=require&channel_binding=require
```

`app/db/url.py`:

1. adds the `asyncpg` driver (`postgresql+asyncpg://`);
2. removes libpq-only options (`sslmode`, `ssl`, `channel_binding`), because
   asyncpg does not accept them as URL parameters.

TLS is supplied separately as an SSL context.

### 3.3 TLS

Neon requires encryption. The engine creates:

```python
ssl_context = ssl.create_default_context(cafile=certifi.where())
```

and passes it through `connect_args={"ssl": ssl_context}`. Certificates are
verified. Do not disable verification to work around a local TLS problem.

### 3.4 Connection pooling

`app/db/engine.py` uses:

| Setting | Value | Reason |
|---|---|---|
| `pool_size` | 5 | Small local MVP; enough concurrent requests |
| `max_overflow` | 5 | Short bursts up to 10 connections |
| `pool_timeout` | 30 s | Fail instead of waiting forever |
| `pool_recycle` | 300 s | Recycle connections before provider/network idle limits |
| `pool_pre_ping` | `True` | Detect dead connections before use |
| `pool_use_lifo` | `True` | Reuse the most recent connection, letting idle ones expire |

Neon's **direct** endpoint is used for the API and Alembic. The pooled
(`-pooler`) endpoint is deferred: in transaction mode, prepared statements and
session state need extra care, and one backend process does not need PgBouncer.

### 3.5 Health checks and cleanup

- `GET /api/v1/health` proves the API process is alive.
- `GET /api/v1/health/db` runs `SELECT 1` and returns latency.
- The FastAPI lifespan calls `dispose_engine()` on shutdown to close pooled
  connections.
- A failed request rolls the session back in `get_session` if an exception
  escapes.

### 3.6 Error handling

| Situation | Result |
|---|---|
| Validation error | `422` with code `validation_error` |
| Rule violation (bad host, duplicate target, wrong state) | `400`/`409` with a safe message |
| Missing record | `404` |
| Integrity/check/FK violation | `409` with code `data_conflict` |
| Other database failure | `503` with code `database_error` |
| Database not configured | `503` with code `database_not_configured` |

The database health endpoint returns its existing shape:
`{"status": "error", "database": "unavailable", "detail": "..."}`.

---

## 4. Schema Overview

All tables use UUID primary keys generated by the application. Timestamps are
timezone-aware (`timestamptz`). Enumerated values are stored as strings with
`CHECK` constraints instead of PostgreSQL enum types, because adding a value to
a check constraint is a simpler migration than altering an enum.

Naming conventions are defined in `app/db/base.py` so constraint and index names
are predictable:

- `pk_<table>`
- `fk_<table>_<column>_<referred_table>`
- `ck_<table>_<name>`
- `ix_<table>_<column>`
- `uq_<table>_<column>`

### 4.1 `users`

**Purpose:** local operator identity and ownership for scans, remediation
updates, verification requests, reports, and audit entries. No login endpoint is
part of the Lean MVP; `password_hash` is nullable so authentication can be added
later without a destructive migration.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `email` | varchar(320) | Unique, indexed, must be lowercase |
| `display_name` | varchar(120) | Required |
| `password_hash` | varchar(255) | Nullable; no credentials stored yet |
| `role` | varchar(20) | `admin`/`analyst`/`viewer`, default `admin` |
| `is_active` | boolean | Default `true` |
| `last_login_at` | timestamptz | Nullable |
| `created_at`, `updated_at` | timestamptz | Server defaults |

Constraints/indexes: unique email index, role check, lowercase email check.

Relationships: one user has many scans, remediation updates, verification
requests, reports, and audit logs.

### 4.2 `scan_sessions`

**Purpose:** one authorized assessment run and its lifecycle state.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `name` | varchar(200) | Required |
| `status` | varchar(20) | `pending`, `running`, `completed`, `failed`, `cancelled` |
| `profile` | varchar(50) | Only `lean_mvp` in this scope |
| `status_message` | text | Human-readable progress/error message |
| `created_by_id` | uuid | FK → `users.id`, `ON DELETE SET NULL` |
| `started_at`, `finished_at` | timestamptz | Lifecycle timestamps |
| `created_at`, `updated_at` | timestamptz | Server defaults |

Constraints/indexes:

- check on `status`;
- check on `profile`;
- index on `status`, `created_by_id`, and `created_at`;
- **partial unique index** `uq_scan_sessions_single_running` on `status` where
  `status = 'running'`.

That partial index is the database guarantee that only one scan runs at a time.
The service also checks first so the user gets a friendly `409` instead of a raw
integrity error.

### 4.3 `scan_targets`

**Purpose:** the explicit URLs authorized for this scan. This is the durable
scope declaration shown in reports.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `scan_id` | uuid | FK → `scan_sessions.id`, `ON DELETE CASCADE` |
| `url` | varchar(2048) | Canonical validated URL |
| `scheme` | varchar(10) | `http`/`https` |
| `hostname` | varchar(253) | Normalized host |
| `port` | integer | Nullable, 1–65535 |
| `path` | varchar(1024) | Default `/` |
| `is_authorized` | boolean | Default `true` |
| `authorization_reference` | varchar(255) | Optional ticket/approval reference |
| `created_at` | timestamptz | Server default |

Constraints/indexes: unique `(scan_id, url)`, scheme check, port check, indexes
on `scan_id` and `hostname`.

The API rejects:

- anything except `http`/`https`;
- embedded username/password;
- fragments and query strings;
- blank values and control characters;
- a hostname that is not an exact match in `SCAN_ALLOWED_HOSTS`;
- duplicate canonical URLs in one scan;
- more than `SCAN_MAX_TARGETS` (default 10).

No wildcard matching is implemented.

### 4.4 `discovered_endpoints`

**Purpose:** URLs and HTTP methods found under an authorized target. This table
exists for the later crawler; the placeholder executor creates no rows.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `scan_id` | uuid | FK → `scan_sessions.id`, cascade |
| `target_id` | uuid | FK → `scan_targets.id`, cascade |
| `method` | varchar(10) | Allowed HTTP method |
| `url` | text | Full URL |
| `url_hash` | varchar(64) | SHA-256 hex for deduplication |
| `path` | varchar(2048) | Path component |
| `status_code` | integer | Nullable, 100–599 |
| `content_type` | varchar(255) | Nullable |
| `discovered_at` | timestamptz | Server default |

Constraints/indexes: unique `(scan_id, method, url_hash)`, method check, status
check, indexes on `scan_id`, `target_id`, and `url_hash`.

`url_hash` keeps the unique index small; two long URLs can exceed PostgreSQL's
btree entry limit.

Relationships: belongs to one scan and one target; has many findings.

### 4.5 `findings`

**Purpose:** one observed weakness, mapped to an OWASP Top 10:2025 category.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `scan_id` | uuid | FK → `scan_sessions.id`, cascade |
| `endpoint_id` | uuid | Nullable FK → `discovered_endpoints.id`, `SET NULL` |
| `check_id` | varchar(50) | Stable identifier of the check |
| `owasp_category` | varchar(10) | `A01`–`A10` |
| `title` | varchar(200) | Short title |
| `description` | text | Explanation |
| `severity` | varchar(20) | `critical`/`high`/`medium`/`low`/`info` |
| `confidence` | varchar(20) | `certain`/`firm`/`tentative` |
| `status` | varchar(20) | `open`, `in_progress`, `remediated`, `verified`, `accepted_risk`, `false_positive` |
| `fingerprint` | varchar(64) | Nullable deduplication key |
| `created_at`, `updated_at` | timestamptz | Server defaults |

Constraints/indexes:

- unique `(scan_id, fingerprint)` (PostgreSQL allows multiple `NULL`s);
- checks on category, severity, confidence, and status;
- indexes on `scan_id`, `endpoint_id`, `check_id`, `owasp_category`, `severity`,
  `status`, `fingerprint`;
- composite indexes `(scan_id, severity)` and `(scan_id, status)` for list
  filtering.

Relationships: one scan, optional endpoint, many evidence rows, one remediation,
many verification runs.

`endpoint_id` uses `SET NULL` so deleting an endpoint does not destroy the
finding.

### 4.6 `evidence`

**Purpose:** redacted proof attached to a finding.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `finding_id` | uuid | FK → `findings.id`, cascade |
| `kind` | varchar(30) | `request`/`response`/`screenshot`/`log`/`text` |
| `label` | varchar(200) | Human-readable label |
| `content` | text | Redacted content only |
| `content_sha256` | varchar(64) | Exactly 64 hex characters |
| `is_redacted` | boolean | Default `true` |
| `created_at` | timestamptz | Server default |

Constraints/indexes: kind check, SHA-256 length check, indexes on `finding_id`
and `kind`.

Rules: never store raw cookies, `Authorization` headers, tokens, passwords, or
unredacted request bodies. Evidence is redacted **before** insertion.

### 4.7 `remediations`

**Purpose:** one-to-one guidance and workflow state for a finding.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `finding_id` | uuid | Unique FK → `findings.id`, cascade |
| `summary` | text | What to change |
| `steps` | json | Ordered list of strings |
| `references` | json | List of URLs or document names |
| `status` | varchar(20) | `not_started`/`in_progress`/`done`/`accepted_risk` |
| `notes` | text | Operator notes |
| `updated_by_id` | uuid | Nullable FK → `users.id`, `SET NULL` |
| `created_at`, `updated_at` | timestamptz | Server defaults |

Constraints/indexes: unique `finding_id`, status check, indexes on `finding_id`,
`status`, `updated_by_id`.

JSON is used for steps/references because they are ordered variable-length lists
that are always read with the remediation. They are not queried individually.

PATCH rules map remediation state to finding state:

| Remediation | Finding |
|---|---|
| `not_started` | `open` |
| `in_progress` | `in_progress` |
| `done` | `remediated` |
| `accepted_risk` | `accepted_risk` |

### 4.8 `verification_runs`

**Purpose:** durable history of fix-verification requests.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `finding_id` | uuid | FK → `findings.id`, cascade |
| `requested_by_id` | uuid | Nullable FK → `users.id`, `SET NULL` |
| `status` | varchar(20) | `pending`/`running`/`passed`/`failed`/`error`/`cancelled` |
| `started_at`, `finished_at` | timestamptz | Nullable |
| `result_summary` | text | Nullable |
| `details` | json | Nullable, non-sensitive details |
| `created_at` | timestamptz | Server default |

Constraints/indexes: status check, indexes on `finding_id`, `status`,
`requested_by_id`, and composite `(finding_id, created_at)`.

The verification engine is not implemented yet. A request creates a `pending`
row. A second active request for the same finding returns `409`.

### 4.9 `reports`

**Purpose:** immutable, versioned HTML/JSON report snapshots.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `scan_id` | uuid | FK → `scan_sessions.id`, cascade |
| `format` | varchar(10) | `html`/`json` |
| `status` | varchar(20) | `pending`/`generated`/`failed` |
| `version` | integer | Starts at 1 per scan and format |
| `file_name` | varchar(255) | Download name |
| `content_type` | varchar(100) | MIME type |
| `content` | text | Stored snapshot |
| `content_sha256` | varchar(64) | Nullable, exactly 64 chars |
| `size_bytes` | integer | Nullable, nonnegative |
| `generated_by_id` | uuid | Nullable FK → `users.id`, `SET NULL` |
| `created_at` | timestamptz | Server default |
| `generated_at` | timestamptz | Nullable |

Constraints/indexes: unique `(scan_id, format, version)`, format check, status
check, nonnegative size, SHA-256 length, indexes on `scan_id`, `format`,
`status`, `generated_by_id`.

Regeneration creates a new version instead of overwriting history. Download is a
separate endpoint that returns the stored content with `Cache-Control: no-store`
and `X-Content-Type-Options: nosniff`.

### 4.10 `audit_logs`

**Purpose:** append-only record of security-relevant actions.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `actor_id` | uuid | Nullable FK → `users.id`, `SET NULL` |
| `actor_label` | varchar(100) | Default `local-admin` |
| `action` | varchar(100) | e.g. `scan.created` |
| `entity_type` | varchar(50) | Nullable |
| `entity_id` | uuid | Nullable, intentionally not an FK |
| `scan_id` | uuid | Nullable FK → `scan_sessions.id`, `SET NULL` |
| `details` | json | Small redacted details |
| `request_id` | varchar(64) | Nullable, reserved for tracing |
| `created_at` | timestamptz | Server default |

Indexes: `action`, `actor_id`, `scan_id`, `created_at`, and
`(entity_type, entity_id)`.

`entity_id` is not a foreign key because it is polymorphic: it may point to a
scan, finding, report, or another entity. `details` must never contain secrets,
tokens, cookies, or raw evidence.

---

## 5. Entity-Relationship Diagram

```mermaid
erDiagram
    USERS ||--o{ SCAN_SESSIONS : creates
    USERS ||--o{ REMEDIATIONS : updates
    USERS ||--o{ VERIFICATION_RUNS : requests
    USERS ||--o{ REPORTS : generates
    USERS ||--o{ AUDIT_LOGS : acts

    SCAN_SESSIONS ||--o{ SCAN_TARGETS : authorizes
    SCAN_SESSIONS ||--o{ DISCOVERED_ENDPOINTS : discovers
    SCAN_SESSIONS ||--o{ FINDINGS : contains
    SCAN_SESSIONS ||--o{ REPORTS : produces
    SCAN_SESSIONS ||--o{ AUDIT_LOGS : records

    SCAN_TARGETS ||--o{ DISCOVERED_ENDPOINTS : owns
    DISCOVERED_ENDPOINTS ||--o{ FINDINGS : exposes

    FINDINGS ||--o{ EVIDENCE : supports
    FINDINGS ||--|| REMEDIATIONS : guides
    FINDINGS ||--o{ VERIFICATION_RUNS : verifies

    USERS {
        uuid id PK
        varchar email UK "lowercase, indexed"
        varchar display_name
        varchar password_hash "nullable"
        varchar role "admin|analyst|viewer"
        boolean is_active
        timestamptz last_login_at
        timestamptz created_at
        timestamptz updated_at
    }

    SCAN_SESSIONS {
        uuid id PK
        varchar name
        varchar status "pending|running|completed|failed|cancelled"
        varchar profile "lean_mvp"
        text status_message
        uuid created_by_id FK
        timestamptz started_at
        timestamptz finished_at
        timestamptz created_at
        timestamptz updated_at
    }

    SCAN_TARGETS {
        uuid id PK
        uuid scan_id FK
        varchar url "unique per scan"
        varchar scheme "http|https"
        varchar hostname
        integer port
        varchar path
        boolean is_authorized
        varchar authorization_reference
        timestamptz created_at
    }

    DISCOVERED_ENDPOINTS {
        uuid id PK
        uuid scan_id FK
        uuid target_id FK
        varchar method
        text url
        varchar url_hash "sha256"
        varchar path
        integer status_code
        varchar content_type
        timestamptz discovered_at
    }

    FINDINGS {
        uuid id PK
        uuid scan_id FK
        uuid endpoint_id FK "nullable"
        varchar check_id
        varchar owasp_category "A01..A10"
        varchar title
        text description
        varchar severity "critical|high|medium|low|info"
        varchar confidence "certain|firm|tentative"
        varchar status
        varchar fingerprint "unique per scan"
        timestamptz created_at
        timestamptz updated_at
    }

    EVIDENCE {
        uuid id PK
        uuid finding_id FK
        varchar kind
        varchar label
        text content "redacted only"
        varchar content_sha256
        boolean is_redacted
        timestamptz created_at
    }

    REMEDIATIONS {
        uuid id PK
        uuid finding_id FK "unique"
        text summary
        json steps
        json references
        varchar status
        text notes
        uuid updated_by_id FK
        timestamptz created_at
        timestamptz updated_at
    }

    VERIFICATION_RUNS {
        uuid id PK
        uuid finding_id FK
        uuid requested_by_id FK
        varchar status "pending|running|passed|failed|error|cancelled"
        timestamptz started_at
        timestamptz finished_at
        text result_summary
        json details
        timestamptz created_at
    }

    REPORTS {
        uuid id PK
        uuid scan_id FK
        varchar format "html|json"
        varchar status
        integer version
        varchar file_name
        varchar content_type
        text content
        varchar content_sha256
        integer size_bytes
        uuid generated_by_id FK
        timestamptz created_at
        timestamptz generated_at
    }

    AUDIT_LOGS {
        uuid id PK
        uuid actor_id FK
        varchar actor_label
        varchar action
        varchar entity_type
        uuid entity_id "polymorphic, not an FK"
        uuid scan_id FK
        json details
        varchar request_id
        timestamptz created_at
    }
```

---

## 6. Design Decisions and Trade-offs

1. **UUIDs instead of sequential integers.** IDs are generated by the
   application, do not reveal record counts, and are safer to expose in URLs.
2. **String values + checks instead of PostgreSQL enums.** Adding a value means
   replacing a check constraint, which is a normal migration. Altering an enum
   in older PostgreSQL versions is more restrictive.
3. **JSON only where structure is variable and always read whole.** Remediation
   steps/references and audit details are JSON. Filterable fields remain
   first-class columns.
4. **Reports are snapshots.** A historical report must not change when a finding
   is later edited. Uniqueness on `(scan_id, format, version)` enforces
   versioning.
5. **One running scan.** A partial unique index makes the rule true even if two
   processes race. The service check exists for a friendly error, not as the
   only protection.
6. **No user registration/login endpoints.** Authentication is outside the
   approved Lean MVP scope. The table exists so future auth and ownership do not
   require a redesign.
7. **No raw secrets in the database.** Evidence is redacted before storage.
   Audit details contain identifiers and status changes, not request bodies.

---

## 7. Alembic Workflow

### 7.1 Current state

The initial migration is:

```text
backend/alembic/versions/2f6893bcadd8_initial_schema.py
```

It was applied with:

```powershell
cd D:\projects\VULNDETECTOR\backend
.\.venv\Scripts\alembic.exe upgrade head
```

Verify the current revision:

```powershell
.\.venv\Scripts\alembic.exe current
```

Inspect the live schema:

```powershell
$env:PYTHONPATH='.'
.\.venv\Scripts\python.exe scripts\inspect_schema.py
```

Expected: 10 application tables plus `alembic_version`, 15 foreign keys, and the
partial unique index `uq_scan_sessions_single_running`.

### 7.2 Create a future migration

1. Edit or add a model in `backend/app/models/`.
2. Import it in `backend/app/models/__init__.py` so metadata sees it.
3. Autogenerate a revision:

   ```powershell
   .\.venv\Scripts\alembic.exe revision --autogenerate -m "add scan tags"
   ```

4. **Read the generated file.** Autogenerate is a draft, not a guarantee. Check
   data migrations, renames, default values, and index changes.
5. Apply it:

   ```powershell
   .\.venv\Scripts\alembic.exe upgrade head
   ```

6. Verify with `alembic current` and `inspect_schema.py`.

### 7.3 Roll back

One revision:

```powershell
.\.venv\Scripts\alembic.exe downgrade -1
```

To an empty schema:

```powershell
.\.venv\Scripts\alembic.exe downgrade base
```

Do this only on a development branch or after a backup. Downgrading the initial
migration drops all ten application tables.

### 7.4 Why migrations beat manual changes

- **Reviewable:** the change is a file in Git.
- **Repeatable:** every environment reaches the same state.
- **Ordered:** dependencies are applied correctly.
- **Recoverable:** downgrade is possible.
- **Auditable:** `alembic_version` records exactly what ran.
- **Safer:** no undocumented drift between a developer's database and Neon.

### 7.5 Neon branches

Use a Neon **development** branch for experiments. A branch is copy-on-write and
isolated, so `downgrade base` or a destructive migration cannot hurt production.
Point `DATABASE_URL` at the development branch, restart the API, and run
Alembic. Never run exploratory migrations against the production branch.

### 7.6 Migration safety checklist

- Use the **direct** Neon endpoint.
- Take a backup or use a branch before destructive changes.
- Add columns as nullable or with a safe server default.
- Backfill data in a separate, explicit step.
- Add constraints after the data is valid.
- Test `upgrade` and `downgrade` on the development branch.
- Never edit an applied revision; create a new one.

---

## 8. File Map

Every backend file added or changed for Step 4:

| File | Responsibility |
|---|---|
| `app/core/config.py` | Typed settings from `backend/.env`, CORS origins, target allowlist, target limit, executor mode |
| `app/core/exceptions.py` | `AppError` hierarchy with safe status codes and error codes |
| `app/db/base.py` | Declarative `Base` and constraint/index naming convention |
| `app/db/engine.py` | Async engine, TLS context, pool settings, `get_session` dependency, shutdown cleanup |
| `app/db/url.py` | Converts a Neon URL to `postgresql+asyncpg://` and strips libpq-only query options |
| `app/models/mixins.py` | UUID primary key and timezone-aware timestamp mixins |
| `app/models/user.py` | `users` table and ownership relationships |
| `app/models/scan.py` | `scan_sessions`, lifecycle checks, single-running partial index |
| `app/models/target.py` | `scan_targets` and authorized scope |
| `app/models/endpoint.py` | `discovered_endpoints` and URL de-duplication hash |
| `app/models/finding.py` | `findings`, severity/status/OWASP checks, relationships |
| `app/models/evidence.py` | Redacted evidence rows and SHA-256 validation |
| `app/models/remediation.py` | One-to-one remediation guidance and workflow state |
| `app/models/verification.py` | Verification request history |
| `app/models/report.py` | Versioned HTML/JSON report snapshots |
| `app/models/audit_log.py` | Append-only audit trail |
| `app/models/__init__.py` | Imports every model so Alembic sees the full metadata |
| `app/schemas/common.py` | `ORMModel`, generic `Page`, error envelope schemas |
| `app/schemas/scan.py` | Scan/target request and response schemas |
| `app/schemas/finding.py` | Finding, evidence, remediation, verification schemas |
| `app/schemas/report.py` | Report schemas and computed download URL |
| `app/services/targets.py` | URL canonicalization and exact allowlist enforcement |
| `app/services/audit.py` | Adds audit rows inside the caller's transaction |
| `app/services/scans.py` | Create, list, detail, status, start, cancel, complete, fail |
| `app/services/findings.py` | List/detail, remediation transitions, verification requests |
| `app/services/reports.py` | Snapshot building, JSON/HTML rendering, versions, downloads |
| `app/services/scan_executor.py` | Labeled placeholder; no network, no findings |
| `app/api/deps.py` | Shared session, limit, and offset dependencies |
| `app/api/routes/health.py` | API and database health checks |
| `app/api/routes/scans.py` | Scan lifecycle, findings list, scan report endpoints |
| `app/api/routes/findings.py` | Finding detail, remediation, verification endpoints |
| `app/api/routes/reports.py` | Report metadata and download endpoints |
| `app/api/router.py` | Mounts all route modules |
| `app/main.py` | App factory settings, CORS, exception handlers, lifespan, routing |
| `alembic/env.py` | Loads settings and models, enables TLS, `compare_type=True` |
| `alembic/versions/2f6893bcadd8_initial_schema.py` | Creates all ten tables, keys, checks, and indexes |
| `alembic.ini` | Alembic script location and logging configuration |
| `pytest.ini` | Async test mode and shared event-loop scope |
| `tests/test_api_integration.py` | Live Neon integration suite |
| `scripts/inspect_schema.py` | Prints tables, index counts, and the partial index definition |
| `scripts/e2e_smoke.py` | Exercises the HTTP lifecycle and cleans up after itself |
| `.env.example` | Safe template including allowlist and executor settings |

### Commands used in this step

| Command | Purpose |
|---|---|
| `alembic current` | Show the revision applied to Neon |
| `alembic revision --autogenerate -m "..."` | Draft a migration from model changes |
| `alembic upgrade head` | Apply all pending migrations |
| `alembic downgrade -1` | Undo the last revision |
| `alembic downgrade base` | Drop everything the migrations created (development only) |
| `pytest -v` | Run unit and integration tests |
| `python scripts\inspect_schema.py` | Summarize the live schema |
| `python scripts\e2e_smoke.py` | Exercise the running API end to end |
