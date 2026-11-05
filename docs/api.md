# VulnSight — Backend API and Scan Lifecycle

| Field | Value |
|---|---|
| Base URL | `http://127.0.0.1:8000/api/v1` |
| Interactive docs | `http://127.0.0.1:8000/docs` |
| Database docs | [`database.md`](./database.md) |
| Scanner status | Not implemented; a labeled placeholder closes the lifecycle |

The Lean MVP has **no authentication endpoints** because authentication is not
in the approved scope. Do not expose this API beyond the local machine.

---

## 1. Endpoint Summary

| Method | Path | Success | Purpose |
|---|---|---|---|
| `GET` | `/health` | `200` | API process health |
| `GET` | `/health/db` | `200` / `503` | `SELECT 1` against Neon plus latency |
| `POST` | `/scans` | `201` | Create a pending scan with authorized targets |
| `GET` | `/scans` | `200` | Scan history, newest first |
| `GET` | `/scans/{scan_id}` | `200` | Scan detail with targets |
| `GET` | `/scans/{scan_id}/status` | `200` | Lightweight status polling |
| `POST` | `/scans/{scan_id}/start` | `202` | Transition `pending → running` |
| `POST` | `/scans/{scan_id}/cancel` | `200` | Cancel a non-terminal scan |
| `POST` | `/recon/validate-target` | `200` | Target validation, DNS resolution & SSRF safety check |
| `GET` | `/scans/{scan_id}/recon` | `200` | Reconnaissance summary, technologies & headers |
| `GET` | `/scans/{scan_id}/endpoints` | `200` | List discovered endpoints in PostgreSQL |
| `GET` | `/scans/{scan_id}/findings` | `200` | List and filter findings |
| `POST` | `/scans/{scan_id}/reports` | `201` | Generate an HTML or JSON snapshot |
| `GET` | `/scans/{scan_id}/reports` | `200` | Report history for a scan |
| `GET` | `/findings/{finding_id}` | `200` | Finding with endpoint, evidence, remediation, verification |
| `PATCH` | `/findings/{finding_id}/remediation` | `200` | Update remediation status/notes |
| `POST` | `/findings/{finding_id}/verify` | `202` | Queue a fix verification request |
| `GET` | `/reports/{report_id}` | `200` | Report metadata |
| `GET` | `/reports/{report_id}/download` | `200` | Download stored report content |

Pagination uses `limit` (1–100, default 20) and `offset` (default 0). List
responses have the shape `{items, total, limit, offset}`.

---

## 2. Scan Lifecycle

```text
                 POST /scans
                     |
                     v
                 ┌─────────┐
                 │ pending │
                 └────┬────┘
        start         │         cancel
        ──────────────┼──────────────────────┐
                      v                      v
                 ┌─────────┐           ┌───────────┐
                 │ running │           │ cancelled │
                 └────┬────┘           └───────────┘
        ┌─────────────┼─────────────┐
        v             v             v
  ┌───────────┐ ┌──────────┐ ┌───────────┐
  │ completed │ │  failed  │ │ cancelled │
  └───────────┘ └──────────┘ └───────────┘
```

Allowed transitions:

| From | To | Trigger |
|---|---|---|
| `pending` | `running` | `POST /scans/{id}/start` |
| `running` | `completed` | Executor finishes |
| `running` | `failed` | Executor error |
| `pending` | `cancelled` | `POST /scans/{id}/cancel` |
| `running` | `cancelled` | `POST /scans/{id}/cancel` |

Any other start/cancel request returns `409`. Terminal states are never
restarted in place; create a new scan.

### How status is stored and retrieved

- The authoritative state is `scan_sessions.status` in PostgreSQL.
- `status_message`, `started_at`, and `finished_at` explain the state.
- Every transition also writes an `audit_logs` row.
- `GET /scans/{id}/status` reads the row directly and returns counts, so the
  frontend can poll it cheaply.
- The partial unique index `uq_scan_sessions_single_running` prevents two rows
  from being `running` at the same time, even under concurrent requests.

### Placeholder executor

`SCAN_EXECUTOR_MODE=placeholder` starts a background task that waits briefly and
marks the scan `completed`. It performs **no network requests** and creates **no
findings**. Real scanners will replace this task later. The completion message
and generated reports state this explicitly.

---

## 3. Error Format

Application errors use one envelope:

```json
{
  "error": {
    "code": "conflict",
    "message": "Another scan is already running.",
    "details": null
  }
}
```

| HTTP | `code` | Typical cause |
|---|---|---|
| `400` | `bad_request` | Host not allowlisted, duplicate target, bad scheme, too many targets |
| `404` | `not_found` | Unknown scan, finding, or report |
| `409` | `conflict` | Invalid state transition, active verification already pending |
| `409` | `data_conflict` | Foreign-key/check/unique constraint failure |
| `422` | `validation_error` | Missing field, blank URL, wrong type, invalid UUID, invalid enum |
| `503` | `database_error` | Database operation failed |
| `503` | `database_not_configured` | `DATABASE_URL` missing |

The database health endpoint uses its own documented shape when unavailable:

```json
{
  "status": "error",
  "database": "unavailable",
  "detail": "Database connection failed. Check the API log and the Neon connection string."
}
```

Server logs contain the exception type for diagnosis. Responses never contain
the connection string, password, or raw SQL.

---

## 4. Walkthrough with PowerShell

Start the API first:

```powershell
cd D:\projects\VULNDETECTOR\backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Use a second terminal for the requests below.

### 4.1 Health

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
```

```json
{
  "status": "ok",
  "service": "VulnSight API",
  "version": "0.1.0",
  "environment": "development"
}
```

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health/db
```

```json
{
  "status": "ok",
  "database": "connected",
  "latency_ms": 41.27
}
```

### 4.2 Create a scan

```powershell
$body = @{
  name = "Local lab baseline"
  profile = "lean_mvp"
  targets = @(
    @{ url = "http://127.0.0.1:8000/"; authorization_reference = "LAB-001" }
    @{ url = "http://localhost:8000/" }
  )
} | ConvertTo-Json -Depth 5

$scan = Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/api/v1/scans `
  -ContentType "application/json" `
  -Body $body

$scan | ConvertTo-Json -Depth 6
```

Example response (`201 Created`):

```json
{
  "id": "4f1e6d1e-2c38-4b0d-9d4b-0d3f9b2a7c11",
  "name": "Local lab baseline",
  "status": "pending",
  "profile": "lean_mvp",
  "status_message": "Scan created and waiting to start.",
  "created_by_id": null,
  "started_at": null,
  "finished_at": null,
  "created_at": "2026-11-05T15:40:12.118Z",
  "updated_at": "2026-11-05T15:40:12.118Z",
  "target_count": 2,
  "finding_count": 0,
  "targets": [
    {
      "id": "9a2c9f0e-6b4a-4f5e-8b70-4c8e9d1a2b33",
      "url": "http://127.0.0.1:8000/",
      "scheme": "http",
      "hostname": "127.0.0.1",
      "port": null,
      "path": "/",
      "is_authorized": true,
      "authorization_reference": "LAB-001",
      "created_at": "2026-11-05T15:40:12.118Z"
    },
    {
      "id": "1b7d5e44-8c2a-42f1-9e11-3a6c0b7d9e55",
      "url": "http://localhost:8000/",
      "scheme": "http",
      "hostname": "localhost",
      "port": null,
      "path": "/",
      "is_authorized": true,
      "authorization_reference": null,
      "created_at": "2026-11-05T15:40:12.118Z"
    }
  ]
}
```

`id`, `created_at`, and other generated values differ per run. The target path
is canonicalized: `http://127.0.0.1:8000` becomes `http://127.0.0.1:8000/`.

### 4.3 Start the scan

```powershell
$scanId = $scan.id

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/scans/$scanId/start"
```

Example response (`202 Accepted`):

```json
{
  "id": "4f1e6d1e-2c38-4b0d-9d4b-0d3f9b2a7c11",
  "status": "running",
  "status_message": "Scan started. The placeholder executor will close this run; scanner modules are not implemented yet.",
  "started_at": "2026-11-05T15:40:19.002Z",
  "finished_at": null,
  "updated_at": "2026-11-05T15:40:19.002Z",
  "target_count": 2,
  "finding_count": 0
}
```

The placeholder closes the run almost immediately. Poll status:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8000/api/v1/scans/$scanId/status"
```

```json
{
  "id": "4f1e6d1e-2c38-4b0d-9d4b-0d3f9b2a7c11",
  "status": "completed",
  "status_message": "Placeholder executor finished. Scanner modules are not implemented yet, so no vulnerability checks or network requests were performed.",
  "started_at": "2026-11-05T15:40:19.002Z",
  "finished_at": "2026-11-05T15:40:19.514Z",
  "updated_at": "2026-11-05T15:40:19.514Z",
  "target_count": 2,
  "finding_count": 0
}
```

Starting it again returns `409 conflict`.

### 4.4 Scan history and detail

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/scans?limit=10&offset=0"

Invoke-RestMethod "http://127.0.0.1:8000/api/v1/scans?status=completed&limit=10"

Invoke-RestMethod "http://127.0.0.1:8000/api/v1/scans/$scanId"
```

List response:

```json
{
  "items": [
    {
      "id": "4f1e6d1e-2c38-4b0d-9d4b-0d3f9b2a7c11",
      "name": "Local lab baseline",
      "status": "completed",
      "profile": "lean_mvp",
      "status_message": "Placeholder executor finished. ...",
      "created_by_id": null,
      "started_at": "2026-11-05T15:40:19.002Z",
      "finished_at": "2026-11-05T15:40:19.514Z",
      "created_at": "2026-11-05T15:40:12.118Z",
      "updated_at": "2026-11-05T15:40:19.514Z",
      "target_count": 2,
      "finding_count": 0
    }
  ],
  "total": 1,
  "limit": 10,
  "offset": 0
}
```

### 4.5 Findings

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/scans/$scanId/findings"

Invoke-RestMethod "http://127.0.0.1:8000/api/v1/scans/$scanId/findings?severity=high&status=open&owasp_category=A05"
```

Example response:

```json
{
  "items": [],
  "total": 0,
  "limit": 20,
  "offset": 0
}
```

The placeholder produces no findings. The integration tests insert one finding
directly through SQLAlchemy to exercise the relationship and workflow endpoints.
A stored finding looks like:

```json
{
  "id": "b073f290-9a2c-42ce-b0a3-57acfa93d283",
  "scan_id": "4f1e6d1e-2c38-4b0d-9d4b-0d3f9b2a7c11",
  "endpoint_id": "c2b9e8a1-6f4d-4c8e-a3b2-1d0e9f8a7b66",
  "check_id": "A05-SECURITY-HEADERS",
  "owasp_category": "A05",
  "title": "Missing Content-Security-Policy header",
  "severity": "high",
  "confidence": "firm",
  "status": "open",
  "created_at": "2026-11-05T15:41:02.001Z",
  "updated_at": "2026-11-05T15:41:02.001Z",
  "description": "The response did not include a CSP header.",
  "fingerprint": "9f2c...",
  "endpoint": {
    "id": "c2b9e8a1-6f4d-4c8e-a3b2-1d0e9f8a7b66",
    "method": "GET",
    "url": "http://127.0.0.1:8000/login",
    "path": "/login",
    "status_code": 200,
    "content_type": "text/html"
  },
  "evidence": [
    {
      "id": "5e1f...",
      "kind": "text",
      "label": "Response header observation",
      "content": "Response headers did not contain Content-Security-Policy.",
      "content_sha256": "0d5e...",
      "is_redacted": true,
      "created_at": "2026-11-05T15:41:02.001Z"
    }
  ],
  "remediation": {
    "id": "7a2d...",
    "finding_id": "b073f290-9a2c-42ce-b0a3-57acfa93d283",
    "summary": "Add a restrictive Content-Security-Policy header.",
    "steps": ["Define a policy", "Send it on every response"],
    "references": ["https://owasp.org/www-project-secure-headers/"],
    "status": "not_started",
    "notes": null,
    "updated_by_id": null,
    "created_at": "2026-11-05T15:41:02.001Z",
    "updated_at": "2026-11-05T15:41:02.001Z"
  },
  "verification_runs": []
}
```

### 4.6 Update remediation

```powershell
$findingId = "<finding-id>"

$patch = @{
  status = "in_progress"
  notes = "CSP draft prepared; waiting for deployment."
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Patch `
  -Uri "http://127.0.0.1:8000/api/v1/findings/$findingId/remediation" `
  -ContentType "application/json" `
  -Body $patch
```

Allowed values: `not_started`, `in_progress`, `done`, `accepted_risk`.
The finding status follows automatically (`open`, `in_progress`, `remediated`,
`accepted_risk`). Invalid values return `422`.

### 4.7 Request verification

```powershell
$verify = @{ note = "Please re-test after deployment." } | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/findings/$findingId/verify" `
  -ContentType "application/json" `
  -Body $verify
```

Response (`202 Accepted`):

```json
{
  "id": "e0c4f1a8-3d5b-4a7e-9f22-6b8d1c0a4e77",
  "finding_id": "b073f290-9a2c-42ce-b0a3-57acfa93d283",
  "status": "pending",
  "started_at": null,
  "finished_at": null,
  "result_summary": null,
  "details": { "request_note": "Please re-test after deployment." },
  "created_at": "2026-11-05T15:42:10.220Z"
}
```

A second active request returns `409`. The verification engine is not
implemented; the row is a durable queue entry and history record.

### 4.8 Generate and download reports

```powershell
$jsonReport = Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/scans/$scanId/reports" `
  -ContentType "application/json" `
  -Body (@{ format = "json" } | ConvertTo-Json)

$htmlReport = Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/scans/$scanId/reports" `
  -ContentType "application/json" `
  -Body (@{ format = "html" } | ConvertTo-Json)

Invoke-RestMethod "http://127.0.0.1:8000/api/v1/scans/$scanId/reports"

Invoke-WebRequest `
  -Uri "http://127.0.0.1:8000/api/v1/reports/$($jsonReport.id)/download" `
  -OutFile ".\scan-report.json"

Invoke-WebRequest `
  -Uri "http://127.0.0.1:8000/api/v1/reports/$($htmlReport.id)/download" `
  -OutFile ".\scan-report.html"
```

Report metadata:

```json
{
  "id": "a4c2...",
  "scan_id": "4f1e6d1e-2c38-4b0d-9d4b-0d3f9b2a7c11",
  "format": "json",
  "status": "generated",
  "version": 1,
  "file_name": "vulnsight-scan-4f1e6d1e-...-json-v1.json",
  "content_type": "application/json",
  "size_bytes": 1496,
  "content_sha256": "8c1d...",
  "created_at": "2026-11-05T15:43:01.001Z",
  "generated_at": "2026-11-05T15:43:01.001Z",
  "download_url": "/api/v1/reports/a4c2.../download"
}
```

Generating the same format again creates version 2. Historical versions are
never overwritten.

---

## 5. Request Validation Rules

### Scan creation

| Field | Rule |
|---|---|
| `name` | Optional, max 200; trimmed; blank becomes a generated name |
| `profile` | Must be `lean_mvp` |
| `targets` | At least 1, at most 50 in the schema; service limit `SCAN_MAX_TARGETS` (10) |
| `targets[].url` | 1–2048 chars, non-blank, no control characters |
| `targets[].authorization_reference` | Optional, max 255 |

Each target URL must:

- use `http` or `https`;
- include a hostname;
- omit embedded credentials, fragments, and query strings;
- use a port in 1–65535 if present;
- have a hostname that exactly matches `SCAN_ALLOWED_HOSTS`
  (default `127.0.0.1,localhost,::1`);
- be unique after canonicalization within the scan.

### Query parameters

| Parameter | Rule |
|---|---|
| `limit` | Integer 1–100 |
| `offset` | Integer ≥ 0 |
| `status` (scans) | One of the scan statuses |
| `severity` (findings) | `critical`/`high`/`medium`/`low`/`info` |
| `status` (findings) | One of the finding statuses |
| `owasp_category` | `A01`–`A10` |

### Finding and report IDs

Must be valid UUIDs. A malformed UUID returns `422`; a well-formed unknown UUID
returns `404`.

---

## 6. Failure Behavior

| Scenario | Behaviour |
|---|---|
| Invalid input | Rejected before any database write |
| Unknown record | `404`, no partial state |
| Database connection failure | `503`; transaction is not committed |
| Constraint violation | `409`; service rolls back |
| Duplicate target URL | `400` with the canonical URL in `details` |
| Second concurrent running scan | `409` from the service; partial index as final guard |
| Executor failure | Scan can be marked `failed`; status message records the reason |
| Cancelled while running | Row becomes `cancelled`; completion update is skipped because status is no longer `running` |
| Partial results | Findings already committed remain visible; the scan status explains the outcome |
| Report generation conflict | `409`; transaction rolls back and can be retried |
| Database not configured | `503 database_not_configured` |

---

## 7. Testing

### 7.1 Automated tests

```powershell
cd D:\projects\VULNDETECTOR\backend
$env:PYTHONPATH='.'
.\.venv\Scripts\pytest.exe -v
```

The suite covers:

- URL normalization;
- API and database health;
- expected tables, foreign keys, and the partial unique index;
- scan creation, retrieval, status, history, and filtering;
- the placeholder lifecycle (`pending → running → completed`);
- cancellation;
- allowlist, duplicate, scheme, credential, fragment, query, blank, and
  target-count validation;
- unknown and malformed IDs;
- finding retrieval and nested relationships;
- remediation transitions;
- verification request history;
- report versions, snapshots, and downloads;
- foreign-key, check-constraint, and single-running-scan constraints.

Integration tests run against the real Neon database and clean up their scans.
They need `DATABASE_URL` and `alembic upgrade head`.

### 7.2 End-to-end smoke script

With the API running:

```powershell
cd D:\projects\VULNDETECTOR\backend
$env:PYTHONPATH='.'
.\.venv\Scripts\python.exe scripts\e2e_smoke.py
```

It creates a scan, starts it, waits for completion, generates both report
formats, checks validation errors, and deletes the scan it created.

Expected final line:

```text
All end-to-end checks passed.
```

### 7.3 Postman or curl

Import or create requests against `http://127.0.0.1:8000`:

1. `GET /api/v1/health`
2. `GET /api/v1/health/db`
3. `POST /api/v1/scans` with a JSON body
4. `POST /api/v1/scans/{id}/start`
5. `GET /api/v1/scans/{id}/status`
6. `GET /api/v1/scans/{id}/findings`
7. `POST /api/v1/scans/{id}/reports`
8. `GET /api/v1/reports/{id}/download`

`/docs` provides a request form, response schema, and status codes for every
endpoint without installing another tool.

### 7.4 Migration rollback check

Only on a development Neon branch or after a backup:

```powershell
cd D:\projects\VULNDETECTOR\backend

.\.venv\Scripts\alembic.exe downgrade base
.\.venv\Scripts\alembic.exe current
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\alembic.exe current

$env:PYTHONPATH='.'
.\.venv\Scripts\python.exe scripts\inspect_schema.py
```

Expected after the final upgrade: revision `2f6893bcadd8` and all ten tables
restored. `downgrade base` drops application data.

---

## 8. Scope Boundaries

Implemented:

- ten normalized tables and versioned migration;
- async engine, session handling, pooling, TLS, and health checks;
- scan creation, history, detail, status, start, and cancel;
- finding list/detail with evidence, remediation, and verification;
- remediation updates and verification requests;
- immutable HTML/JSON report generation and download;
- validation, safe error envelopes, audit entries, and integration tests.

Intentionally **not** implemented:

- user registration or login;
- crawler, HTTP probing, or any real vulnerability check;
- SSRF protection for arbitrary internet targets (hosts are restricted to an
  explicit allowlist instead);
- verification execution engine;
- frontend Step 4 pages;
- rate limiting, multi-user access control, or deployment hardening.

The placeholder executor exists only to prove that the database, API, lifecycle,
and reporting pipeline work end to end. Do not describe it as a scanner.
