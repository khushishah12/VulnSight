# VulnSight Finding Management, Risk Scoring & Remediation Center

## 1. Finding Management Architecture

VulnSight provides a standardized, normalized finding data structure that encapsulates vulnerability attributes, technical evidence, detection mechanisms, and remediation lifecycles.

```
┌───────────────────────────────────────────────────────────────────────────┐
│                           Standardized Finding                            │
├───────────────────────────────────────────────────────────────────────────┤
│ • Finding ID: UUID                                                        │
│ • Vulnerability Name: Title of observed flaw                              │
│ • OWASP Category: A01 – A10 (OWASP Top 10:2025)                           │
│ • Affected URL / Endpoint: Target URI + HTTP verb                         │
│ • Severity: critical | high | medium | low | info                         │
│ • Confidence: certain | firm | tentative                                  │
│ • Risk Score: 0.1 – 10.0 (Transparent Matrix Score)                      │
│ • Description: Detailed technical narrative                               │
│ • Detection Method: active_path_probe | passive_header_analysis | etc.     │
│ • Detection Timestamp: ISO 8601 UTC                                       │
│ • Remediation Status: not_started | in_progress | done | accepted_risk    │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            ▼                                                   ▼
┌──────────────────────────────────────┐     ┌──────────────────────────────┐
│       Technical Evidence             │     │      Remediation Center      │
│  • Redacted Content (No Secrets)     │     │  • Meaning & Root Cause      │
│  • SHA-256 Chain-of-Custody Hash     │     │  • Business Impact           │
│  • Kind: request | response | log    │     │  • Multi-Framework Examples  │
└──────────────────────────────────────┘     │  • Fix Verification Criteria │
                                             └──────────────────────────────┘
```

### 1.1 Sensitive Evidence Redaction Engine (`app.core.redaction`)
To ensure that findings do not store sensitive user credentials or infrastructure secrets:
- Technical evidence content is automatically processed by `redact_sensitive_text()`.
- Scrubbed elements include:
  - Authorization headers: `Authorization: [REDACTED_AUTH_TOKEN]`
  - Passwords in query strings or JSON: `"password": "[REDACTED]"`
  - JWT Tokens: `[REDACTED_JWT_TOKEN]`
  - Session Cookies: `session=[REDACTED_SESSION_COOKIE]`
  - Cloud / API Keys: `[REDACTED_AWS_KEY]`, `[REDACTED_API_KEY]`
- Evidence records are tagged with `is_redacted=True` and cryptographically hashed with SHA-256.

---

## 2. Transparent Risk Assessment Matrix (TRSM v1)

VulnSight implements a transparent, deterministic risk assessment heuristic.

> [!IMPORTANT]
> **CVSS Disclaimer**: The VulnSight Risk Score is an internal automated heuristic prioritization metric based on technical impact, exposure likelihood, and scanner confidence. It is **NOT** an official FIRST CVSS v3.1 or CVSS v4.0 vector or score.

### 2.1 Component Definitions

1. **Severity (Technical Impact $I \in [1.0, 10.0]$)**:
   Measures potential harm to Confidentiality, Integrity, and Availability:
   - `critical` $\rightarrow 10.0$: Total compromise, unauthorized remote code execution, database exfiltration.
   - `high` $\rightarrow 8.5$: Unauthenticated administrative access, reflected XSS, exposed credentials.
   - `medium` $\rightarrow 5.5$: Insecure cookie attributes, missing CSRF tokens, permissive CORS.
   - `low` $\rightarrow 3.0$: Missing defensive security headers, version banners, missing SRI hashes.
   - `info` $\rightarrow 1.0$: Missing distributed tracing correlation headers.

2. **Likelihood ($L \in [0.1, 1.0]$)**:
   Combines Attack Vector Exposure ($V$) and Exploit Complexity ($E$):
   $$L = V \times E$$
   - High Likelihood ($0.75 - 0.85$): Publicly reachable, trivial automation (e.g. unauthenticated GET `/admin`).
   - Medium Likelihood ($0.55 - 0.65$): Requires victim interaction (e.g. CSRF form submission, phishing link).
   - Low Likelihood ($0.20 - 0.45$): Requires CDN compromise or secondary reconnaissance intelligence.

3. **Confidence ($C \in [0.80, 1.0]$)**:
   Weights evidentiary certainty:
   - `certain` $\rightarrow 1.0$: Cryptographic proof, exact signature match (e.g., `.git/config` header, password submitted over HTTP).
   - `firm` $\rightarrow 0.95$: Verbatim unencoded canary tag reflection, explicit database syntax error string.
   - `tentative` $\rightarrow 0.80$: Path keyword match or heuristic status code indicator.

4. **Scoring Formula**:
   $$\text{Raw Risk} = I \times (0.35 + 0.65 \times L) \times C$$
   $$\text{Risk Score} = \min(10.0, \max(0.1, \text{round}(\text{Raw Risk}, 1)))$$

5. **Qualitative Rating Scale**:
   - $9.0 - 10.0$: **Critical**
   - $7.0 - 8.9$: **High**
   - $4.0 - 6.9$: **Medium**
   - $1.0 - 3.9$: **Low**
   - $0.1 - 0.9$: **Informational**

---

## 3. Remediation Center Knowledgebase

The Remediation Center provides multi-framework remediation guidance without making unverified assumptions about the target's underlying technology stack.

### 3.1 Multi-Framework Stack Coverage
For every vulnerability, code snippets and secure implementations are provided across:
- **Node.js / Express.js**
- **Python / FastAPI**
- **Python / Django**
- **Java / Spring Boot**
- **SQL (Parameterized Queries & ORMs)**

### 3.2 Vulnerability Guide Structure
Each guide exposes:
1. **Meaning**: Conceptual explanation of the weakness.
2. **Why It Occurs**: Development and operational pitfalls leading to the issue.
3. **Internal Mechanics**: How browsers, web servers, or databases process the flaw.
4. **Safe Conceptual Exploitation Scenario**: Non-destructive attacker methodology.
5. **Business Impact**: Regulatory fines, customer trust loss, financial fraud.
6. **Root Cause**: Architectural or implementation source.
7. **Step-by-Step Remediation**: Actionable engineering checklist.
8. **Side-by-Side Code Examples**: Vulnerable vs. Secure implementations.
9. **Framework Guidance**: Middleware tips and server configuration snippets.
10. **Fix Verification Criteria**: Concrete parameters for re-testing.

---

## 4. Fix Verification Instructions

For each finding, the Remediation Center specifies four mandatory verification properties:

| Property | Description |
| :--- | :--- |
| **What Should Change** | Expected application state change after applying the patch. |
| **Check to Rerun** | The exact safe, non-destructive probe to re-execute. |
| **Expected Evidence** | Concrete positive indicators demonstrating remediation success (e.g., HTTP 401 challenge, encoded HTML entities, present security headers). |
| **Inconclusive Conditions** | External factors that prevent definitive verification (e.g., target server offline, WAF network block, CDN caching). |

### 4.1 Verification Lifecycle & Execution
1. Operator requests verification via `POST /api/v1/findings/{finding_id}/verify`.
2. A durable `VerificationRun` record is created with status `pending`.
3. If executed live (`execute_now=True` or via verification runner):
   - `SafeReconClient` executes the safe re-probe.
   - If fixed: status transitions to `passed`, finding status becomes `verified`, remediation status becomes `done`.
   - If flaw remains: status transitions to `failed`, finding status remains `open`.
   - If unreachable: status transitions to `error` or `inconclusive`.
   - An immutable audit log entry is recorded.

---

## 5. API Endpoints Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/v1/scans/{scan_id}/findings` | `GET` | List findings for scan with risk score, affected URL, detection method, and status. |
| `/api/v1/findings/{finding_id}` | `GET` | Retrieve full finding details, technical evidence, risk assessment matrix, and remediation guide. |
| `/api/v1/findings/{finding_id}/remediation-guide` | `GET` | Retrieve multi-framework Remediation Center guide for the finding. |
| `/api/v1/remediation-center` | `GET` | Browse all available vulnerability guides in the knowledgebase. |
| `/api/v1/remediation-center/{check_id}` | `GET` | Retrieve specific guide by check ID. |
| `/api/v1/findings/{finding_id}/remediation` | `PATCH` | Update remediation workflow status (`not_started`, `in_progress`, `done`, `accepted_risk`) and notes. |
| `/api/v1/findings/{finding_id}/verify` | `POST` | Queue or execute safe fix verification request. |
