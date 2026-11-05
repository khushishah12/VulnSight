# VulnSight — Lean MVP Software Requirements Specification (SRS)

| Field | Value |
|---|---|
| Project | VulnSight — Web Application Vulnerability Assessment and Remediation Platform |
| Document | Software Requirements Specification — Lean MVP |
| Version | 1.1 — revised for a small, achievable project |
| Supersedes | SRS v1.0 (archived at `docs/archive/SRS-v1.0-full.md`) |
| Status | Draft for approval. No architecture or code has started. |
| Date | 05 November 2026 |
| Goal | Make the project small enough for one developer to finish and demonstrate confidently |

> **What “easy” means here.** Easy means a smaller build, not a fake or unsafe product. VulnSight Lite is a local-first, single-user scanner that performs a small set of safe checks, maps findings to OWASP Top 10:2025, and produces a clear report. It does not try to cover everything.

---

## 1. What Changed From v1.0

The previous version was too broad for a first release. This version deliberately cuts the MVP down.

| Area | v1.0 | v1.1 Lean MVP |
|---|---|---|
| Users | Admin, Analyst, Viewer | One local admin |
| Deployment | Self-hosted, potentially shared | Local-first, one machine |
| Authentication | Accounts, roles, password reset | One admin password, no registration |
| Target verification | DNS TXT or HTML file | Operator-managed lab allowlist |
| Scanning | Passive + active + authenticated crawl | Unauthenticated only |
| Active checks | Reflected XSS + error-based SQLi | Reflected XSS only |
| Checks | 15+ | 8 focused checks |
| Crawl limit | 100 pages | 20 pages, depth 2 |
| Reports | HTML, PDF, JSON | HTML + JSON; browser print-to-PDF |
| Findings | Assignment, notes, workflow | Simple false-positive toggle |
| Audit | Formal audit log | Basic activity log |
| Source/config analysis | V2 | V2 |
| AI | Advanced | Advanced |
| Multi-tenant | V2 | Advanced / not planned |

**Result:** the MVP is still a real vulnerability assessment tool, but it is small enough to build, test, explain, and demo.

---

## 2. The Exact Problem VulnSight Solves

A developer or student wants a quick, safe answer to:

1. What obvious security weaknesses are visible on this web application?
2. Which OWASP Top 10:2025 category does each one relate to?
3. How serious is it, and how confident are we?
4. What should be fixed first, and how?

Existing scanners can be expensive, noisy, or hard to interpret. Manual testing takes expertise. VulnSight Lite provides a small, understandable assessment with evidence and remediation, while clearly stating what it did **not** test.

### What VulnSight Lite is not

- Not a replacement for a professional penetration test.
- Not a full OWASP assessment.
- Not a source-code or cloud-security scanner.
- Not an exploitation tool.
- Not a public multi-user SaaS.
- Not a guarantee that an application is secure.

---

## 3. Who Uses It

| User | Need |
|---|---|
| **Solo developer / student** | A small, understandable security project and a useful report |
| **Instructor / evaluator** | A clear demonstration of scanning, OWASP mapping, and remediation |
| **Small team** | A quick external check of an authorized lab or staging site |
| **Beginner in cybersecurity** | A tool that explains findings in plain language |

### MVP access model

- One local **Admin** account.
- No registration, roles, invitations, password reset, or multi-tenant support.
- The app is intended to run on the operator’s own machine and scan only allowlisted lab/authorized targets.

---

## 4. MVP Scope and User Journey

1. Start VulnSight locally and sign in as the single admin.
2. Add an authorized target from the configured allowlist.
3. Confirm authorization.
4. Run one **Safe Scan**.
5. VulnSight crawls up to 20 same-origin pages and runs 8 checks.
6. Review findings, evidence, confidence, OWASP mapping, and remediation.
7. Mark a finding as a false positive.
8. Export an HTML or JSON report; print the HTML to PDF if needed.
9. View the coverage matrix showing what was not tested.

---

## 5. OWASP Top 10:2025 Coverage

All ten categories are **mapped and explained**. Only a small subset is dynamically assessed.

| Category | MVP coverage | Reality |
|---|---|---|
| **A01 Broken Access Control** | Very limited | CORS wildcard check only; object-level access control is not tested |
| **A02 Security Misconfiguration** | Moderate external subset | Headers, cookies, CORS, directory listing, version disclosure |
| **A03 Software Supply Chain Failures** | Not assessed | Needs dependency/build/source access |
| **A04 Cryptographic Failures** | Limited | HTTPS use and cookie flags only; no data-at-rest or key review |
| **A05 Injection** | Limited | Reflected XSS canary only; no SQLi, stored XSS, or exploitation |
| **A06 Insecure Design** | Not assessed | Requires design review and human judgment |
| **A07 Authentication Failures** | Limited | Login form transport only; no session/MFA/lockout testing |
| **A08 Software or Data Integrity Failures** | Not assessed | Needs source/config/update-mechanism review |
| **A09 Security Logging and Alerting Failures** | Not assessed | Requires logs, alert rules, and controlled events |
| **A10 Mishandling of Exceptional Conditions** | Limited | Verbose error/stack-trace disclosure only |

**Mandatory statement in every report:**

> This scan does not cover all OWASP Top 10:2025 categories. A03, A06, A08, and A09 are not assessed in the MVP. A01, A04, A05, A07, and A10 are only partially assessed. Results are not proof that the application is secure.

---

## 6. The 8 MVP Checks

| # | Check | What it looks for | OWASP | Confidence |
|---|---|---|---|---|
| 1 | Security headers | Missing CSP, HSTS, `X-Frame-Options`/frame protection, `X-Content-Type-Options`, `Referrer-Policy` | A02 | Confirmed |
| 2 | Cookie flags | Missing `Secure`, `HttpOnly`, or `SameSite` on cookies | A02 / A04 | Confirmed |
| 3 | HTTPS and login transport | Site uses HTTP, or a login form submits over HTTP | A04 / A07 | Confirmed |
| 4 | CORS wildcard | `Access-Control-Allow-Origin: *`, especially with credentials | A01 / A02 | Likely |
| 5 | Directory listing | Server exposes an “Index of /” style directory page | A02 | Confirmed |
| 6 | Version disclosure | Server/framework version exposed in headers or page content | A02 | Confirmed |
| 7 | Reflected XSS | Harmless canary reflected without encoding in a query parameter | A05 | Likely |
| 8 | Verbose errors | Malformed but harmless input produces stack traces or internal error details | A10 | Likely |

### Explicitly not checked in the MVP

- SQL injection, command injection, stored XSS, second-order injection.
- IDOR/BOLA, privilege escalation, multi-role access control.
- Session fixation, logout invalidation, MFA, account lockout.
- TLS certificate expiry/mismatch, weak ciphers, deep TLS configuration.
- Exposed backup files, `.git`, `.env`, package manifests.
- Missing Subresource Integrity, mixed content beyond basic observation.
- Supply chain, secrets, IaC, logging, alerting, design flaws.
- Business logic, race conditions, deserialization, SSRF.

This is intentional. Saying “not tested” is part of the product’s honesty.

---

## 7. MVP Features

### Setup and access

- Local single-admin login.
- Admin password set during setup.
- No registration, roles, invitations, or password reset.
- Local-first deployment; not a public SaaS.

### Targets and safety

- Add, view, and delete authorized targets.
- Target must match the operator’s allowlist.
- Explicit authorization checkbox before the first scan.
- Always block cloud metadata addresses and non-HTTP(S) schemes.
- Lab mode can allow localhost/private lab addresses only when the operator explicitly enables it.

### Scanning

- One **Safe Scan** profile.
- One scan at a time.
- Maximum 20 pages, depth 2, 5 minutes, and 2 requests per second per target.
- Same-origin crawler; no JavaScript rendering.
- Cancel button.
- The 8 checks listed above.
- No exploitation, data extraction, persistence, brute force, or denial-of-service behavior.

### Findings

- Finding title, affected URL, check ID, evidence, severity, confidence, OWASP category, CWE where applicable, remediation, and reference.
- Simple deduplication by check + URL.
- Severity: Critical, High, Medium, Low, Info.
- Confidence: Confirmed, Likely, Possible.
- Mark as false positive / restore.
- No assignment, comments, or complex workflow.

### Reporting and history

- Dashboard with total findings, counts by severity, and last scan status.
- Scan history list.
- Finding detail page.
- Coverage matrix.
- HTML report and JSON export.
- Browser print-to-PDF (no server-side PDF generation).
- Basic activity log of scans and finding changes.

---

## 8. What Is Postponed

### Version 2 — only after the Lean MVP works

- Public target ownership verification (DNS TXT or HTML file).
- Authenticated single-session scanning.
- Multi-role authorization testing: IDOR/BOLA, privilege escalation.
- SQL injection, stored XSS, TLS certificate checks, exposed-file checks, SRI.
- Scheduling, email/webhook notifications.
- Server-side PDF, CSV, and SARIF exports.
- SCA/SBOM, secret scanning, IaC/configuration checks, SAST import.
- API scanning from OpenAPI.
- GitHub/GitLab/Jira/Slack integrations.
- Multi-tenant workspaces and SSO.
- JavaScript-rendered crawling.

### Advanced — optional, later

- AI-assisted remediation and triage with citations and human review.
- Attack-surface discovery.
- Continuous monitoring.
- Human-approved, non-destructive proof-of-concept validation.
- Auto-fix pull requests.
- Compliance mapping.
- Custom check SDK.
- SIEM/SOAR/CMDB integration.

### Never in scope

- Denial-of-service or stress testing.
- Brute-force, password cracking, or credential stuffing.
- Malware, social engineering, or physical testing.
- Destructive exploitation, data exfiltration, persistence, or lateral movement.
- WAF/IDS evasion.
- Unauthorized scanning.
- A guarantee of complete coverage or zero false positives.
- Compliance certification.

---

## 9. Functional Requirements

| ID | Priority | Requirement |
|---|---|---|
| FR-001 | MUST | The app supports one local admin login; no registration, roles, or password reset. |
| FR-002 | MUST | The admin can add, view, and delete an HTTP/HTTPS target with a name and base URL. |
| FR-003 | MUST | A target must match the operator-configured allowlist before it can be scanned. |
| FR-004 | MUST | The user must confirm authorization before the first scan of a target. |
| FR-005 | MUST | The app blocks cloud-metadata addresses, non-HTTP(S) schemes, and disallowed private addresses. |
| FR-006 | MUST | The admin can start one Safe Scan at a time. |
| FR-007 | MUST | A scan enforces 20 pages, depth 2, 5 minutes, and 2 requests per second per target. |
| FR-008 | MUST | The crawler stays on the same origin and does not execute JavaScript. |
| FR-009 | MUST | The scan can be cancelled. |
| FR-010 | MUST | The scan runs exactly the 8 documented checks. |
| FR-011 | MUST | Every finding includes title, URL, check ID, evidence, severity, confidence, OWASP mapping, remediation, and reference. |
| FR-012 | MUST | Findings are deduplicated by check + URL. |
| FR-013 | MUST | Severity is one of Critical, High, Medium, Low, Info. |
| FR-014 | MUST | Confidence is one of Confirmed, Likely, Possible. |
| FR-015 | MUST | Every report shows the OWASP coverage matrix and the mandatory limitation statement. |
| FR-016 | MUST | Evidence is redacted for cookies, authorization headers, tokens, passwords, and obvious personal data. |
| FR-017 | MUST | The user can mark a finding as a false positive and restore it. |
| FR-018 | MUST | The dashboard shows total findings, severity counts, last scan status, and coverage. |
| FR-019 | MUST | The user can view scan history and open a previous scan. |
| FR-020 | MUST | The user can export a scan as HTML and JSON, and print the HTML to PDF. |
| FR-021 | MUST | The app records a basic activity log of scans, exports, target changes, and finding changes. |
| FR-022 | MUST | The user can delete a target and its associated scans/findings. |
| FR-023 | SHOULD | The UI shows scan progress and the remaining page/request budget. |
| FR-024 | SHOULD | The UI provides a short explanation of each check and its limitations. |
| FR-025 | SHOULD | The report includes scan metadata: target, date, duration, page count, and scan profile. |

---

## 10. Non-Functional Requirements

| ID | Requirement |
|---|---|
| NFR-001 | A 20-page scan completes within 5 minutes on a normal laptop with a stable connection. |
| NFR-002 | The app supports one user and one concurrent scan. No queue is required. |
| NFR-003 | A first-time user can complete setup, a scan, and an export within 5 minutes. |
| NFR-004 | Interactive pages respond within 2 seconds under normal local load. |
| NFR-005 | The app runs locally and does not require a cloud account or paid service. |
| NFR-006 | Scan data is retained for 30 days by default and can be deleted manually. |
| NFR-007 | Checks are modular and independently testable; core logic has at least 60% automated test coverage. |
| NFR-008 | Logs exclude secrets and personal data. |
| NFR-009 | The UI works in current Chrome, Firefox, and Edge at desktop width. |
| NFR-010 | User and setup documentation are included. |
| NFR-011 | No unresolved Critical or High security defect may ship. |
| NFR-012 | The app remains useful if one check fails; a failed check does not fail the whole scan. |

---

## 11. Security Requirements

| ID | Requirement |
|---|---|
| SR-001 | **Local-first.** Bind to localhost by default; do not expose the app publicly without explicit configuration and a warning. |
| SR-002 | **Authorization and allowlist.** A scan requires an allowlisted target and an authorization confirmation. |
| SR-003 | **Non-destructive.** Use harmless canaries only. No writes, uploads, account changes, persistence, brute force, or DoS. |
| SR-004 | **Rate limiting and kill switch.** Enforce request limits, backoff, and a way to stop all scanning. |
| SR-005 | **Admin authentication.** Store the admin password as a memory-hard hash; use secure session cookies and CSRF protection. |
| SR-006 | **No stored target credentials.** The MVP does not support authenticated scans, so it must not collect or store target passwords, cookies, or tokens. |
| SR-007 | **Input/output safety.** Validate input, use parameterized queries, encode output, and avoid exposing stack traces. |
| SR-008 | **Redaction.** Remove cookies, auth headers, tokens, passwords, and personal data from evidence and logs. |
| SR-009 | **Safe errors.** User-facing errors are generic; detailed errors stay in protected logs. |
| SR-010 | **Activity logging.** Record scan starts/stops, target changes, exports, and finding changes. |
| SR-011 | **Dependency safety.** Pin dependencies, keep a lockfile, and run dependency checks before release. |
| SR-012 | **Report privacy.** Reports are stored locally and are not publicly accessible. |
| SR-013 | **Legal.** Include an acceptable-use notice and require authorization confirmation. |
| SR-014 | **SSRF hygiene.** Reject metadata endpoints and disallowed schemes; validate redirects against the allowlist. |

---

## 12. Expected Demonstration

The demo should take about 5 minutes and use a local intentionally vulnerable lab such as OWASP Juice Shop or DVWA.

1. Start VulnSight locally and sign in as the admin.
2. Add the lab URL from the allowlist and confirm authorization.
3. Run a Safe Scan; show progress, page count, and request budget.
4. Show findings for missing headers, cookie flags, HTTPS/login transport, CORS, directory listing, version disclosure, reflected XSS, and/or verbose errors.
5. Open one finding and explain the evidence, confidence, OWASP mapping, and remediation.
6. Mark a finding as a false positive and show the activity log.
7. Open the coverage matrix and explain that A03, A06, A08, and A09 are not assessed.
8. Export HTML and JSON; print the HTML to PDF.
9. Show scan history and the dashboard.
10. State clearly what the scan proved, what it only suggested, and what remains untested.

---

## 13. MVP Acceptance Criteria

The Lean MVP is complete when:

1. The app runs locally and the single admin can sign in.
2. A non-allowlisted target cannot be scanned.
3. A cloud-metadata address is blocked.
4. A 20-page Safe Scan completes or stops at the budget.
5. All 8 checks run and produce findings on the lab target.
6. Findings show evidence, severity, confidence, OWASP mapping, and remediation.
7. Duplicate findings are merged.
8. Secrets and cookies are redacted.
9. The false-positive toggle works.
10. The coverage matrix and limitation statement appear in the UI and report.
11. HTML and JSON exports work; the HTML prints cleanly to PDF.
12. Scan history and the activity log are visible.
13. No Critical or High security defect remains open in the app.
14. The demo can be completed in 5–10 minutes without manual database edits.

---

## 14. Beginner-Friendly Glossary

| Term | Meaning |
|---|---|
| **Vulnerability** | A weakness that could let someone harm or misuse a system. |
| **Finding** | A specific observation from the scanner; it may be real or a false positive. |
| **False positive** | A finding that looks like a problem but is not actually exploitable or relevant. |
| **OWASP Top 10** | A list of the ten most critical web application security risk categories. |
| **CWE** | A catalog of common software weakness types. |
| **CORS** | Rules controlling which websites may call an API from a browser. |
| **XSS** | Cross-site scripting: injecting JavaScript into a page so it runs in another user’s browser. |
| **TLS** | The encryption protocol behind HTTPS; it protects data in transit. |
| **HSTS** | A header telling browsers to use HTTPS for future visits. |
| **CSP** | A browser rule set limiting what scripts and resources can run. |
| **Cookie flags** | Settings such as `Secure`, `HttpOnly`, and `SameSite` that control cookie exposure. |
| **OWASP mapping** | Connecting a finding to the most relevant OWASP category. |
| **Confidence** | How sure the scanner is that a finding is real. |
| **Redaction** | Removing or masking secrets and personal data. |
| **Non-destructive testing** | Testing without damaging data, changing settings, or taking control. |
| **Rate limiting** | Limiting requests so the target is not overwhelmed. |

---

## 15. Approval

| Decision | Status |
|---|---|
| Lean MVP scope approved | ☐ |
| 8 checks approved | ☐ |
| OWASP coverage and limitations approved | ☐ |
| Single-admin/local-first model approved | ☐ |
| V2/Advanced split approved | ☐ |
| Permission to begin Step 1.2 (architecture) | ☐ |

**Step 1.1 remains the only completed step.** No architecture or code will begin until the Lean MVP requirements are approved.

*Full previous version: `docs/archive/SRS-v1.0-full.md`.*
