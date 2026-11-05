# VulnSight — Software Requirements Specification (SRS)

| Field | Value |
|---|---|
| Project | VulnSight — Intelligent Web Application Vulnerability Assessment and Remediation Platform |
| Document | Software Requirements Specification (SRS) |
| Version | 1.0 — Step 1.1 baseline |
| Status | Draft for approval. No architecture or implementation has started. |
| Date | 05 November 2026 |
| Scope of this document | Requirements only: problem, users, features, OWASP coverage, MVP/V2/Advanced split, functional, non-functional, security, and demonstration expectations |
| Approval needed from | Project owner |

> **How to read this document.** VulnSight is a security tool, but this SRS is written so that a beginner can follow it. Cybersecurity terms are explained where they first appear and again in Appendix A. The words **MUST**, **SHOULD**, and **MAY** describe requirement strength: MUST = required, SHOULD = strongly expected, MAY = optional/future.

---

## 1. Purpose

This document defines what VulnSight will and will not do. It is deliberately honest about the limits of automated web scanning. Its most important rule is:

> **VulnSight must never claim that a URL scan proves an application is secure, or that all ten OWASP Top 10:2025 categories have been fully tested.**

Instead, VulnSight reports what it actually observed, how confident it is, what still needs authenticated testing, source-code review, configuration review, or human assessment, and what the user should do next.

### 1.1 Baseline decisions made in this version

| ID | Decision |
|---|---|
| D-01 | The MVP is a **single-workspace, self-hosted web application**. Multi-tenancy is Version 2. |
| D-02 | The MVP supports **unauthenticated scanning** and an **optional single-session authenticated crawl**. Automated multi-role authorization testing is Version 2. |
| D-03 | “Intelligent” in the MVP means deterministic correlation, deduplication, confidence scoring, and contextual remediation guidance. It does **not** mean an AI chatbot. AI assistance is an Advanced feature. |
| D-04 | All ten OWASP Top 10:2025 categories are **mapped and explained**, but only a subset can be dynamically assessed. A03, A06, and A09 are explicitly not assessed by URL scanning in the MVP. |
| D-05 | The MVP is **non-destructive**. It does not exploit, extract data, persist access, brute-force credentials, or perform denial-of-service testing. |
| D-06 | The MVP requires **authorization attestation and target ownership verification** before the first scan. |
| D-07 | The MVP exports reports as **HTML, PDF, and JSON**. CSV and SARIF are Version 2. |
| D-08 | No production billing, public SaaS, or enterprise compliance certification is in scope for the MVP. |

---

## 2. Problem Statement

### 2.1 The exact problem VulnSight solves

Small development teams, independent developers, students, and lean security teams often need a fast answer to four questions:

1. **What is visibly exposed** on our web application from the outside?
2. **Which OWASP Top 10:2025 risk** does each observation relate to?
3. **Which findings matter first**, and how confident are we that each one is real?
4. **How do we fix it**, in language a developer can act on?

Today, answering those questions usually requires either an expensive commercial scanner, a periodic penetration test, or manual security expertise. The results are often noisy, hard to interpret, and disconnected from remediation. Conversely, free tools may find issues but provide little context, no OWASP mapping, weak reporting, and no honest statement of what they could not test.

**VulnSight turns an authorized URL — and optionally a test session or source/configuration input — into a prioritized, evidence-backed, OWASP-mapped assessment report with practical remediation guidance and an explicit coverage disclaimer.**

### 2.2 Why existing approaches fall short

- **Manual penetration tests** are valuable but episodic, expensive, and not available on every commit.
- **Raw scanners** produce duplicate findings, false positives, and technical output that non-specialists cannot prioritize.
- **Unauthenticated scanners** cannot see logged-in areas, role-based access control, or most business logic.
- **Source-only tools** cannot see how the deployed application actually behaves.
- **Compliance checklists** do not tell a developer what is wrong on this specific URL today.
- **AI-only tools** can sound confident while being wrong; they need evidence and human review.

### 2.3 What success looks like

A first-time user can add an authorized target, run a safe scan, understand the top risks in plain language, see the evidence, export a useful report, and know exactly which checks were not possible. The platform reduces time-to-first-useful-assessment without exaggerating coverage.

### 2.4 What VulnSight is not

VulnSight is **not**:

- a replacement for a professional penetration test;
- a guarantee that an application is secure;
- a full source-code audit, cloud posture scanner, or compliance certification tool in the MVP;
- an exploitation framework;
- a tool for scanning systems without permission;
- a way to bypass authentication, exfiltrate data, or attack third parties.

---

## 3. Users and Stakeholders

### 3.1 Primary users

| User | What they need | Typical use |
|---|---|---|
| **Solo developer / small development team** | A quick, affordable external check before release | Scan a staging or production URL, fix high-priority issues, export a report |
| **Application security analyst** | Evidence, triage, deduplication, and retest support | Review findings, mark false positives, track remediation, compare scans |
| **QA / DevOps engineer** | Repeatable security checks in a delivery workflow | Run a scan after deployment; later integrate with CI/CD |
| **Security consultant or educator** | A structured assessment and teaching aid | Assess lab targets, demonstrate OWASP categories, produce reports |
| **IT generalist at a small organization** | Plain-language visibility into website exposure | Understand missing protections and prioritize fixes |

### 3.2 Secondary stakeholders

- **Engineering managers** who need a risk summary, not raw HTTP traffic.
- **Compliance or audit readers** who consume reports but do not operate the scanner.
- **System administrators** who configure users, retention, and scan limits.
- **Instructors and students** using intentionally vulnerable lab applications in a controlled environment.

### 3.3 Access roles for the MVP

| Role | Permissions |
|---|---|
| **Admin** | Manage workspace, users, scan limits, target verification, retention, and all findings |
| **Analyst** | Add verified targets, run scans, review findings, export reports |
| **Viewer** | Read dashboards and reports; cannot start scans or change findings |

### 3.4 Who must not use it

Anyone who does not own or have explicit written permission to test the target. VulnSight is an authorized-assessment platform, not an attack service.

---

## 4. Product Overview and Scope

### 4.1 Three assessment modes

VulnSight must clearly distinguish three levels of access, because they produce very different evidence:

1. **Unauthenticated URL scanning** — the scanner behaves like an anonymous visitor. It sees only public pages and responses.
2. **Authenticated testing** — the scanner uses a test account/session supplied by the target owner. It can see logged-in pages and, in Version 2, compare multiple roles.
3. **Source-code or configuration review** — the scanner or reviewer examines code, dependency manifests, server configuration, infrastructure-as-code, logs, or design documents. This is largely a Version 2/Advanced capability and is not “URL scanning.”

### 4.2 Coverage honesty requirement

Every scan report MUST include a coverage matrix showing:

- which OWASP categories were tested dynamically;
- which were only partially tested;
- which require authentication;
- which require source/configuration access;
- which were not tested at all;
- the reason for each limitation.

A finding must never be described as “the application is vulnerable to A01” merely because one check in that category was run. Findings are specific observations mapped to a category.

### 4.3 Main capabilities

1. Authorized target onboarding and scope control.
2. Safe crawling and technology discovery.
3. Unauthenticated and optional authenticated assessment.
4. OWASP Top 10:2025 and CWE mapping.
5. Evidence capture with secret/PII redaction.
6. Deduplication, severity, confidence, and prioritization.
7. Remediation guidance with references.
8. Dashboards, scan history, and finding workflow.
9. HTML, PDF, and JSON reports.
10. Audit logging and safety guardrails.

---

## 5. OWASP Top 10:2025 Categories

VulnSight uses the official OWASP Top 10:2025 list. The categories below are the complete list; VulnSight does not claim full assessment of all of them.

| ID | Category | Beginner-friendly meaning |
|---|---|---|
| **A01:2025** | Broken Access Control | A user can do or see something they should not, such as opening another user’s record or an admin page. |
| **A02:2025** | Security Misconfiguration | The system is set up unsafely: default settings, unnecessary features, missing security headers, verbose errors, or open permissions. |
| **A03:2025** | Software Supply Chain Failures | A weakness comes from dependencies, build tools, package registries, or distribution infrastructure — not just the application’s own code. |
| **A04:2025** | Cryptographic Failures | Sensitive data is not properly protected by encryption, hashing, or key management. |
| **A05:2025** | Injection | Untrusted input is treated as code or commands, such as SQL, operating-system commands, or browser JavaScript. |
| **A06:2025** | Insecure Design | Security was not built into the design or business workflow; this is a missing control, not merely a coding mistake. |
| **A07:2025** | Authentication Failures | Login, session, password, or multi-factor authentication is weak or can be bypassed. |
| **A08:2025** | Software or Data Integrity Failures | The system trusts code, updates, or data without verifying that it has not been tampered with. |
| **A09:2025** | Security Logging and Alerting Failures | Attacks are not recorded, and nobody is alerted when something suspicious happens. |
| **A10:2025** | Mishandling of Exceptional Conditions | Errors, missing parameters, crashes, or unusual states are handled unsafely, including “failing open.” |

### 5.1 Coverage matrix

Coverage levels used below:

- **Moderate** — useful external evidence for a meaningful subset, but not the whole category.
- **Limited** — a few specific checks; most of the category remains untested.
- **Context-dependent** — requires authentication, multiple roles, logs, source, or configuration.
- **Not assessed** — no honest automated URL check in the MVP.

| OWASP category | MVP unauthenticated URL scan | Authenticated testing | Source/config review | Honest MVP claim |
|---|---|---|---|---|
| **A01 Broken Access Control** | Limited: exposed admin/debug endpoints, forced-browsing signals, some CORS issues | Strong for role/object checks in V2 | Strong: route guards, authorization policy, access-control matrix | “Limited exposure checks only; object-level access control is not proven.” |
| **A02 Security Misconfiguration** | Moderate: headers, cookies, directory listing, default files, HTTP methods, CORS, debug/error configuration | Helpful for admin surfaces | Strong: server, framework, cloud, and IaC configuration | “External misconfiguration subset.” |
| **A03 Software Supply Chain Failures** | Very limited: front-end library fingerprints and exposed manifests | Not primarily an auth issue | Strong: SCA/SBOM, lockfiles, container images, CI/CD, registries | “Not assessed in MVP.” |
| **A04 Cryptographic Failures** | Limited: TLS/certificate issues, cookie flags, mixed content, HTTP login forms | Helpful for token and sensitive-data handling | Strong: crypto code, secrets, key management, data-at-rest design | “Transport and cookie subset only.” |
| **A05 Injection** | Limited: reflected XSS and error-based SQL injection with non-destructive canaries | Broader: stored XSS, second-order injection, authenticated endpoints | Strong: SAST/taint analysis, dangerous APIs, templates, ORM misuse | “Two narrow injection classes; no exploitation.” |
| **A06 Insecure Design** | Not assessed | Only workflow evidence; still manual | Strong: threat model, design docs, secure SDLC review | “Not assessed; requires design review.” |
| **A07 Authentication Failures** | Limited: login transport, cookie/session flags, username-enumeration indicators | Strong: session lifecycle, logout, MFA, lockout, password policy | Strong: auth code, session configuration, password storage | “Login/session surface only.” |
| **A08 Software or Data Integrity Failures** | Limited: missing Subresource Integrity, mixed content, some exposed artifacts | Some data-integrity evidence | Strong: signature verification, update mechanism, deserialization, CI/CD integrity | “SRI and mixed-content subset.” |
| **A09 Security Logging and Alerting Failures** | Not observable from outside | Only with log access and controlled test events | Strong: logging config, alert rules, retention, SIEM, incident response | “Not assessed.” |
| **A10 Mishandling of Exceptional Conditions** | Limited: malformed input causing verbose errors, stack traces, inconsistent 5xx responses | Helpful for authenticated error paths | Strong: exception handling, fail-open paths, transaction rollback, resource cleanup | “Error-disclosure subset only.” |

### 5.2 Category-by-category reality check

- **A01** is the hardest category to prove from outside. A scanner can sometimes find an admin page that responds without login, but it cannot prove that one user cannot read another user’s record unless it has multiple accounts and known test objects.
- **A02** is the strongest MVP category because many misconfigurations are directly observable in HTTP responses.
- **A03** is primarily a dependency/build/CI problem. A URL scan can sometimes fingerprint an outdated front-end library, but that is weak evidence and not a supply-chain assessment.
- **A04** is often misunderstood. TLS protects data in transit; it does not prove that passwords are hashed correctly or that data at rest is encrypted.
- **A05** has many forms. Reflected XSS and error-based SQL injection are feasible, limited checks. Stored XSS, blind injection, deserialization, and command injection need authentication, write actions, or deeper testing.
- **A06** is a design category. A scanner cannot reliably detect “the workflow allows a user to approve their own refund.”
- **A07** requires real accounts and session lifecycle testing. Login-page observations are only a small subset.
- **A08** requires knowing where code/data comes from and whether integrity is verified. SRI is one visible indicator.
- **A09** is almost entirely invisible from the outside. It requires logs, alert rules, and a controlled test event.
- **A10** can be partially observed through error behavior, but fail-open logic and transaction rollback require code/config review and controlled testing.

### 5.3 What “assessed” means in VulnSight

A category is marked **assessed** only when at least one specific, documented check ran and produced evidence. The report must distinguish:

- **Tested, no finding observed** — not the same as “secure.”
- **Partially tested** — only some checks ran.
- **Not tested** — no check ran, or the required access was unavailable.
- **Finding observed** — a specific signal was seen, with a confidence level.

---

## 6. Detection Capability by Access Level

### 6.1 What can be detected through unauthenticated URL scanning

These are realistic MVP checks, not a claim of complete coverage:

**Passive or low-impact observations**

- Missing or weak security headers: Content-Security-Policy, HSTS, X-Content-Type-Options, frame protection, Referrer-Policy, Permissions-Policy.
- Cookie flags: `Secure`, `HttpOnly`, and `SameSite`.
- TLS/certificate problems: expired certificate, hostname mismatch, deprecated protocol versions, weak cipher configuration where safely observable.
- HTTP-to-HTTPS redirect behavior and mixed content.
- CORS misconfiguration indicators, such as wildcard origins with credentials.
- Directory listing enabled.
- Common exposed files or paths, such as backups, debug pages, `.git` metadata, or package manifests — detected with minimal retrieval and redaction, never bulk download.
- Default/example pages, exposed admin or debug interfaces that respond without authentication.
- Unnecessary HTTP methods advertised by the server.
- Technology/version disclosure in headers or page content.
- Missing Subresource Integrity on third-party scripts.
- Login forms submitting over HTTP.
- Verbose error pages and stack traces caused by malformed but harmless input.
- Basic differences in error responses that suggest unhandled exceptions.

**Limited active checks**

- **Reflected cross-site scripting (XSS):** send a harmless canary value and check whether it is reflected without proper encoding. This does not prove exploitability in every browser context.
- **Error-based SQL injection:** send a small, non-destructive canary and look for database error signatures. This does not extract data and does not prove blind SQL injection.
- **Basic HTTP method behavior:** check advertised methods without performing destructive writes.

**What unauthenticated scanning cannot reliably detect**

- Object-level authorization (IDOR/BOLA) and privilege escalation.
- Stored XSS or second-order injection.
- Business-logic flaws.
- Most authentication/session weaknesses.
- Most supply-chain, logging, and design issues.
- Deserialization, race conditions, blind injection, and multi-step attacks.
- Whether data at rest is encrypted or keys are managed correctly.

### 6.2 What requires authenticated testing

Authentication means the scanner logs in with a test account supplied by the owner. This unlocks:

- **A01:** horizontal access control (one user reading another user’s object), vertical access control (normal user reaching admin functions), forced browsing, missing function-level authorization, CORS with credentials.
- **A02:** authenticated admin/configuration surfaces and user-specific settings.
- **A04:** token handling, sensitive data in authenticated responses, cache controls, cookie behavior after login.
- **A05:** stored XSS, second-order injection, authenticated API parameters, and injection in multi-step forms.
- **A06:** evidence of workflow/business-logic weaknesses, though final judgment remains manual.
- **A07:** session fixation, logout invalidation, session timeout, MFA behavior, password policy, lockout, and credential-stuffing resistance (tested safely, without real credential attacks).
- **A08:** integrity of authenticated data flows and update mechanisms.
- **A10:** authenticated error paths and fail-open behavior.
- **A09:** only with log access; authentication alone is not enough.

**Important limitation:** automated authorization testing is only credible when the tester has at least two accounts with different roles and known test objects. The MVP supports one session for crawl coverage; full multi-role authorization testing is Version 2.

### 6.3 What requires source-code or configuration access

- **A01:** route guards, authorization middleware, policy definitions, access-control matrix.
- **A02:** server/framework configuration, cloud permissions, container settings, infrastructure-as-code, debug flags.
- **A03:** dependency manifests, lockfiles, SBOM, container images, build pipeline, package registry, provenance.
- **A04:** cryptography code, password hashing, key management, secrets, data-at-rest design, TLS termination configuration.
- **A05:** static analysis/taint tracking, dangerous APIs, template engines, ORM usage, deserialization, command execution.
- **A06:** threat models, design documents, secure SDLC process, business rules.
- **A07:** authentication code, session configuration, password storage, MFA implementation.
- **A08:** signature verification, update mechanism, CI/CD integrity, trusted artifact sources, deserialization safeguards.
- **A09:** logging configuration, alert rules, retention, SIEM integration, incident-response runbooks.
- **A10:** exception handling, fail-open paths, transaction boundaries, resource cleanup, error logging.

### 6.4 What no scanner can honestly prove

- That the application is free of vulnerabilities.
- That all OWASP categories are covered.
- That a business process is secure.
- That logging and alerting work, unless logs and alerts are inspected.
- That third-party dependencies and build systems are trustworthy, unless the supply chain is examined.
- That a finding is exploitable in every environment.

---

## 7. Feature Roadmap

### 7.1 MVP — must be completed first

The MVP is a **single-workspace, self-hosted web application** that performs safe external assessment and produces actionable reports.

**Onboarding and safety**

- Account registration, login, logout, and password reset.
- Admin, Analyst, and Viewer roles.
- Add an HTTP/HTTPS target with name, base URL, environment, and scope rules.
- Authorization attestation and ownership verification by DNS TXT record or HTML file.
- Block private, loopback, link-local, multicast, reserved, and cloud-metadata addresses.
- Per-target request-rate limits, page/request/time budgets, and a cancel button.
- Admin allowlist for local lab/demo targets.

**Scanning**

- Safe passive scan profile.
- Safe active scan profile with limited checks.
- Optional single-session authenticated crawl using a user-supplied cookie or header.
- Same-origin crawler with depth/page limits; robots.txt respected by default.
- Technology fingerprinting.
- Passive checks: headers, cookies, TLS/certificate, CORS, HTTP methods, directory listing, common exposed files, version disclosure, SRI, mixed content, login transport, verbose errors.
- Limited active checks: reflected XSS and error-based SQLi, using harmless canaries.
- No exploitation, data extraction, persistence, brute force, or denial-of-service behavior.

**Findings and remediation**

- Normalized finding records with URL, method, parameter, evidence, severity, confidence, CWE, and OWASP category.
- Deduplication and correlation.
- Severity and confidence labels.
- Plain-language explanation and remediation steps with references.
- Finding status: open, confirmed, false positive, accepted risk, fixed.
- Notes and assignment.
- Redaction of secrets, tokens, cookies, and personal data from evidence.

**Reporting and operations**

- Dashboard with scan status, risk counts, and coverage summary.
- Scan history and finding history.
- HTML, PDF, and JSON reports.
- Audit log for logins, target changes, scans, finding changes, exports, and admin actions.
- Data export and deletion request workflow.
- Coverage disclaimer on every report.

**MVP success statement**

> An authorized user can verify a target, run a safe scan, understand a prioritized set of OWASP-mapped findings with evidence and remediation, export a report, and see exactly what was not tested.

### 7.2 Version 2 — after the MVP is stable

- Multi-role authenticated testing: two or more accounts, role matrix, IDOR/BOLA, privilege escalation, forced browsing.
- Login-flow recording and session refresh; MFA handoff guidance.
- Scheduled/recurring scans and notifications.
- Baseline comparison, retest, and “fixed/regressed” tracking.
- SCA/SBOM, secret scanning, IaC/configuration checks, and import of SAST results.
- API scanning from OpenAPI/Swagger definitions.
- Framework-specific remediation guidance.
- CSV and SARIF exports.
- GitHub/GitLab/Jira/Slack/email/webhook integrations.
- Multi-tenant workspaces and SSO.
- JavaScript-rendered crawling for single-page applications.
- Richer false-positive workflow and reviewer sign-off.

### 7.3 Advanced features — later and optional

- AI-assisted triage and remediation drafting, with citations, opt-in data handling, and human review.
- Attack-surface discovery: subdomains, related assets, and cloud exposure.
- Continuous monitoring and distributed scanning.
- Human-approved, non-destructive proof-of-concept validation.
- Business-logic and workflow testing assistance.
- Threat-modeling assistant.
- Auto-fix pull requests with mandatory human review.
- SIEM/SOAR/CMDB integrations.
- Compliance mapping (for example PCI DSS, ISO 27001, SOC 2) — mapping, not certification.
- Custom check SDK and check marketplace.
- Predictive risk scoring and historical trend analysis.
- Mobile and cloud-native assessment modules.

### 7.4 Explicitly out of scope for all current phases

- Denial-of-service testing, stress testing, or resource-exhaustion attacks.
- Brute-force, password cracking, credential stuffing, or real credential attacks.
- Malware, ransomware, social engineering, or physical testing.
- Destructive exploitation, data exfiltration, persistence, or lateral movement.
- WAF/IDS evasion or stealth/anti-forensic behavior.
- Unauthorized scanning of third-party systems.
- A guarantee of complete OWASP coverage or zero false positives.
- Compliance certification.

---

## 8. Functional Requirements

Priority: **MUST** = required for the release; **SHOULD** = strongly expected; **MAY** = optional.

| ID | Release | Priority | Requirement |
|---|---|---|---|
| FR-001 | MVP | MUST | Users can register, sign in, sign out, and reset a password securely. |
| FR-002 | MVP | MUST | The system supports Admin, Analyst, and Viewer roles with least-privilege permissions. |
| FR-003 | MVP | MUST | The deployment is a single workspace; all targets, scans, and findings belong to that workspace. |
| FR-004 | MVP | MUST | An Analyst can add an HTTP/HTTPS target with a name, base URL, environment, and include/exclude scope rules. |
| FR-005 | MVP | MUST | Before the first scan, the user must attest authorization and verify control of the target using a DNS TXT record or an HTML verification file. |
| FR-006 | MVP | MUST | The system blocks loopback, private, link-local, multicast, reserved, and cloud-metadata addresses, plus non-HTTP(S) schemes. |
| FR-007 | MVP | MUST | The system re-resolves DNS and validates redirects/connections to prevent DNS rebinding and server-side request forgery (SSRF). |
| FR-008 | MVP | MUST | An Analyst can start a scan using Passive, Safe Active, or Authenticated Crawl profiles. |
| FR-009 | MVP | MUST | Every scan enforces page, request, depth, and time budgets and can be cancelled by the user. |
| FR-010 | MVP | MUST | The crawler stays within the verified scope, does not follow external domains, and respects robots.txt by default. |
| FR-011 | MVP | MUST | A user can supply one authenticated session as a cookie or header; it is encrypted at rest, revocable, excluded from logs, and never shown in reports. |
| FR-012 | MVP | MUST | The passive checker covers security headers, cookie flags, TLS/certificate issues, CORS, HTTP methods, directory listing, common exposed paths, version disclosure, SRI, mixed content, login transport, and verbose errors. |
| FR-013 | MVP | MUST | The active checker covers reflected XSS and error-based SQL injection only, using harmless canaries and no data extraction. |
| FR-014 | MVP | MUST | Every finding includes title, description, URL, method, parameter, evidence, severity, confidence, CWE, OWASP 2025 mapping, remediation, and references. |
| FR-015 | MVP | MUST | The system deduplicates and correlates repeated observations before presenting findings. |
| FR-016 | MVP | MUST | Every finding has a severity (Critical, High, Medium, Low, Info) and a confidence (Confirmed, Likely, Possible). |
| FR-017 | MVP | MUST | Every report shows a coverage matrix for all ten OWASP categories and states what was not tested. |
| FR-018 | MVP | MUST | Remediation guidance is written in plain language and includes at least one authoritative reference. |
| FR-019 | MVP | MUST | Evidence is redacted for cookies, authorization headers, tokens, passwords, API keys, and obvious personal data. |
| FR-020 | MVP | MUST | Findings can be marked open, confirmed, false positive, accepted risk, or fixed, with notes and assignee. |
| FR-021 | MVP | MUST | A dashboard shows scan status, counts by severity, recent scans, and coverage status. |
| FR-022 | MVP | MUST | Reports can be exported as HTML, PDF, and JSON. |
| FR-023 | MVP | MUST | Users can view scan history and the findings associated with each scan. |
| FR-024 | MVP | MUST | The system records an audit log of logins, target changes, scans, finding changes, exports, and admin actions. |
| FR-025 | MVP | SHOULD | Users can export workspace data and request deletion in line with the retention policy. |
| FR-026 | V2 | MUST | Authorized users can configure at least two test accounts/roles and run horizontal and vertical authorization checks. |
| FR-027 | V2 | MUST | Scans can be scheduled and users can receive email or webhook notifications. |
| FR-028 | V2 | MUST | Users can compare scans, retest findings, and see fixed/regressed status over time. |
| FR-029 | V2 | MUST | The platform can ingest source/config inputs for SCA/SBOM, secret scanning, IaC/configuration checks, and SAST results. |
| FR-030 | V2 | MUST | The platform can scan APIs from an OpenAPI/Swagger definition. |
| FR-031 | V2 | MUST | The platform integrates with at least GitHub/GitLab, Jira, Slack, email, and generic webhooks. |
| FR-032 | V2 | SHOULD | The platform supports multiple workspaces and SSO. |
| FR-033 | V2 | SHOULD | Remediation guidance includes framework-specific examples. |
| FR-034 | Advanced | MAY | An opt-in AI assistant drafts remediation explanations with citations and requires human review. |
| FR-035 | Advanced | MAY | The platform discovers related subdomains and external assets within an authorized scope. |
| FR-036 | Advanced | MAY | A human-approved validation workflow confirms selected findings with non-destructive proof-of-concept checks. |
| FR-037 | Advanced | MAY | The platform proposes auto-fix pull requests that require human approval before merge. |
| FR-038 | Advanced | MAY | Reports map findings to compliance frameworks without claiming certification. |
| FR-039 | Advanced | MAY | A custom-check SDK allows teams to add vetted checks safely. |
| FR-040 | Advanced | MAY | The platform exports to SIEM/SOAR/CMDB systems. |

---

## 9. Non-Functional Requirements

| ID | Category | Requirement |
|---|---|---|
| NFR-001 | Performance | A 50-page default scan completes within 10 minutes on the reference deployment (2 vCPU, 4 GB RAM, stable 10 Mbps connection). Report generation for 200 findings completes within 30 seconds. |
| NFR-002 | Responsiveness | Interactive pages should have a p95 response time of 2.5 seconds or less under normal load. |
| NFR-003 | Concurrency | The MVP supports 10 registered users and 3 concurrent scans system-wide, with queuing beyond that limit. Version 2 targets 100 users and 10 concurrent scans. |
| NFR-004 | Reliability | A single failed check must not fail the entire scan. Transient network failures are retried with backoff. Duplicate findings are not created by retries. |
| NFR-005 | Availability | The hosted reference deployment targets 99.0% monthly availability, excluding announced maintenance. Self-hosted availability depends on the operator. |
| NFR-006 | Usability | A first-time user can complete target verification, run a scan, and export a report within 10 minutes without training. |
| NFR-007 | Accessibility | Core workflows should meet WCAG 2.1 AA where practical. |
| NFR-008 | Compatibility | The web interface supports the latest two major versions of Chrome, Firefox, Edge, and Safari, and is usable at 360 px width. |
| NFR-009 | Maintainability | Detection checks are modular, documented, independently testable, and mapped to stable check IDs. Core logic has automated unit/integration tests with at least 70% coverage. |
| NFR-010 | Observability | Structured logs include scan ID and correlation ID, and exclude secrets. Metrics cover scan duration, request count, error rate, queue depth, and findings by severity. |
| NFR-011 | Portability | The MVP can run as a containerized single-node deployment with configuration supplied externally; no hard dependency on one cloud provider. |
| NFR-012 | Data retention | Scan data is retained for 90 days by default, configurable from 30 to 365 days, then purged automatically. |
| NFR-013 | Backup and recovery | A hosted deployment should support daily backups with a 24-hour recovery point objective and a 4-hour recovery time objective. |
| NFR-014 | Scalability | Version 2 should allow scan workers to scale horizontally without changing the user-facing API. |
| NFR-015 | Localization | The MVP is English-only but must keep user-facing strings externalized for future translation. |
| NFR-016 | Report consistency | The same finding data and coverage statements appear consistently in HTML, PDF, and JSON reports. |
| NFR-017 | Documentation | User, administrator, developer, and security-runbook documentation are delivered with each release. |
| NFR-018 | Release quality | No unresolved Critical or High security defect may ship in a release. SAST, DAST, and dependency checks run before release. |
| NFR-019 | Privacy | The platform supports data minimization, retention limits, export, and deletion in a GDPR/CCPA-aware manner. |
| NFR-020 | Legal | Terms of use, acceptable-use policy, and a vulnerability-disclosure contact are published before any public deployment. |

---

## 10. Security, Privacy, Legal, and Ethical Requirements

These requirements are part of the product, not optional hardening.

| ID | Requirement |
|---|---|
| SR-001 | **Authorization first.** No scan may start without an authorization attestation and successful target verification, except for an Admin-approved local lab target. |
| SR-002 | **Scope enforcement.** The scanner must enforce the target allowlist and scope rules at every request, including redirects. |
| SR-003 | **SSRF protection.** Block loopback, private, link-local, multicast, reserved, and cloud-metadata addresses. Re-resolve DNS and validate the actual connected address to prevent rebinding. |
| SR-004 | **Non-destructive testing.** Use a vetted payload allowlist. Do not write data, delete data, create accounts, change passwords, upload files, persist access, brute-force, or perform denial-of-service tests. |
| SR-005 | **Rate limiting.** Enforce per-target and global request limits, backoff on errors, and a global kill switch. |
| SR-006 | **Authentication security.** Hash passwords with a memory-hard algorithm (for example Argon2id) or a strong adaptive algorithm; enforce password policy, secure reset, and login throttling. |
| SR-007 | **Session security.** Use `Secure`, `HttpOnly`, and `SameSite` cookies; rotate sessions after login; enforce idle and absolute timeouts; invalidate sessions on logout; protect state-changing requests with CSRF defenses. |
| SR-008 | **Authorization and isolation.** Deny by default, enforce object-level authorization, separate admin functions, and isolate workspace data. Version 2 must isolate tenants. |
| SR-009 | **Secrets management.** Encrypt target credentials and session material at rest with a managed key; never write secrets to logs, reports, error messages, or analytics; allow revocation. |
| SR-010 | **Input and output safety.** Validate input, use parameterized queries, encode output, apply a Content-Security-Policy, and avoid exposing stack traces. |
| SR-011 | **Audit logging.** Record who did what, when, from where, and to which target. Protect audit logs from modification and retain them according to policy. |
| SR-012 | **Data protection.** Use TLS 1.2+ for all platform traffic, encrypt data at rest, encrypt backups, and restrict access to scan evidence. |
| SR-013 | **Privacy and redaction.** Collect only necessary data, redact secrets and personal data, support deletion, and never sell or repurpose scan data. |
| SR-014 | **Safe error handling.** Return generic errors to users, log details securely, and never include secrets or full request bodies in user-facing errors. |
| SR-015 | **Supply-chain security.** Pin dependencies, maintain lockfiles, run SCA, sign release artifacts, and produce an SBOM for the platform itself. |
| SR-016 | **Abuse prevention.** Apply quotas, detect abnormal scanning patterns, allow immediate suspension, and publish an abuse-contact process. |
| SR-017 | **Report access.** Reports are private by default. Shared links, if added, must be scoped, expiring, and revocable. |
| SR-018 | **AI guardrails (Advanced).** AI features are opt-in, must not send secrets or raw evidence to third parties without explicit consent, must cite sources, and must require human review. |
| SR-019 | **Legal compliance.** Publish acceptable-use terms, respect applicable law and jurisdiction, maintain an incident-response process, and provide a vulnerability-disclosure channel. |
| SR-020 | **Secure development.** Threat-model the platform, review code, run SAST/DAST/dependency checks, and conduct a penetration test before public launch. |
| SR-021 | **Environment separation.** Development, test, and production environments must use separate credentials and data; production secrets must never be used in tests. |
| SR-022 | **API security.** Authenticate every API call, enforce authorization and rate limits, validate schemas, and restrict CORS. |
| SR-023 | **File-upload safety (V2).** Restrict type and size, scan uploads, store them outside the web root, and never execute uploaded content. |

---

## 11. Data and Reporting Requirements

### 11.1 Finding record

Each finding must contain:

- stable finding ID and check ID;
- title and plain-language description;
- target, URL, HTTP method, and parameter;
- OWASP Top 10:2025 category and CWE;
- severity and confidence;
- evidence summary and redacted request/response excerpts;
- remediation steps and references;
- first seen, last seen, and scan ID;
- status, assignee, and notes;
- false-positive reason when applicable.

### 11.2 Severity and confidence

| Level | Meaning |
|---|---|
| **Critical** | Direct, high-impact compromise is plausible with little effort. |
| **High** | Significant data or access risk, or a serious missing control. |
| **Medium** | Exploitable under specific conditions, or a meaningful weakness. |
| **Low** | Hardening gap or limited-impact issue. |
| **Info** | Observation with no direct security impact. |

| Confidence | Meaning |
|---|---|
| **Confirmed** | The scanner directly observed the condition (for example, a missing header or a reflected canary). |
| **Likely** | Strong evidence, but a human should verify context. |
| **Possible** | Heuristic or fingerprint-based; may be a false positive. |

Severity must be explained. When a known CVE is involved, a CVSS score may be shown as additional context, but it is not proof of exploitability in this application.

### 11.3 Report sections

1. Cover page and report metadata.
2. Executive summary.
3. Scope, authorization, and verification status.
4. Method and scan profile.
5. OWASP Top 10:2025 coverage matrix.
6. Findings grouped by severity and category.
7. Evidence and affected URLs.
8. Remediation guidance.
9. Limitations and untested areas.
10. Appendix: glossary, references, and scan metadata.

### 11.4 Data classification and retention

- **Public:** generic documentation and marketing content.
- **Internal:** target names, scan metadata, non-sensitive findings.
- **Confidential:** evidence, request/response excerpts, report exports.
- **Secret:** credentials, session cookies, API keys, tokens — never stored in findings or reports.

Default retention is 90 days, configurable from 30 to 365 days. Deletion must remove findings, evidence, and exports according to policy while preserving required audit metadata.

---

## 12. Assumptions, Constraints, and Dependencies

### 12.1 Assumptions

- The user owns the target or has explicit written authorization.
- The target is reachable over HTTP/HTTPS and is not intentionally blocking all automated traffic.
- Authenticated testing uses credentials supplied by the target owner; MFA may limit automation.
- Source/configuration analysis is optional and user-provided.
- The MVP is self-hosted and single-workspace.
- OWASP Top 10:2025 mappings are versioned and can be updated.
- The demo target is an intentionally vulnerable local lab, not a public third-party site.

### 12.2 Constraints

- No destructive testing or exploitation.
- No guarantee of complete coverage or zero false positives.
- Automated checks cannot replace human judgment for design, business logic, and authorization.
- The MVP must remain usable by a small team without a dedicated security operations center.
- Legal and privacy obligations vary by jurisdiction.

### 12.3 Dependencies

- A reliable DNS and HTTP client with safe redirect handling.
- A maintained vulnerability/check knowledge base.
- OWASP Top 10:2025, CWE, and CVE reference data.
- A report renderer for HTML/PDF.
- An encrypted secret store for target credentials.
- An intentionally vulnerable lab application for testing and demonstration.

---

## 13. Risks and Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| False positives | Users lose trust and waste time | Confidence labels, evidence, manual verification, clear limitations |
| False negatives | Users believe an area is safe when it is not | Coverage matrix, explicit “not tested” statements, no security guarantee |
| Abuse of the scanner | Legal and ethical harm | Authorization verification, allowlist, SSRF protection, rate limits, audit logs, kill switch |
| Credential leakage | Account compromise | Encryption, redaction, no logging of secrets, revocation, least privilege |
| Scope creep | MVP never ships | Release gates, explicit MVP/V2/Advanced split |
| OWASP changes | Outdated mapping | Versioned mapping, update process, report shows mapping version |
| AI hallucination | Bad remediation advice | AI only in Advanced, citations, human review, no automatic changes |
| Target instability | Incomplete scans | Timeouts, retries with backoff, partial-scan reporting |
| Auth complexity | Authenticated coverage delayed | Single-session MVP; multi-role V2 |
| Data retention/privacy | Regulatory exposure | Minimization, redaction, retention limits, deletion workflow |
| Platform supply-chain compromise | Serious trust loss | Pinned dependencies, SCA, SBOM, signed artifacts, code review |

---

## 14. Acceptance Criteria and Expected Demonstration

### 14.1 MVP acceptance criteria

The MVP is accepted when:

1. An Admin, Analyst, and Viewer can perform their permitted actions.
2. A target cannot be scanned until authorization and ownership verification succeed.
3. A private/loopback/metadata target is blocked and the block is visible in the audit log.
4. A scan completes with a clear status, request budget, and cancellation behavior.
5. The scan detects the agreed passive checks and the two limited active checks on the lab target.
6. Findings include evidence, severity, confidence, CWE, OWASP mapping, and remediation.
7. Duplicate findings are merged and secrets are redacted.
8. The coverage matrix clearly states that A03, A06, and A09 are not assessed in the MVP.
9. HTML, PDF, and JSON reports are generated from the same finding data.
10. The audit log records the full scan lifecycle.
11. No Critical or High security defect remains open in the platform itself.
12. The demo can be completed in 15 minutes without manual database changes.

### 14.2 Expected MVP demonstration

**Scenario:** Assess a local, intentionally vulnerable lab application (for example OWASP Juice Shop) in a controlled environment.

1. Sign in as an Analyst.
2. Add the lab target and complete ownership verification (or use the Admin-approved lab allowlist).
3. Attempt to add a blocked private/metadata address; show that the platform refuses it.
4. Run an unauthenticated Safe Active scan; show the scan progress, request budget, and cancel option.
5. Review findings such as missing security headers, cookie flags, TLS/transport issues, error disclosure, reflected XSS, error-based SQLi, and an exposed admin/debug surface.
6. Open a finding and show the evidence, confidence, OWASP/CWE mapping, remediation, and references.
7. Mark one finding as a false positive and add a note; show the audit entry.
8. Add a single test session and run an Authenticated Crawl; show that protected pages are now discovered, while noting the limits of single-session testing.
9. Show the coverage matrix and explain why A03, A06, and A09 are not dynamically assessed.
10. Generate HTML, PDF, and JSON reports and open the executive summary.
11. Show scan history and the audit log.
12. Summarize what the scan proved, what it suggested, and what still requires source review, configuration review, multi-role testing, or a human pentest.

### 14.3 Final demonstration if Version 2/Advanced are completed

- Multi-role authorization testing with a demonstrated IDOR/BOLA finding, clearly separated from false positives.
- Scheduled scan and notification.
- Source/config assessment: dependency, secret, and IaC findings mapped to A03/A08/A09.
- API scan from an OpenAPI definition.
- Baseline comparison showing a fixed finding and a regressed finding.
- AI-assisted remediation draft with citations and human approval (Advanced only).
- Explicit statement that even the full platform is not a substitute for a professional penetration test or compliance certification.

---

## 15. Release Gates and Approval

### 15.1 Step 1.1 definition of done

- Problem statement, users, and scope are agreed.
- OWASP Top 10:2025 coverage is accepted as honest and limited.
- MVP, Version 2, and Advanced features are agreed.
- Functional, non-functional, and security requirements are approved.
- Demo scenario and acceptance criteria are approved.
- No architecture design or code has started.

### 15.2 Approval

| Decision | Status |
|---|---|
| Problem and scope approved | ☐ |
| Users and roles approved | ☐ |
| OWASP coverage claims approved | ☐ |
| MVP / V2 / Advanced split approved | ☐ |
| Functional requirements approved | ☐ |
| Non-functional requirements approved | ☐ |
| Security, privacy, and legal requirements approved | ☐ |
| Demonstration and acceptance criteria approved | ☐ |
| Permission to begin Step 1.2 (architecture design) | ☐ |

**Next step after approval:** Step 1.2 — architecture design. It has not started.

---

## Appendix A — Beginner-Friendly Glossary

| Term | Plain-language meaning |
|---|---|
| **Vulnerability** | A weakness that could let someone harm or misuse a system. |
| **Finding** | A specific observation reported by the scanner. It may be a real vulnerability or a false positive. |
| **False positive** | A finding that looks like a problem but is not actually exploitable or relevant. |
| **False negative** | A real problem the scanner did not find. |
| **Exploit** | A technique that takes advantage of a vulnerability. |
| **Proof of concept (PoC)** | A small, controlled demonstration that a vulnerability is real. |
| **OWASP** | A nonprofit community that publishes widely used application-security guidance. |
| **OWASP Top 10** | A list of the ten most critical web application security risk categories. |
| **CWE** | A catalog of common software weakness types. |
| **CVE** | A public identifier for a specific known vulnerability, usually in a product or library. |
| **CVSS** | A scoring system for the severity of a vulnerability; it is context, not proof. |
| **XSS** | Cross-site scripting: injecting JavaScript into a page so it runs in another user’s browser. |
| **SQL injection** | Sending input that changes a database query, potentially exposing or changing data. |
| **IDOR / BOLA** | Insecure direct object reference / broken object-level authorization: changing an ID to access someone else’s data. |
| **SSRF** | Server-side request forgery: tricking the server into making a request to an internal or unintended destination. |
| **CSRF** | Cross-site request forgery: tricking a logged-in user’s browser into sending an unwanted request. |
| **TLS** | The encryption protocol behind HTTPS; it protects data in transit. |
| **HSTS** | A header telling browsers to use HTTPS for future visits. |
| **CSP** | Content-Security-Policy: a browser rule set that limits what scripts and resources can run. |
| **CORS** | Cross-Origin Resource Sharing: rules controlling which websites may call an API from a browser. |
| **SRI** | Subresource Integrity: a check that a third-party script or stylesheet has not been tampered with. |
| **Cookie flags** | Settings such as `Secure`, `HttpOnly`, and `SameSite` that control how cookies are exposed and sent. |
| **Authentication** | Proving who you are, usually by logging in. |
| **Authorization** | What a logged-in user is allowed to do. |
| **Session** | The period and token that keep a user logged in. |
| **MFA** | Multi-factor authentication: a second proof of identity beyond a password. |
| **RBAC** | Role-based access control: permissions assigned by role. |
| **SAST** | Static application security testing: examining source code without running it. |
| **DAST** | Dynamic application security testing: testing a running application from the outside. |
| **SCA** | Software composition analysis: checking dependencies for known vulnerabilities and license issues. |
| **SBOM** | Software bill of materials: a list of the components in a product. |
| **IaC** | Infrastructure as code: configuration files that define servers and cloud resources. |
| **CI/CD** | Continuous integration/continuous delivery: automated build, test, and deployment pipelines. |
| **Non-destructive testing** | Testing that observes behavior without damaging data, changing settings, or taking control. |
| **Rate limiting** | Limiting how many requests are sent in a period so the target is not overwhelmed. |
| **Redaction** | Removing or masking secrets and personal data from logs and reports. |
| **Coverage matrix** | A table showing which checks ran and which did not. |
| **Self-hosted** | Software the user runs on their own infrastructure. |
| **Multi-tenant** | One deployment serving multiple separate organizations. |

---

## Appendix B — Coverage Disclaimer and References

### B.1 Mandatory disclaimer

> VulnSight performs authorized, non-destructive checks against the scope supplied by the user. It does not prove that an application is secure. Automated URL scanning cannot fully assess all OWASP Top 10:2025 categories. A03 (Software Supply Chain Failures), A06 (Insecure Design), and A09 (Security Logging and Alerting Failures) require source, configuration, log, or human review and are not dynamically assessed in the MVP. Findings may be incomplete or may contain false positives. Use VulnSight as one input to a broader security program, not as a replacement for code review, configuration review, or a professional penetration test.

### B.2 References

- OWASP Top 10:2025 — https://owasp.org/Top10/2025/
- OWASP Top 10:2025 Introduction — https://owasp.org/Top10/2025/0x00_2025-Introduction
- OWASP Application Security Verification Standard (ASVS)
- OWASP Web Security Testing Guide (WSTG)
- OWASP Cheat Sheet Series
- MITRE CWE — https://cwe.mitre.org/
- NIST National Vulnerability Database — https://nvd.nist.gov/

---

*End of VulnSight SRS v1.0 — Step 1.1. Architecture and implementation must not begin until the approval table above is completed.*
