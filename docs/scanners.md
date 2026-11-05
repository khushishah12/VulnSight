# VulnSight OWASP Top 10:2025 Vulnerability Detection Engine

## 1. Architectural Overview

VulnSight's detection engine provides a modular, extensible, and non-destructive framework for assessing web applications against the **OWASP Top 10:2025** standard. The architecture strictly decouples scanning logic from transport, persistence, and reporting, ensuring high reliability, testability, and safety.

```
┌───────────────────────────────────────────────────────────────────────────┐
│                           Scan Orchestrator                               │
│                   (app.scanners.orchestrator)                             │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            ▼                                                   ▼
┌─────────────────────────┐                           ┌────────────────────┐
│   Safe Recon Client     │                           │ Discovered Endpoints│
│ (SSRF / DNS Protection) │                           │  & Recon Payloads  │
└───────────┬─────────────┘                           └─────────┬──────────┘
            │                                                   │
            └─────────────────────────┬─────────────────────────┘
                                      │
                                      ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                     OWASP Top 10:2025 Modular Scanners                    │
│                                                                           │
│  [A01] Access Control         [A02] Security Misconfig  [A03] Supply Chain│
│  [A04] Cryptographic Failures [A05] Injection           [A06] Design      │
│  [A07] Auth Failures          [A08] Integrity Failures  [A09] Logging     │
│  [A10] Exceptional Conditions                                             │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
                                      ▼ (FindingDraft / FindingEvidenceDraft)
┌───────────────────────────────────────────────────────────────────────────┐
│                    Persistence & Deduplication Engine                     │
│                  (PostgreSQL / Neon Serverless DB)                        │
│                                                                           │
│  • Finding Entity (check_id, owasp_category, severity, confidence)        │
│  • Evidence Entity (kind, label, content, content_sha256, is_redacted)   │
│  • Remediation Entity (summary, steps, references, status)                │
│  • AuditLog Entity (action="scanners.findings_recorded")                 │
└───────────────────────────────────────────────────────────────────────────┘
```

### 1.1 Core Contracts (`base.py`)
- **`BaseScanner`**: Abstract base class requiring `scan(...)` returning `list[FindingDraft]`.
- **`FindingEvidenceDraft`**: Evidence bundle with `kind` (`request`, `response`, `text`, `log`), `label`, `content`, and redaction flags.
- **`FindingDraft`**: Structured finding holding check ID, category (`A01`–`A10`), severity (`critical`, `high`, `medium`, `low`, `info`), confidence (`certain`, `firm`, `tentative`), remediation guidance, and deterministic fingerprint generator.

### 1.2 Orchestration & Fault Isolation (`orchestrator.py`)
- Scanners run sequentially within an isolated try/except block. If an individual check fails or raises an unhandled exception, it is logged, and execution continues uninterrupted across remaining scanners.
- Findings are deduplicated per scan using a deterministic SHA-256 fingerprint:
  $$\text{Fingerprint} = \text{SHA256}(\text{scan\_id} : \text{check\_id} : \text{title} : \text{endpoint\_id})$$
- All records (findings, evidence, remediations) are atomically written and recorded in the audit log.

---

## 2. OWASP Top 10:2025 Category Specifications

---

### Category A01 – Broken Access Control

#### 1. Vulnerability Explanation
Broken Access Control occurs when an application fails to properly enforce restrictions on what authenticated or unauthenticated users are allowed to do. Attackers can exploit these flaws to access unauthorized functionality or data (e.g., viewing other users' accounts, sensitive files, administrative portals, or executing privileged actions).

#### 2. Why It Occurs (Root Cause)
- Implicit trust in client-side state, navigation, or parameters.
- Missing server-side authorization middleware on administrative routes.
- Flawed role-based access control (RBAC) or attribute-based access control (ABAC).
- Insecure Direct Object References (IDOR).
- HTTP verb tampering (e.g., allowing unauthenticated `HEAD` or `OPTIONS` when `GET` is blocked, or `POST` bypassing filters).

#### 3. Conceptual Attacker Exploitation
An attacker scans for common administrative paths (e.g., `/admin`, `/api/v1/users`, `/dashboard`). If access control checks are absent or rely solely on frontend menu hiding, the attacker makes direct HTTP requests, gaining access to administrative dashboards, user databases, or internal configuration tools without possessing administrative privileges.

#### 4. Evidence Collected
- Target endpoint URL.
- HTTP Request method, headers, and request path.
- HTTP Response status code (e.g., `200 OK` on an unauthenticated administrative resource), headers, and truncated body showing privileged UI elements or data.

#### 5. Automated Detection Scope
- Identifying unauthenticated access to standard administrative, internal, and actuator routes.
- Detecting HTTP method tampering where unauthenticated verbs return successful status codes without challenge.
- Detecting absence of `WWW-Authenticate` or `Location` redirects when accessing privileged endpoints.

#### 6. What Requires Authentication, Source Code Review, or Manual Review
- Multi-tenant boundary isolation (Tenant A viewing Tenant B's data via IDOR) requires two valid tenant accounts.
- Granular business logic authorization (e.g., junior manager approving a transaction above their limit) requires application context and manual testing.
- Source code analysis (SAST) is required to verify that authorization annotations/decorators (e.g., `@has_role('admin')`) are applied consistently across all controllers.

#### 7. Safe Detection Logic Implementation
- Module: `app.scanners.a01_access_control` (`AccessControlScanner`)
- Probes a controlled list of common administrative paths (`/admin`, `/admin/`, `/administrator`, `/api/admin`, `/manage`, `/dashboard`, `/actuator`).
- Tests if unauthenticated requests yield `200 OK` with sensitive keywords (`admin`, `dashboard`, `management`, `control panel`).
- Tests HTTP verb manipulation (`OPTIONS`, `HEAD`) against protected endpoints without sending destructive bodies.

#### 8. Confidence Levels
- **Firm**: When an administrative path returns `200 OK` containing explicit administrative keywords in the response body.
- **Tentative**: When an administrative path returns `200 OK` or `405 Method Not Allowed` without explicit administrative keywords (possible false positive or generic SPA index route).

#### 9. False-Positive Considerations & Mitigations
- Single Page Applications (SPAs) often return `200 OK` and `index.html` for every path.
- *Mitigation*: The scanner verifies that the returned content type is either JSON or contains specific administrative keywords, and checks that it differs from the root homepage body hash.

#### 10. Lab Testing Verification
- **Target Lab**: OWASP Juice Shop (`/#/administration`, `/rest/admin/application-version`) and custom vulnerable endpoints.
- **Test Result**: Accurately flags exposed administration endpoints and records request/response evidence.

---

### Category A02 – Security Misconfiguration

#### 1. Vulnerability Explanation
Security Misconfiguration happens when security controls are inaccurately configured, default configurations are retained, open cloud storage is accessible, verbose error messages are displayed, or vital security headers are absent.

#### 2. Why It Occurs (Root Cause)
- Deploying default framework configurations into production.
- Failure to disable debugging or development features.
- Incomplete HTTP response header policies (e.g., omitting CSP, X-Frame-Options).
- Permissive Cross-Origin Resource Sharing (CORS) wildcards or origin reflection with credentials enabled.
- Unprotected directory listings on web servers.

#### 3. Conceptual Attacker Exploitation
An attacker queries the server and inspects headers. If `Access-Control-Allow-Origin` dynamically reflects arbitrary origins with `Access-Control-Allow-Credentials: true`, an attacker can host a malicious website that issues authenticated AJAX requests to steal sensitive user data. If directory listing is enabled, attackers browse source files, backups, and database dumps.

#### 4. Evidence Collected
- Missing or misconfigured HTTP headers list (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Permissions-Policy`).
- Reflected CORS headers with credentials.
- HTTP response showing directory index file listings or accessible `.git/config` / `.env` files.

#### 5. Automated Detection Scope
- Evaluation of security headers.
- CORS origin reflection with credentials (`Origin: https://evil.com`).
- Detection of publicly accessible development/configuration files (`.env`, `.git/config`, `web.config`, `Dockerfile`).
- Detection of directory listing titles (`Index of /`, `Directory Listing for`).

#### 6. What Requires Authentication, Source Code Review, or Manual Review
- Internal cloud IAM policies and S3/GCS bucket permissions.
- Database access control lists and server hardening configurations.
- Unused services running behind firewalls or reverse proxies.

#### 7. Safe Detection Logic Implementation
- Module: `app.scanners.a02_security_misconfiguration` (`SecurityMisconfigurationScanner`)
- Reuses passive reconnaissance header analysis.
- Issues a benign CORS probe with `Origin: https://evil-attacker.example.com` and checks if credentials flag is returned alongside reflected origin.
- Sends safe `GET` requests to `.env`, `.git/HEAD`, `.git/config`, validating file signatures (e.g., `ref: refs/heads/`).

#### 8. Confidence Levels
- **Certain**: Accessible `.git/config` or `.env` files with signature content; CORS reflecting origin with `Access-Control-Allow-Credentials: true`.
- **Firm**: Missing critical security headers on production endpoints.
- **Tentative**: Directory listing indicator on generic HTTP servers.

#### 9. False-Positive Considerations & Mitigations
- WAF or custom 404 handlers returning `200 OK` with generic error text.
- *Mitigation*: Strictly validate file contents (e.g., `.git/config` must contain `[core]`; `.env` must match key-value regex patterns) before reporting a finding.

#### 10. Lab Testing Verification
- **Target Lab**: OWASP Juice Shop and DVWA.
- **Test Result**: Detected missing Content-Security-Policy, overly permissive CORS headers, and flagged exposed configuration files.

---

### Category A03 – Software Supply Chain Failures

#### 1. Vulnerability Explanation
Software Supply Chain Failures (elevated in OWASP Top 10:2025) occur when applications incorporate vulnerable, unmaintained, tampered, or outdated third-party packages, libraries, Docker images, or CDN scripts.

#### 2. Why It Occurs (Root Cause)
- Lack of dependency tracking (absence of Software Bill of Materials - SBOM).
- Relying on outdated client-side libraries with known CVEs (e.g., vulnerable jQuery, AngularJS, Bootstrap).
- Publicly exposing package manifests (`package.json`, `requirements.txt`, `Pipfile.lock`, `composer.json`) allowing attackers to fingerprint exact dependency trees.
- Insecure package repositories or lack of cryptographic signature verification.

#### 3. Conceptual Attacker Exploitation
An attacker scans script tags or package manifests to discover vulnerable library versions (e.g., jQuery `< 3.5.0` vulnerable to prototype pollution and CVE-2020-11022). The attacker then leverages documented CVE exploits against client sessions.

#### 4. Evidence Collected
- Detected library name, detected version, known CVE identifiers.
- Manifest URL, HTTP response status, and manifest excerpt.
- Matched `<script src="...">` tags.

#### 5. Automated Detection Scope
- Identifying client-side library versions via regex on script URLs and inline script headers.
- Checking detected versions against curated vulnerability thresholds (e.g., jQuery, AngularJS, Bootstrap, Lodash).
- Detecting publicly accessible package manifests (`package.json`, `composer.json`, `package-lock.json`).

#### 6. What Requires Authentication, Source Code Review, or Manual Review
- Deep transitive backend dependencies (e.g., deep Java Maven or Python wheels not exposed over HTTP).
- Private packages vulnerable to dependency confusion / typosquatting.
- Software provenance verification (SLSA framework) and CI/CD pipeline pipeline security.

#### 7. Safe Detection Logic Implementation
- Module: `app.scanners.a03_supply_chain` (`SupplyChainScanner`)
- Passively parses scripts discovered during HTML recon for version patterns (`jquery-1.12.4.min.js`, `bootstrap@4.3.1`).
- Queries standard manifest paths safely using `GET` and verifies JSON syntax and valid dependency fields.

#### 8. Confidence Levels
- **Firm**: Publicly exposed `package.json` with dependency listings; client-side libraries with explicitly matched vulnerable version numbers.
- **Tentative**: Library name detected in script path without an explicit, verifiable version string.

#### 9. False-Positive Considerations & Mitigations
- Minified or patched scripts retaining older header banners.
- *Mitigation*: Only flag libraries where the full semver string is positively identified and strictly less than the secure threshold.

#### 10. Lab Testing Verification
- **Target Lab**: OWASP Juice Shop (exposing older client libraries and manifests).
- **Test Result**: Successfully detected vulnerable libraries and manifest disclosure without disruptive traffic.

---

### Category A04 – Cryptographic Failures

#### 1. Vulnerability Explanation
Previously known as Sensitive Data Exposure, Cryptographic Failures involve weaknesses related to cryptography (or lack thereof), leading to sensitive data exposure in transit or at rest.

#### 2. Why It Occurs (Root Cause)
- Transmitting sensitive data over cleartext HTTP.
- Absence of HTTP Strict Transport Security (`HSTS`).
- Transmitting credentials or session cookies without the `Secure` attribute.
- Deprecated TLS protocols (TLS 1.0, 1.1) or weak cipher suites.
- Sensitive user inputs (passwords, payment cards) submitted to non-HTTPS action endpoints.

#### 3. Conceptual Attacker Exploitation
An attacker on the same local network (Wi-Fi hotspot, compromised router, or malicious ISP) intercepts cleartext HTTP traffic using ARP spoofing or DNS poisoning. They sniff session cookies or passwords submitted over unencrypted links, or perform SSL stripping attacks when HSTS is absent.

#### 4. Evidence Collected
- Target URL using `http://` scheme.
- Missing `Strict-Transport-Security` header or invalid `max-age`.
- List of cookies set without the `Secure` flag.
- Form `<form action="http://...">` containing password fields.

#### 5. Automated Detection Scope
- Verifying whether target enforces HTTPS.
- Checking for the presence and validity of `Strict-Transport-Security` (HSTS).
- Analyzing `Set-Cookie` directives for missing `Secure` flags.
- Checking HTML forms for password inputs submitting over unencrypted HTTP.

#### 6. What Requires Authentication, Source Code Review, or Manual Review
- Weak encryption algorithms used at rest (AES-ECB vs. AES-GCM, DES, 3DES).
- Hardcoded cryptographic keys, weak initialization vectors (IVs), or flawed PRNGs in backend source code.
- Certificate chain validation, revocation status (OCSP stapling), and key rotation policies.

#### 7. Safe Detection Logic Implementation
- Module: `app.scanners.a04_crypto_failures` (`CryptographicFailuresScanner`)
- Evaluates target URL scheme and response headers.
- Inspects all parsed HTML forms for inputs with `type="password"` whose form action is either cleartext HTTP or hosted on a cleartext page.
- Inspects all cookies extracted during HTTP recon.

#### 8. Confidence Levels
- **Certain**: URL scheme is `http://`; password form submitted over cleartext HTTP; cookie set without `Secure` on HTTPS.
- **Firm**: Missing HSTS header on an HTTPS endpoint.

#### 9. False-Positive Considerations & Mitigations
- Localhost development environments typically do not have HTTPS/HSTS configured.
- *Mitigation*: Mark findings on `localhost` / `127.0.0.1` as Low/Info severity with explanatory notes indicating they apply to production environments.

#### 10. Lab Testing Verification
- **Target Lab**: HTTP endpoints, local mock servers, DVWA over HTTP.
- **Test Result**: Correctly flagged cleartext transmission, missing HSTS, and insecure cookie attributes.

---

### Category A05 – Injection

#### 1. Vulnerability Explanation
Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query (SQL, NoSQL, OS Command, LDAP, or Cross-Site Scripting HTML injection). The attacker's hostile data tricks the interpreter into executing unintended commands or accessing data without proper authorization.

#### 2. Why It Occurs (Root Cause)
- String concatenation or interpolation used to construct database queries, OS commands, or dynamic HTML.
- Inadequate input validation, sanitation, or contextual output encoding.
- Direct reflection of user input from query parameters, path segments, or POST data into response HTML.

#### 3. Conceptual Attacker Exploitation
An attacker submits an escape string (e.g., `' OR '1'='1`, `<script>alert(1)</script>`, `| whoami`). In SQL injection, this alters the query syntax to bypass authentication or dump database tables. In reflected XSS, an attacker tricks a victim into clicking a link that executes arbitrary JavaScript in their browser session.

#### 4. Evidence Collected
- Parameter name and injected benign test token (e.g., `vsight<safe_tag_99>`).
- Unsanitized reflection in the HTTP response body.
- Database syntax error messages (e.g., `SQL syntax`, `ORA-01756`, `psycopg2.errors`).
- HTTP request URL and response excerpt.

#### 5. Automated Detection Scope
- Non-destructive reflected input analysis using unique benign canary tokens (e.g., `vsight_probe_safe`).
- Detection of raw HTML angle-bracket reflection without contextual entity encoding.
- Passive detection of verbose database syntax errors elicited by benign single-quote probes.

#### 6. What Requires Authentication, Source Code Review, or Manual Review
- Blind SQL injection requiring time-delay exploitation or heavy out-of-band requests.
- Stored/Second-order injection (persisted in DB and displayed to administrators later).
- In-depth AST and data-flow taint analysis via SAST to verify parameterized queries across all database access layers.

#### 7. Safe Detection Logic Implementation
- Module: `app.scanners.a05_injection` (`InjectionScanner`)
- **Strictly Non-Destructive**: Never sends weaponized exploit payloads (`DROP TABLE`, `UNION SELECT`, `<script>`, shell metacharacters).
- Injects a uniquely generated random alphanumeric canary token (e.g., `vsightprobe12345` and benign `vsight<safe_tag_12345>`).
- Probes single-quote syntax leakage (`'`) and checks for known database error strings using a compiled regular expression library (PostgreSQL, MySQL, SQLite, Oracle, MSSQL).

#### 8. Confidence Levels
- **Firm**: Unsanitized canary token with unescaped `<safe_tag>` reflected verbatim in an HTML response.
- **Firm**: Database syntax error explicitly matching vendor error signatures.
- **Tentative**: Parameter reflected with partial encoding.

#### 9. False-Positive Considerations & Mitigations
- Search endpoints or echo services reflecting input safely inside `<textarea>` or correctly encoded.
- *Mitigation*: The scanner specifically checks for unencoded `<` and `>` characters inside standard HTML contexts. If encoded as `&lt;` and `&gt;`, no finding is raised.

#### 10. Lab Testing Verification
- **Target Lab**: OWASP Juice Shop (`/rest/products/search?q=...`) and intentionally vulnerable injection endpoints.
- **Test Result**: Successfully detected reflected XSS canary token and database syntax errors without triggering WAF blocks or database disruption.

---

### Category A06 – Insecure Design

#### 1. Vulnerability Explanation
Insecure Design represents fundamental flaws in architecture and design rather than implementation bugs. It focuses on risks related to design and architectural flaws, calling for more pre-design threat modeling, secure design patterns, and reference architectures.

#### 2. Why It Occurs (Root Cause)
- Lack of security requirements analysis during the software design phase.
- Missing anti-automation controls (rate limiting) on sensitive business operations.
- State-changing actions performed via HTTP `POST`/`PUT` without anti-Cross-Site Request Forgery (CSRF) tokens.
- Failure to model threats such as credential stuffing, brute force, or account enumeration.

#### 3. Conceptual Attacker Exploitation
An attacker creates a malicious webpage with an auto-submitting hidden form pointing to `https://bank.com/transfer`. If the banking application lacks anti-CSRF tokens, a logged-in victim visiting the malicious site unknowingly submits the transfer request. Alternatively, an attacker scripts thousands of credential attempts against an unthrottled password-reset endpoint.

#### 4. Evidence Collected
- Form action URL and method (`POST`).
- Extracted input names showing absence of standard anti-CSRF token fields (`csrf`, `xsrf`, `token`, `_token`).
- Target form HTML representation.

#### 5. Automated Detection Scope
- Identifying state-changing HTML forms (`POST`, `PUT`, `DELETE`) lacking anti-CSRF tokens.
- Identifying sensitive flows (login, register, reset password) lacking rate-limiting headers or lockout indicators.

#### 6. What Requires Authentication, Source Code Review, or Manual Review
- Threat modeling (STRIDE / PASTA) of business workflows.
- Financial logic verification (e.g., race conditions on gift card redemptions).
- Credential recovery flows, security question resilience, and architectural trust boundaries.

#### 7. Safe Detection Logic Implementation
- Module: `app.scanners.a06_insecure_design` (`InsecureDesignScanner`)
- Inspects all parsed HTML forms with `method="post"`.
- Checks form inputs against a comprehensive list of anti-CSRF field name conventions (`csrf_token`, `xsrf_token`, `csrfmiddlewaretoken`, `authenticity_token`, `__RequestVerificationToken`).
- Flags missing protection when neither hidden input tokens nor anti-CSRF cookie patterns are found.

#### 8. Confidence Levels
- **Firm**: State-changing POST form completely lacking hidden anti-CSRF token inputs or SameSite cookie protection.
- **Tentative**: API endpoint that might rely on custom JSON request headers (`X-Requested-With`) rather than form tokens.

#### 9. False-Positive Considerations & Mitigations
- Modern Single Page Applications submitting JSON payloads with `Authorization: Bearer <JWT>` are inherently immune to standard cross-origin form submission CSRF.
- *Mitigation*: The scanner only flags standard HTML forms submitting via `application/x-www-form-urlencoded` or `multipart/form-data`.

#### 10. Lab Testing Verification
- **Target Lab**: DVWA (CSRF module) and custom test forms.
- **Test Result**: Successfully detected unprotected POST forms and highlighted missing CSRF safeguards.

---

### Category A07 – Identification and Authentication Failures

#### 1. Vulnerability Explanation
Identification and Authentication Failures (formerly Broken Authentication) encompass weaknesses in user identity verification, session management, and credential protection.

#### 2. Why It Occurs (Root Cause)
- Permitting weak or default passwords.
- Exposing session IDs in URL query parameters.
- Session cookies missing the `HttpOnly` or `SameSite` flags.
- Failure to invalidate session tokens upon logout or timeout.
- Unprotected brute-force or credential-stuffing surfaces.

#### 3. Conceptual Attacker Exploitation
If a session cookie lacks the `HttpOnly` flag, any Cross-Site Scripting (XSS) vulnerability enables an attacker to execute `document.cookie` and steal the user's active session token. If session tokens appear in URL query strings, they leak via HTTP `Referer` headers, browser history, and proxy logs.

#### 4. Evidence Collected
- Cookie names and attribute flags (`HttpOnly`, `SameSite`, `Path`).
- URL query parameters containing session tokens (`sessionid`, `token`, `auth`, `jwt`).
- HTTP request and response header snapshots.

#### 5. Automated Detection Scope
- Verifying whether cookies set by the application enforce `HttpOnly` and `SameSite` attributes.
- Checking for session tokens or authentication keys transmitted in URL query strings.
- Identifying missing authentication requirements on sensitive endpoints.

#### 6. What Requires Authentication, Source Code Review, or Manual Review
- Safe password storage auditing (Argon2id, bcrypt, PBKDF2 vs. MD5/SHA1).
- Multi-factor authentication (MFA) bypasses and enforcement logic.
- Session revocation on password reset or account deactivation.

#### 7. Safe Detection Logic Implementation
- Module: `app.scanners.a07_auth_failures` (`AuthenticationFailuresScanner`)
- Analyzes session cookies extracted during HTTP reconnaissance.
- Inspects query parameters on all discovered endpoints for sensitive token keys (`session`, `sid`, `token`, `auth_token`, `jwt`).

#### 8. Confidence Levels
- **Certain**: Session cookies explicitly missing `HttpOnly` or `SameSite`; session identifiers present in URL query strings.
- **Firm**: Authentication forms transmitted over unencrypted channels.

#### 9. False-Positive Considerations & Mitigations
- Non-sensitive cookies (e.g., `theme=dark`, `ui_lang=en`) do not strictly require `HttpOnly`.
- *Mitigation*: The scanner targets known session/auth cookie naming patterns (`session`, `sid`, `jwt`, `token`, `auth`, `connect.sid`, `PHPSESSID`, `JSESSIONID`).

#### 10. Lab Testing Verification
- **Target Lab**: OWASP Juice Shop and DVWA.
- **Test Result**: Accurately flagged session cookies without `HttpOnly` and highlighted URL query token exposure.

---

### Category A08 – Software and Data Integrity Failures

#### 1. Vulnerability Explanation
Software and Data Integrity Failures focus on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying their integrity. This includes untrusted deserialization and loading external scripts without Subresource Integrity (SRI) hashes.

#### 2. Why It Occurs (Root Cause)
- Loading client-side scripts from third-party Content Delivery Networks (CDNs) without specifying `integrity="..."` (Subresource Integrity).
- Deserializing untrusted objects (Python `pickle`, Java `ObjectInputStream`, PHP `unserialize`).
- Pulling dependencies or firmware updates from unauthenticated or unsigned sources.

#### 3. Conceptual Attacker Exploitation
An attacker compromises a third-party CDN or performs a DNS spoofing attack. Because the client browser does not verify the cryptographic hash of the delivered script (`integrity="sha384-..."`), the browser executes the attacker's tampered JavaScript, resulting in full application takeover.

#### 4. Evidence Collected
- `<script src="https://cdn.example.com/...">` HTML tag.
- Missing `integrity` attribute.
- Missing `crossorigin` attribute.

#### 5. Automated Detection Scope
- Scanning all external `<script>` and `<link rel="stylesheet">` elements loaded from third-party origins to verify presence of valid SRI `integrity` attributes.
- Identifying mixed-content inclusions (HTTP assets loaded on HTTPS pages).

#### 6. What Requires Authentication, Source Code Review, or Manual Review
- Server-side insecure deserialization endpoints.
- Auto-update signing and verification mechanisms.
- CI/CD deployment pipeline configuration (GitHub Actions, GitLab CI secrets and runner security).

#### 7. Safe Detection Logic Implementation
- Module: `app.scanners.a08_integrity_failures` (`IntegrityFailuresScanner`)
- Uses parsed HTML script and stylesheet tags from reconnaissance.
- Checks if the script origin differs from the target domain.
- Flags third-party scripts that lack the `integrity` attribute.

#### 8. Confidence Levels
- **Certain**: External third-party `<script>` tag loaded on HTTPS without an `integrity` hash.
- **Firm**: External stylesheet missing SRI.

#### 9. False-Positive Considerations & Mitigations
- First-party scripts served from relative paths (`/static/js/app.js`) do not require SRI because they share the primary origin's trust and TLS transport.
- *Mitigation*: The scanner only validates scripts with absolute `http://` or `https://` URLs pointing to distinct hostnames.

#### 10. Lab Testing Verification
- **Target Lab**: Web applications loading jQuery or Bootstrap from public CDNs without SRI hashes.
- **Test Result**: Successfully detected scripts missing SRI and generated appropriate remediation advice.

---

### Category A09 – Security Logging and Alerting Failures

#### 1. Vulnerability Explanation
Insufficient logging, detection, monitoring, and active response allow attackers to sustain persistence, pivot to other systems, and tamper with, extract, or destroy data without being noticed.

#### 2. Why It Occurs (Root Cause)
- Failure to log auditable events (logins, failed logins, high-value transactions).
- Absence of distributed tracing identifiers (`X-Request-ID`, `X-Correlation-ID`) across API services.
- Exposing sensitive data, API keys, or stack traces in client-side console logs.
- Failure to configure real-time alerting for anomalous traffic spikes or security events.

#### 3. Conceptual Attacker Exploitation
An attacker executes slow, distributed brute-force or credential-stuffing attacks. Because the application does not log authentication failures or alert security operations (SecOps), the attacker operates undetected for months until a breach occurs.

#### 4. Evidence Collected
- HTTP response headers indicating absence of request tracking (`X-Request-ID`, `X-Correlation-ID`).
- Inline scripts containing client-side logging calls (`console.log`, `console.error`) referencing sensitive tokens (`token`, `password`, `key`, `secret`).

#### 5. Automated Detection Scope
- Verifying the presence of request correlation and tracing headers on API endpoints.
- Inspecting client-side HTML and JavaScript for debug logging of credentials or sensitive data.

#### 6. What Requires Authentication, Source Code Review, or Manual Review
- Backend log centralization (SIEM, Elasticsearch, CloudWatch).
- Log immutability, encryption, and retention policies.
- Incident response time, alerting thresholds, and SOC playbook efficacy.

#### 7. Safe Detection Logic Implementation
- Module: `app.scanners.a09_logging_failures` (`LoggingAndAlertingScanner`)
- Evaluates response headers of API and web endpoints for standard correlation headers (`X-Request-ID`, `X-Correlation-ID`, `Traceparent`).
- Scans inline script content for `console.log(...)` or `console.debug(...)` containing sensitive keywords.

#### 8. Confidence Levels
- **Firm**: Sensitive credentials or tokens printed to client-side console logs.
- **Low/Info**: Missing `X-Request-ID` or distributed tracing headers on public API routes.

#### 9. False-Positive Considerations & Mitigations
- Static landing pages or brochure websites do not require distributed tracing headers.
- *Mitigation*: Missing correlation header findings are classified as Informational or Low severity and targeted primarily at API endpoints.

#### 10. Lab Testing Verification
- **Target Lab**: OWASP Juice Shop and mock API services.
- **Test Result**: Accurately flagged missing request correlation headers and detected client-side debug statements.

---

### Category A10 – Mishandling of Exceptional Conditions

#### 1. Vulnerability Explanation
Previously focused on Server-Side Request Forgery (SSRF) in 2021, OWASP Top 10:2025 expands Category A10 to cover **Mishandling of Exceptional Conditions**. This addresses flaws where an application fails to securely manage errors, unhandled exceptions, unexpected data types, or edge conditions, resulting in sensitive system disclosure, fail-open states, or denial of service.

#### 2. Why It Occurs (Root Cause)
- Catching exceptions generically or leaving unhandled runtime exceptions.
- Displaying raw stack traces, framework debug screens (Django debug screen, Werkzeug debugger, Spring Whitelabel Error Page), or database query dumps to end users.
- Failing open: default-allowing access when an authorization service or external identity provider is unreachable.
- Leaking internal operating system paths (`/var/www/`, `C:\inetpub\`, `/home/app/`).

#### 3. Conceptual Attacker Exploitation
An attacker submits malformed inputs, oversized payloads, or invalid types (e.g., passing a JSON array where an integer is expected). The server crashes and returns a detailed stack trace showing framework versions, internal file paths, database schema details, and third-party library internals. The attacker uses this intelligence to target known vulnerabilities.

#### 4. Evidence Collected
- HTTP response body containing stack trace markers (e.g., `Traceback (most recent call last)`, `NullPointerException`, `Fatal error:`).
- Matched internal OS file paths (`/var/www/...`, `C:\Users\...`).
- Detected framework debug screens.

#### 5. Automated Detection Scope
- Detecting stack traces across major runtime environments:
  - Python (`Traceback (most recent call last):`, `django.core.exceptions`)
  - Java (`java.lang.NullPointerException`, `at com.`, `org.springframework.`)
  - PHP (`Fatal error:`, `Uncaught Exception in /`)
  - ASP.NET / C# (`System.NullReferenceException`, `Server Error in '/' Application`)
  - Node.js / Express (`TypeError: Cannot read property`, `at Module._compile`)
- Detecting disclosure of internal operating system paths in HTTP responses.

#### 6. What Requires Authentication, Source Code Review, or Manual Review
- Analyzing fail-open vs. fail-closed behavior under network partition or upstream service outage.
- Resource exhaustion (memory leaks, CPU spikes) under extreme concurrency edge cases.
- Source code review of `try / catch / finally` blocks and custom exception hierarchies.

#### 7. Safe Detection Logic Implementation
- Module: `app.scanners.a10_exceptional_conditions` (`ExceptionalConditionsScanner`)
- Uses compiled regex patterns targeting known stack trace headers across Python, Java, PHP, .NET, and Node.js.
- Inspects response bodies of reconnaissance endpoints and error responses.
- Extracts and redacts internal paths, creating structured evidence items.

#### 8. Confidence Levels
- **Certain**: Complete runtime stack trace or framework debug screen detected in response.
- **Firm**: Explicit internal filesystem path disclosure in response body.

#### 9. False-Positive Considerations & Mitigations
- Educational websites or documentation pages discussing error handling may contain the text `NullPointerException`.
- *Mitigation*: The scanner requires multi-line call stack patterns (e.g., `at com.package...` or `File "...py", line \d+`) rather than simple word matches.

#### 10. Lab Testing Verification
- **Target Lab**: OWASP Juice Shop and mock servers generating 500 errors with debug stack traces.
- **Test Result**: Successfully detected stack traces and internal paths, generating critical findings with exact line evidence.

---

## 3. Database Persistence & Storage Mapping

Findings, evidence, and remediations are persisted into Neon Serverless PostgreSQL according to the normalized database schema:

| Table | Entity | Key Fields Stored |
| :--- | :--- | :--- |
| `findings` | `Finding` | `id`, `scan_id`, `endpoint_id`, `check_id`, `owasp_category` (`A01`–`A10`), `title`, `description`, `severity`, `confidence`, `status`, `fingerprint` |
| `evidence` | `Evidence` | `id`, `finding_id`, `kind` (`request`, `response`, `text`, `log`), `label`, `content`, `content_sha256` (64-char hex), `is_redacted` |
| `remediations` | `Remediation` | `id`, `finding_id`, `summary`, `steps` (JSONB array), `references` (JSONB array), `status` (`not_started`) |
| `audit_logs` | `AuditLog` | `id`, `action` (`scanners.findings_recorded`), `entity_type` (`scan`), `entity_id`, `scan_id`, `details` |

---

## 4. Test Suite Verification

The detection engine is accompanied by an extensive test suite in `backend/tests/test_scanners.py`.

```
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-8.3.4
collected 11 items

backend/tests/test_scanners.py::test_a01_access_control PASSED           [  9%]
backend/tests/test_scanners.py::test_a02_security_misconfiguration PASSED [ 18%]
backend/tests/test_scanners.py::test_a03_supply_chain PASSED             [ 27%]
backend/tests/test_scanners.py::test_a04_cryptographic_failures PASSED   [ 36%]
backend/tests/test_scanners.py::test_a05_injection_reflected_xss PASSED  [ 45%]
backend/tests/test_scanners.py::test_a05_injection_sql_error PASSED      [ 54%]
backend/tests/test_scanners.py::test_a06_insecure_design PASSED          [ 63%]
backend/tests/test_scanners.py::test_a07_authentication_failures PASSED  [ 72%]
backend/tests/test_scanners.py::test_a08_integrity_failures PASSED       [ 81%]
backend/tests/test_scanners.py::test_a09_logging_failures PASSED         [ 90%]
backend/tests/test_scanners.py::test_a10_exceptional_conditions PASSED   [100%]

======================== 11 passed, 10 warnings in 39.29s =====================
```
