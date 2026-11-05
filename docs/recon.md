# VulnSight — Reconnaissance Engine Architecture

| Field | Value |
|---|---|
| Step | 5 — Reconnaissance Engine |
| Status | Implemented, SSRF-hardened, and verified with automated test suite |
| Module | `backend/app/recon/` |
| Primary Libraries | HTTPX, BeautifulSoup4, ipaddress, socket, PostgreSQL |

The Reconnaissance Engine collects passive and active architectural intelligence about authorized target systems before vulnerability scanners execute. It discovers endpoints, maps attack surfaces, fingerprints server technologies, extracts HTML forms, and verifies security header compliance while strictly prohibiting arbitrary internal network access through multilayered SSRF defenses.

---

## 1. Architecture Overview

```mermaid
flowchart TD
    TargetInput["Target URL Input"] --> Validator["Target Validator (validator.py)"]
    Validator --> SyntaxCheck["Syntax & Scheme Check (http/https only)"]
    SyntaxCheck --> ScopeCheck["Authorized Host Allowlist Enforcement"]
    ScopeCheck --> AsyncDNS["Async DNS Resolution (socket.getaddrinfo)"]
    AsyncDNS --> SSRFFilter{"SSRF Filter Check"}

    SSRFFilter -- "Blocked Range / Metadata" --> Reject["Reject with SSRFBlockedError (403)"]
    SSRFFilter -- "Safe Public / Authorized IP" --> SafeClient["Safe HTTP Client (client.py)"]

    SafeClient --> HTTPRecon["HTTP Reconnaissance (http_recon.py)"]
    SafeClient --> HTMLRecon["HTML Reconnaissance (html_recon.py)"]
    SafeClient --> Discovery["Safe Discovery (discovery.py)"]

    HTTPRecon --> Status["Status & Latency"]
    HTTPRecon --> Headers["Headers & Server Banner"]
    HTTPRecon --> Cookies["Masked Cookies & Flags"]
    HTTPRecon --> SecHeaders["Defensive Headers Audit"]

    HTMLRecon --> Title["Page Title & Meta Tags"]
    HTMLRecon --> Links["Internal & External Links"]
    HTMLRecon --> Forms["Forms, Methods & Inputs"]
    HTMLRecon --> ScriptsStyles["Scripts & Stylesheets"]
    HTMLRecon --> Endpoints["Comments & Regex Endpoints"]

    Discovery --> Robots["robots.txt Parsing"]
    Discovery --> Sitemap["sitemap.xml Parsing"]
    Discovery --> SecTxt["security.txt (RFC 9116)"]
    Discovery --> TechDetection["Technology Fingerprinting"]

    HTTPRecon & HTMLRecon & Discovery --> Storage["PostgreSQL Storage (storage.py)"]
    Storage --> DBEndpoints[("discovered_endpoints Table")]
    Storage --> DBAudit[("audit_logs (recon.completed)")]
```

---

## 2. Part 1: Target Validation & Multi-Layered SSRF Defense

### 2.1 URL Syntax and Scheme Rules
* **Permitted schemes**: `http` and `https` exclusively. Protocols such as `file:`, `gopher:`, `ftp:`, `dict:`, `ldap:`, `data:`, and `javascript:` are rejected immediately.
* **Credentials forbidden**: URLs with embedded usernames or passwords (`http://user:pass@host/`) are blocked to prevent credential leakage.
* **Port range**: Restricted strictly to valid TCP ports ($1 \le \text{port} \le 65535$).
* **Fragment stripping**: URL fragments (`#...`) are removed prior to canonicalization.

### 2.2 Asynchronous DNS Resolution
Hostname resolution uses Python's asynchronous event loop via `asyncio.get_running_loop().getaddrinfo(...)` with `socket.SOCK_STREAM`. This avoids blocking worker threads and catches all A and AAAA records for a host.

### 2.3 SSRF IP Blocklist
Every resolved IP address is verified against standardized RFC address allocations using Python's `ipaddress` module:

| Category | Address Range / Subnet | RFC | Purpose |
|---|---|---|---|
| Loopback | `127.0.0.0/8`, `::1` | RFC 1122 / RFC 4291 | Local machine processes |
| Private IPv4 | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 | Corporate and home intranets |
| Shared Address Space | `100.64.0.0/10` | RFC 6598 | Carrier-grade NAT |
| Link-Local | `169.254.0.0/16`, `fe80::/10` | RFC 3927 / RFC 4291 | Auto-configured local links |
| Unique Local IPv6 | `fc00::/7` | RFC 4193 | Private IPv6 intranets |
| Cloud Metadata | `169.254.169.254` | AWS / GCP / Azure | Cloud instance metadata service (IMDS) |
| Container Metadata | `169.254.170.2` | AWS ECS | Container task credentials |
| Alibaba Cloud Metadata | `100.100.100.200` | Alibaba Cloud | Instance identity metadata |
| AWS IPv6 Metadata | `fd00:ec2::254` | AWS IMDSv2 IPv6 | Instance metadata service over IPv6 |
| Multicast | `224.0.0.0/4`, `ff00::/8` | RFC 5771 / RFC 4291 | Multicast groups |
| Reserved / Broadcast | `240.0.0.0/4`, `255.255.255.255/32`, `::/128` | RFC 1112 / RFC 919 | Broadcast and unassigned blocks |

### 2.4 IPv4-Mapped IPv6 Unwrapping
Attackers often attempt SSRF filter evasion by prefixing IPv4 addresses with IPv6 wrappers (e.g. `::ffff:169.254.169.254` or `::ffff:127.0.0.1`). The validator unwraps all IPv4-mapped and 6to4 addresses (`2002::/16`) back to canonical IPv4 representations before applying subnet checks.

### 2.5 Controlled Local Testing Exception
To enable developers to test against local vulnerable test targets (such as OWASP Juice Shop on `localhost:3000` or local test apps on `127.0.0.1`), loopback is permitted **only** when `scan_allow_loopback_for_testing=true` AND the hostname is explicitly present in `scan_allowed_hosts`. Cloud metadata addresses (`169.254.169.254`) and arbitrary internal subnets remain permanently blocked.

### 2.6 DNS Rebinding & Redirect Protection
* **Manual Redirect Handling**: The HTTP client disables automatic redirects (`follow_redirects=False`).
* **Per-Hop Scope & SSRF Validation**: Every redirect `Location` header is parsed, resolved, and checked against scope and SSRF filters.
* **Open Redirect Defense**: Redirects to arbitrary external hostnames or internal IP addresses trigger a `RedirectBlockedError`.
* **Max Redirect Depth**: Maximum 5 hops enforced to eliminate infinite redirect loops.

---

## 3. Part 2: HTTP Reconnaissance

Implemented in [`app/recon/http_recon.py`](file:///d:/projects/VULNDETECTOR/backend/app/recon/http_recon.py):
* **Status Code & Reason**: Captures response code (e.g. 200, 301, 403, 500) and phrase.
* **Server Banner**: Extracts `Server` header value.
* **Header Technologies**: Extracts runtime clues from `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`, `Via`, `CF-Ray`, `X-Varnish`.
* **Security Headers Audit**: Checks presence/absence of:
  * `Strict-Transport-Security` (HSTS)
  * `Content-Security-Policy` (CSP)
  * `X-Frame-Options` (Clickjacking defense)
  * `X-Content-Type-Options` (MIME sniffing defense)
  * `Referrer-Policy` (Referrer leakage control)
  * `Permissions-Policy` (Browser feature restriction)
* **Cookie Analysis**: Parses all `Set-Cookie` headers. Extracts `name`, `domain`, `path`, `secure`, `httponly`, `samesite`, and `expires`. Masks raw cookie values (`[REDACTED len=N]`) to prevent credential leakage.
* **Response Timing**: Accurately measures round-trip network latency in milliseconds.

---

## 4. Part 3: HTML Reconnaissance

Implemented in [`app/recon/html_recon.py`](file:///d:/projects/VULNDETECTOR/backend/app/recon/html_recon.py) using `BeautifulSoup4`:
* **Title & Meta Tags**: Extracts `<title>` and `<meta>` properties (including `generator`, `author`, `description`).
* **Links**: Gathers `<a href>` and `<area href>`, resolves relative links to absolute URLs, filters out `javascript:` and mailto links, and splits into internal and external sets.
* **Form & Input Extraction**:
  * Action URL and method (`GET`, `POST`, `PUT`, `DELETE`).
  * Enctype, file upload flags (`input type="file"`), and password field presence (`input type="password"`).
  * Field types (`text`, `hidden`, `email`, `number`, `select`, `textarea`), names, and `required` constraints.
* **Asset Discovery**: Gathers internal and CDN external script bundles (`<script src>`) and stylesheets (`<link rel="stylesheet">`).
* **Interesting Endpoint Heuristics**:
  * Regex extraction of API routes (`/api/...`, `/v1/...`, `/v2/...`, `/graphql`).
  * File paths (`.json`, `.xml`, `.php`, `.aspx`).
  * Sensitive keyword routes (`/auth/`, `/login`, `/admin`, `/dashboard`, `/users`).
  * HTML comment path references (`<!-- /test/endpoint -->`).
  * HTML5 `data-*` endpoint attributes (`data-url="/api/item"`).

---

## 5. Part 4: Safe Additional Discovery

Implemented in [`app/recon/discovery.py`](file:///d:/projects/VULNDETECTOR/backend/app/recon/discovery.py):
* **`robots.txt`**: Fetches and parses `Disallow:`, `Allow:`, and `Sitemap:` directives. Disallowed paths represent high-priority candidate endpoints for security auditing.
* **`sitemap.xml`**: Fetches XML sitemaps, safely parses `<loc>` entries, and extracts up to 25 target endpoints.
* **`security.txt`**: Checks RFC 9116 paths (`/.well-known/security.txt` and `/security.txt`) for security disclosure contacts and policies.
* **Technology Fingerprinting**: Correlates headers, cookies, scripts, meta tags, and DOM markers:
  * **Web Servers**: Apache, Nginx, Caddy, Microsoft-IIS, Uvicorn.
  * **CDNs / Proxies**: Cloudflare, AWS CloudFront, Varnish.
  * **Frameworks**: FastAPI, Express.js, Django, Flask, ASP.NET, PHP, Laravel, Spring.
  * **Frontend**: Next.js, React, Angular, Vue.js, jQuery, Bootstrap, Tailwind CSS.
  * **Test Labs**: OWASP Juice Shop, DVWA, WebGoat.

---

## 6. Part 5: PostgreSQL Storage

Implemented in [`app/recon/storage.py`](file:///d:/projects/VULNDETECTOR/backend/app/recon/storage.py):
* **Endpoint Persistence**: Discovered URLs are normalized and inserted into the `discovered_endpoints` table:
  * `id` (UUID PK)
  * `scan_id` (FK to `scan_sessions.id` ON DELETE CASCADE)
  * `target_id` (FK to `scan_targets.id` ON DELETE CASCADE)
  * `method` (HTTP verb, default `'GET'`)
  * `url` (full URL)
  * `url_hash` (SHA-256 hash for PostgreSQL unique index deduplication)
  * `path` (URL path)
  * `status_code` (verified HTTP status or NULL)
  * `content_type` (MIME type or NULL)
  * `discovered_at` (TIMESTAMPTZ)
* **Deduplication**: Uses `uq_discovered_endpoints_scan_method_url` on `(scan_id, method, url_hash)`.
* **Audit Trail**: Records an append-only `AuditLog` row with `action="recon.completed"` containing detailed JSON metadata.

---

## 7. Verification & Test Suite

The test suite in [`backend/tests/test_recon.py`](file:///d:/projects/VULNDETECTOR/backend/tests/test_recon.py) verifies the entire reconnaissance pipeline:

```powershell
backend\.venv\Scripts\pytest.exe backend/tests/test_recon.py -v
```

```text
backend\tests\test_recon.py::test_target_syntax_validation PASSED        [  7%]
backend\tests\test_recon.py::test_ssrf_blocks_private_and_reserved_ips PASSED [ 14%]
backend\tests\test_recon.py::test_ssrf_blocks_cloud_metadata_ips PASSED  [ 21%]
backend\tests\test_recon.py::test_ssrf_unwraps_ipv4_mapped_ipv6 PASSED   [ 28%]
backend\tests\test_recon.py::test_ssrf_loopback_handling PASSED          [ 35%]
backend\tests\test_recon.py::test_redirect_validation_blocks_out_of_scope_and_ssrf PASSED [ 42%]
backend\tests\test_recon.py::test_security_headers_analysis PASSED       [ 50%]
backend\tests\test_recon.py::test_header_technologies_detection PASSED   [ 57%]
backend\tests\test_recon.py::test_html_recon_parsing PASSED              [ 64%]
backend\tests\test_recon.py::test_technology_correlation PASSED          [ 71%]
backend\tests\test_recon.py::test_url_hash_computation PASSED            [ 78%]
backend\tests\test_recon.py::test_api_validate_target_endpoint PASSED    [ 85%]
backend\tests\test_recon.py::test_robots_and_sitemap_parsing PASSED      [ 92%]
backend\tests\test_recon.py::test_endpoints_api_retrieval_and_filtering PASSED [100%]

============================= 14 passed in 19.83s =============================
```
