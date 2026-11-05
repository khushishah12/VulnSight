"""Comprehensive Remediation Center Knowledgebase for OWASP Top 10:2025.

Provides multi-framework remediation guidance (Node.js/Express, Python/FastAPI,
Python/Django, Java/Spring Boot, SQL) without making premature assumptions about
the target application's technology stack.
"""

from __future__ import annotations

from app.remediation.models import (
    CodeSnippet,
    FixVerificationCriteria,
    FrameworkGuidance,
    RemediationGuide,
)

# Registry of comprehensive guides indexed by check ID prefix
_KNOWLEDGEBASE: dict[str, RemediationGuide] = {}


def _register(guide: RemediationGuide) -> None:
    _KNOWLEDGEBASE[guide.check_id] = guide


# ---------------------------------------------------------------------------
# A01: Broken Access Control
# ---------------------------------------------------------------------------
_register(
    RemediationGuide(
        check_id="A01-ADMIN-EXPOSED",
        owasp_category="A01",
        title="Unauthenticated Administrative Interface Exposure",
        vulnerability_meaning=(
            "Privileged administrative dashboards or control routes can be accessed "
            "directly without authenticating or possessing appropriate role authorizations."
        ),
        why_it_occurs=(
            "Developers rely on 'security through obscurity' by hiding administrative links "
            "in the frontend UI rather than enforcing server-side role checks on every route."
        ),
        internal_workings=(
            "The web server or API router maps the incoming URI directly to the administrative "
            "handler without routing through an authentication or role-validation middleware."
        ),
        safe_exploitation_scenario=(
            "An unauthenticated attacker enters '/admin' or '/api/admin/users' directly in the "
            "browser. The server responds with 200 OK and returns sensitive user management controls."
        ),
        business_impact=(
            "Unauthorized viewing or alteration of customer records, administrative account "
            "takeover, regulatory compliance violations (GDPR, HIPAA, PCI-DSS)."
        ),
        root_cause="Missing server-side authorization enforcement on administrative route handlers.",
        step_by_step_remediation=[
            "1. Deny access by default across all routing endpoints.",
            "2. Implement role-based access control (RBAC) middleware verifying user session and roles.",
            "3. Enforce multi-factor authentication (MFA) on all administrative functionality.",
            "4. Return HTTP 401 Unauthorized (if unauthenticated) or HTTP 403 Forbidden (if unauthorized).",
            "5. Ensure routing unit and integration tests assert 401/403 for anonymous requests.",
        ],
        code_examples={
            "nodejs_express": CodeSnippet(
                stack_name="Node.js / Express",
                vulnerable_code=(
                    "// Vulnerable: Direct route handler without authorization middleware\n"
                    "app.get('/api/admin/users', async (req, res) => {\n"
                    "    const users = await db.getAllUsers();\n"
                    "    res.json(users);\n"
                    "});"
                ),
                secure_code=(
                    "// Secure: Require authentication and verified admin role\n"
                    "const { requireAuth, requireRole } = require('./middleware/auth');\n\n"
                    "app.get('/api/admin/users', requireAuth, requireRole('admin'), async (req, res) => {\n"
                    "    const users = await db.getAllUsers();\n"
                    "    res.json(users);\n"
                    "});"
                ),
                explanation="Enforce authentication and role validation middleware before executing the handler.",
            ),
            "python_fastapi": CodeSnippet(
                stack_name="Python / FastAPI",
                vulnerable_code=(
                    "# Vulnerable: Unprotected endpoint\n"
                    "@router.get('/api/admin/users')\n"
                    "async def list_admin_users():\n"
                    "    return await get_all_users()"
                ),
                secure_code=(
                    "# Secure: Depends on current authenticated admin user\n"
                    "from fastapi import Depends, HTTPException, status\n"
                    "from app.auth.deps import get_current_admin_user\n\n"
                    "@router.get('/api/admin/users')\n"
                    "async def list_admin_users(admin: User = Depends(get_current_admin_user)):\n"
                    "    return await get_all_users()"
                ),
                explanation="Use FastAPI Dependency Injection to validate JWT token and assert user.role == 'admin'.",
            ),
            "python_django": CodeSnippet(
                stack_name="Python / Django",
                vulnerable_code=(
                    "# Vulnerable: Standard function view without decorators\n"
                    "def admin_dashboard(request):\n"
                    "    return render(request, 'admin_panel.html')"
                ),
                secure_code=(
                    "# Secure: Enforce login and staff/superuser permissions\n"
                    "from django.contrib.auth.decorators import user_passes_test\n\n"
                    "@user_passes_test(lambda u: u.is_authenticated and u.is_superuser)\n"
                    "def admin_dashboard(request):\n"
                    "    return render(request, 'admin_panel.html')"
                ),
                explanation="Decorate views with permission tests to enforce authentication and superuser status.",
            ),
            "java_spring": CodeSnippet(
                stack_name="Java / Spring Boot",
                vulnerable_code=(
                    "// Vulnerable: Spring Security config permitAll on /admin\n"
                    "http.authorizeHttpRequests(auth -> auth\n"
                    "    .requestMatchers(\"/admin/**\").permitAll()\n"
                    ");"
                ),
                secure_code=(
                    "// Secure: Require ROLE_ADMIN for /admin endpoints\n"
                    "http.authorizeHttpRequests(auth -> auth\n"
                    "    .requestMatchers(\"/admin/**\").hasRole(\"ADMIN\")\n"
                    "    .anyRequest().authenticated()\n"
                    ");"
                ),
                explanation="Configure Spring Security filter chain to require 'ADMIN' authority for administrative URIs.",
            ),
        },
        framework_guidance={
            "express": FrameworkGuidance(
                framework_name="Express",
                recommendations=["Centralize RBAC in a reusable middleware function", "Use passport.js or JWT verification."],
            ),
            "fastapi": FrameworkGuidance(
                framework_name="FastAPI",
                recommendations=["Create reusable `Security(get_current_active_admin)` dependency."],
            ),
            "spring": FrameworkGuidance(
                framework_name="Spring Security",
                recommendations=["Use `@PreAuthorize(\"hasRole('ADMIN')\")` on service and controller methods."],
            ),
        },
        fix_verification=FixVerificationCriteria(
            what_should_change="Unauthenticated requests to the endpoint should return HTTP 401 Unauthorized or 403 Forbidden instead of 200 OK.",
            check_to_rerun="Issue an unauthenticated GET request to the administrative path.",
            expected_evidence="HTTP status code 401 or 403 with standard WWW-Authenticate challenge or error JSON.",
            inconclusive_conditions="Target server is down, firewall blocks scanner IP, or server returns 502/504 gateway errors.",
        ),
        references=[
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html",
        ],
    )
)

_register(
    RemediationGuide(
        check_id="A01-METHOD-TAMPER",
        owasp_category="A01",
        title="HTTP Verb / Method Tampering Access Control Bypass",
        vulnerability_meaning="Restricted routes can be queried or bypassed by altering the HTTP method (e.g., HEAD, OPTIONS, POST).",
        why_it_occurs="Access control rules or security constraints are bound exclusively to specific HTTP methods (e.g., GET) rather than the URI.",
        internal_workings="The web server filter blocks 'GET /admin' but permits 'OPTIONS' or 'HEAD', leaking headers or bypassing authorization entirely.",
        safe_exploitation_scenario="An attacker sends 'HEAD /admin' or 'OPTIONS /admin' and receives full response headers revealing administrative state.",
        business_impact="Information disclosure and potential bypass of web application firewalls (WAFs).",
        root_cause="HTTP method-specific security rule bindings in route filters.",
        step_by_step_remediation=[
            "1. Apply security constraints to resource URIs regardless of HTTP method.",
            "2. Disable unused HTTP methods (e.g., TRACE, TRACK).",
            "3. Enforce uniform authentication middleware across all verb handlers.",
        ],
        code_examples={
            "nodejs_express": CodeSnippet(
                stack_name="Node.js / Express",
                vulnerable_code="app.get('/protected', requireAuth, handler);\napp.all('/protected', handler); // unprotected for other verbs",
                secure_code="app.use('/protected', requireAuth);\napp.get('/protected', handler);",
                explanation="Mount authorization middleware at the path level using app.use() so it applies to all HTTP verbs.",
            ),
            "python_fastapi": CodeSnippet(
                stack_name="Python / FastAPI",
                vulnerable_code="@app.get('/protected', dependencies=[Depends(auth)])\n# other verbs left unprotected",
                secure_code="router = APIRouter(prefix='/protected', dependencies=[Depends(auth)])\n@router.get('')\nasync def h(): ...",
                explanation="Bind security dependencies at the APIRouter level to cover all included endpoints.",
            ),
        },
        framework_guidance={},
        fix_verification=FixVerificationCriteria(
            what_should_change="Non-GET verbs (OPTIONS, HEAD) on protected endpoints should require authentication or return 405 Method Not Allowed.",
            check_to_rerun="Send OPTIONS and HEAD requests to the protected endpoint.",
            expected_evidence="HTTP status 401, 403, or 405.",
            inconclusive_conditions="Proxy intercepts and strips unsupported verbs before reaching backend.",
        ),
        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"],
    )
)

# ---------------------------------------------------------------------------
# A02: Security Misconfiguration
# ---------------------------------------------------------------------------
_register(
    RemediationGuide(
        check_id="A02-SECURITY-HEADERS",
        owasp_category="A02",
        title="Missing Defensive HTTP Security Headers",
        vulnerability_meaning="The web server omits defensive headers that instruct browsers how to handle content safely.",
        why_it_occurs="Default web server or framework configurations do not enable security headers out of the box.",
        internal_workings="Without Content-Security-Policy, X-Frame-Options, or X-Content-Type-Options, browsers execute untrusted scripts, render inside iframes, and perform MIME-type sniffing.",
        safe_exploitation_scenario="A malicious third party embeds the web application inside an invisible <iframe> on an attacker-controlled site to conduct clickjacking.",
        business_impact="Susceptibility to cross-site scripting (XSS), clickjacking, drive-by downloads, and protocol downgrade attacks.",
        root_cause="Absence of security header middleware or reverse proxy header directives.",
        step_by_step_remediation=[
            "1. Configure Content-Security-Policy (CSP) to restrict script and object execution sources.",
            "2. Set X-Frame-Options: DENY (or SAMEORIGIN) to prevent clickjacking.",
            "3. Set X-Content-Type-Options: nosniff to disable MIME sniffing.",
            "4. Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload on HTTPS.",
            "5. Set Permissions-Policy: camera=(), microphone=(), geolocation=() to restrict browser APIs.",
        ],
        code_examples={
            "nodejs_express": CodeSnippet(
                stack_name="Node.js / Express",
                vulnerable_code="// Vulnerable: Standard express without header hardening\nconst app = express();",
                secure_code=(
                    "// Secure: Use helmet middleware to set all security headers\n"
                    "const helmet = require('helmet');\n"
                    "const app = express();\n"
                    "app.use(helmet());\n"
                    "app.use(helmet.contentSecurityPolicy({\n"
                    "    directives: { defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\"] }\n"
                    "}));"
                ),
                explanation="The 'helmet' package sets Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and HSTS automatically.",
            ),
            "python_fastapi": CodeSnippet(
                stack_name="Python / FastAPI",
                vulnerable_code="# Vulnerable: Default FastAPI application\napp = FastAPI()",
                secure_code=(
                    "# Secure: Custom ASGI middleware setting security headers\n"
                    "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
                    "class SecurityHeadersMiddleware(BaseHTTPMiddleware):\n"
                    "    async def dispatch(self, request, call_next):\n"
                    "        response = await call_next(request)\n"
                    "        response.headers['X-Content-Type-Options'] = 'nosniff'\n"
                    "        response.headers['X-Frame-Options'] = 'DENY'\n"
                    "        response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
                    "        return response\n\n"
                    "app.add_middleware(SecurityHeadersMiddleware)"
                ),
                explanation="Add a middleware in FastAPI that injects security headers into every outgoing response.",
            ),
            "python_django": CodeSnippet(
                stack_name="Python / Django",
                vulnerable_code="# Vulnerable: Default settings.py with security middleware commented out",
                secure_code=(
                    "# Secure: Enable Django built-in security middleware in settings.py\n"
                    "MIDDLEWARE = [\n"
                    "    'django.middleware.security.SecurityMiddleware',\n"
                    "    'django.middleware.clickjacking.XFrameOptionsMiddleware',\n"
                    "    ...\n"
                    "]\n"
                    "SECURE_BROWSER_XSS_FILTER = True\n"
                    "SECURE_CONTENT_TYPE_NOSNIFF = True\n"
                    "X_FRAME_OPTIONS = 'DENY'\n"
                    "SECURE_HSTS_SECONDS = 31536000\n"
                    "SECURE_HSTS_INCLUDE_SUBDOMAINS = True"
                ),
                explanation="Configure Django's SecurityMiddleware flags in settings.py.",
            ),
            "java_spring": CodeSnippet(
                stack_name="Java / Spring Boot",
                vulnerable_code="http.headers(headers -> headers.disable()); // headers disabled",
                secure_code=(
                    "// Secure: Spring Security default headers configuration\n"
                    "http.headers(headers -> headers\n"
                    "    .frameOptions(frame -> frame.deny())\n"
                    "    .contentTypeOptions(Customizer.withDefaults())\n"
                    "    .contentSecurityPolicy(csp -> csp.policyDirectives(\"default-src 'self'\"))\n"
                    ");"
                ),
                explanation="Spring Security enables secure headers by default; verify they are not explicitly disabled.",
            ),
        },
        framework_guidance={
            "express": FrameworkGuidance(
                framework_name="Express",
                recommendations=["Install and mount `helmet` at the top of your middleware stack."],
            ),
            "nginx": FrameworkGuidance(
                framework_name="Nginx",
                recommendations=["Add `add_header X-Frame-Options DENY always;` in server block."],
                config_snippet="add_header X-Content-Type-Options nosniff always;\nadd_header X-Frame-Options DENY always;\nadd_header Content-Security-Policy \"default-src 'self'\" always;",
            ),
        },
        fix_verification=FixVerificationCriteria(
            what_should_change="Response headers should include Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options.",
            check_to_rerun="Send a HEAD or GET request and inspect response headers.",
            expected_evidence="X-Content-Type-Options: nosniff and X-Frame-Options: DENY present in response headers.",
            inconclusive_conditions="CDN or caching proxy serves stale headers prior to cache purge.",
        ),
        references=["https://owasp.org/www-project-secure-headers/"],
    )
)

_register(
    RemediationGuide(
        check_id="A02-CONFIG-EXPOSED",
        owasp_category="A02",
        title="Publicly Accessible Environment / Version Control Files",
        vulnerability_meaning="Sensitive configuration files such as .env, .git/config, or web.config are publicly downloadable.",
        why_it_occurs="Web servers are configured to serve files directly from the project root instead of an isolated public/dist directory.",
        internal_workings="The web server matches requests for '/.env' to the local filesystem and streams the text file without restriction.",
        safe_exploitation_scenario="An attacker downloads '/.env' and reads live database connection strings, JWT secret keys, and third-party API credentials.",
        business_impact="Total application compromise, database theft, unauthorized cloud access via exposed cloud secrets.",
        root_cause="Web server document root set to repository root; absence of dotfile blocking rules.",
        step_by_step_remediation=[
            "1. Immediately rotate all secrets, database credentials, and API keys present in the exposed file.",
            "2. Set the web server document root strictly to the public directory (e.g., `dist/`, `public/`, `build/`).",
            "3. Block all requests containing dotfiles (`.*`) in Nginx, Apache, or web server configurations.",
            "4. Add `.env`, `.git`, and sensitive files to `.gitignore` and `.dockerignore`.",
        ],
        code_examples={
            "nginx": CodeSnippet(
                stack_name="Nginx Configuration",
                vulnerable_code="# Vulnerable: No dotfile protection\nlocation / { try_files $uri $uri/ /index.html; }",
                secure_code="# Secure: Deny all dotfiles (.git, .env)\nlocation ~ /\\.(?!well-known) { deny all; return 404; }",
                explanation="Configure Nginx to return 404 for any path starting with a dot.",
            ),
            "nodejs_express": CodeSnippet(
                stack_name="Node.js / Express",
                vulnerable_code="// Vulnerable: Serving root project folder as static\napp.use(express.static(__dirname));",
                secure_code="// Secure: Only serve isolated public directory\nconst path = require('path');\napp.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'ignore' }));",
                explanation="Set dotfiles: 'ignore' and restrict static assets to a dedicated public folder.",
            ),
        },
        framework_guidance={},
        fix_verification=FixVerificationCriteria(
            what_should_change="Requests to /.env or /.git/config must return HTTP 404 Not Found or 403 Forbidden.",
            check_to_rerun="Send a GET request to /.env and /.git/config.",
            expected_evidence="HTTP status 404 Not Found without configuration content.",
            inconclusive_conditions="Application returns a generic 200 OK SPA fallback page.",
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html"],
    )
)

# ---------------------------------------------------------------------------
# A04: Cryptographic Failures
# ---------------------------------------------------------------------------
_register(
    RemediationGuide(
        check_id="A04-CLEARTEXT-HTTP",
        owasp_category="A04",
        title="Unencrypted Cleartext HTTP Transport",
        vulnerability_meaning="The web application is accessible over unencrypted HTTP without mandatory redirect to HTTPS.",
        why_it_occurs="Missing TLS termination or lack of automatic HTTP-to-HTTPS redirect rules.",
        internal_workings="Traffic between client and server travels in unencrypted plaintext across routers and ISPs.",
        safe_exploitation_scenario="An attacker on an open network eavesdrops on unencrypted network packets and reads cookies and POST bodies.",
        business_impact="Eavesdropping, session hijacking, violation of privacy laws (GDPR) and payment security standards (PCI-DSS).",
        root_cause="Failure to enforce HTTPS and absence of HSTS.",
        step_by_step_remediation=[
            "1. Obtain a valid TLS certificate (e.g., via Let's Encrypt).",
            "2. Configure the web server / reverse proxy to redirect all port 80 (HTTP) traffic to port 443 (HTTPS) with status 301.",
            "3. Enable HTTP Strict Transport Security (HSTS) with max-age=31536000 and includeSubDomains.",
        ],
        code_examples={
            "nginx": CodeSnippet(
                stack_name="Nginx Configuration",
                vulnerable_code="server { listen 80; server_name example.com; # serves traffic on 80 }",
                secure_code="server {\n    listen 80;\n    server_name example.com;\n    return 301 https://$host$request_uri;\n}",
                explanation="Always return a 301 permanent redirect to HTTPS for all port 80 traffic.",
            ),
            "python_fastapi": CodeSnippet(
                stack_name="Python / FastAPI",
                vulnerable_code="# Vulnerable: Running uvicorn directly on HTTP without TLS",
                secure_code=(
                    "# Secure: Enforce HTTPS redirect middleware\n"
                    "from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware\n"
                    "app.add_middleware(HTTPSRedirectMiddleware)"
                ),
                explanation="Starlette's HTTPSRedirectMiddleware enforces 301 redirects to HTTPS.",
            ),
        },
        framework_guidance={},
        fix_verification=FixVerificationCriteria(
            what_should_change="HTTP requests should return a 301 Moved Permanently redirect pointing to https://.",
            check_to_rerun="Send a GET request to http://<target>/ and inspect redirect.",
            expected_evidence="HTTP status 301 with Location header starting with https://.",
            inconclusive_conditions="Load balancer strips redirect or testing is performed inside a local container.",
        ),
        references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
    )
)

# ---------------------------------------------------------------------------
# A05: Injection
# ---------------------------------------------------------------------------
_register(
    RemediationGuide(
        check_id="A05-REFLECTED-XSS",
        owasp_category="A05",
        title="Reflected Cross-Site Scripting (XSS)",
        vulnerability_meaning="Untrusted input from the HTTP request is reflected directly into the HTML response without contextual encoding.",
        why_it_occurs="Interpolating raw user input directly into HTML templates, bypassing framework auto-escaping.",
        internal_workings="The browser parses unescaped HTML characters (<, >, \", ') as markup, allowing attacker-controlled JavaScript to execute.",
        safe_exploitation_scenario=(
            "An attacker crafts a URL with a benign canary payload '?q=test<safe_tag>'. "
            "The application renders the tag verbatim without encoding to '&lt;safe_tag&gt;'."
        ),
        business_impact="Account hijacking via session cookie theft, credential theft via phishing overlays, malicious actions performed on behalf of victim.",
        root_cause="Missing contextual output encoding on user-controlled input rendered in HTML.",
        step_by_step_remediation=[
            "1. Use modern template engines (Jinja2, Thymeleaf, React, Angular) that auto-escape by default.",
            "2. Never disable auto-escaping (e.g., avoid `dangerouslySetInnerHTML`, `| safe`, `th:utext`).",
            "3. Apply contextual encoding (HTML entity, JavaScript attribute, URI component).",
            "4. Enforce a restrictive Content-Security-Policy (CSP) that disables unsafe inline scripts.",
        ],
        code_examples={
            "nodejs_express": CodeSnippet(
                stack_name="Node.js / Express",
                vulnerable_code=(
                    "// Vulnerable: Directly concatenating query param into HTML\n"
                    "app.get('/search', (req, res) => {\n"
                    "    res.send(`<h1>Results for: ${req.query.q}</h1>`);\n"
                    "});"
                ),
                secure_code=(
                    "// Secure: Use contextual escaping library or template engine\n"
                    "const escapeHtml = require('escape-html');\n"
                    "app.get('/search', (req, res) => {\n"
                    "    res.send(`<h1>Results for: ${escapeHtml(req.query.q)}</h1>`);\n"
                    "});"
                ),
                explanation="Always escape user inputs with escape-html before inserting them into dynamic HTML templates.",
            ),
            "python_fastapi": CodeSnippet(
                stack_name="Python / FastAPI",
                vulnerable_code=(
                    "# Vulnerable: Raw string formatting in HTMLResponse\n"
                    "@app.get('/search', response_class=HTMLResponse)\n"
                    "def search(q: str):\n"
                    "    return f'<h1>Search for: {q}</h1>'"
                ),
                secure_code=(
                    "# Secure: Use html.escape or Jinja2 template auto-escaping\n"
                    "import html\n"
                    "@app.get('/search', response_class=HTMLResponse)\n"
                    "def search(q: str):\n"
                    "    return f'<h1>Search for: {html.escape(q)}</h1>'"
                ),
                explanation="Use Python's standard html.escape() or Jinja2 templates which auto-escape by default.",
            ),
            "python_django": CodeSnippet(
                stack_name="Python / Django",
                vulnerable_code="# Vulnerable: Marking user input safe in template\n{{ search_term|safe }}",
                secure_code="# Secure: Let Django auto-escape template variables\n{{ search_term }}",
                explanation="Never apply the '|safe' filter to user-provided data in Django templates.",
            ),
            "java_spring": CodeSnippet(
                stack_name="Java / Spring Boot",
                vulnerable_code="<!-- Vulnerable: Thymeleaf unescaped text -->\n<span th:utext=\"${param.q}\"></span>",
                secure_code="<!-- Secure: Thymeleaf escaped text -->\n<span th:text=\"${param.q}\"></span>",
                explanation="Use th:text instead of th:utext to ensure Thymeleaf applies HTML entity encoding.",
            ),
        },
        framework_guidance={
            "react": FrameworkGuidance(
                framework_name="React",
                recommendations=["JSX escapes values automatically", "Never use `dangerouslySetInnerHTML` with user input."],
            ),
        },
        fix_verification=FixVerificationCriteria(
            what_should_change="Canary tags such as '<safe_tag>' must be reflected as '&lt;safe_tag&gt;' or stripped entirely.",
            check_to_rerun="Submit a benign query string containing '<safe_tag_test>' and inspect the response body.",
            expected_evidence="Output encoded as '&lt;safe_tag_test&gt;' or HTTP 400 Bad Request.",
            inconclusive_conditions="Application returns JSON or redirects before rendering HTML.",
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    )
)

_register(
    RemediationGuide(
        check_id="A05-SQL-SYNTAX-ERROR",
        owasp_category="A05",
        title="SQL Injection / Database Syntax Error Leakage",
        vulnerability_meaning="Database error messages are leaked to clients, indicating improper input sanitization in SQL queries.",
        why_it_occurs="Building SQL queries via string formatting or concatenation rather than parameterized prepared statements.",
        internal_workings="Special SQL characters (e.g., single quotes) escape the data literal and alter the structure of the SQL command.",
        safe_exploitation_scenario="Sending a single quote (') produces an internal SQL syntax error from the database engine.",
        business_impact="Unauthorized data extraction, complete database alteration or destruction, authentication bypass.",
        root_cause="Dynamic SQL string construction without parameterized queries.",
        step_by_step_remediation=[
            "1. Always use parameterized queries (prepared statements) or an ORM (SQLAlchemy, Prisma, Hibernate).",
            "2. Never concatenate or interpolate user input directly into SQL strings.",
            "3. Disable detailed database error disclosure in production; return generic error messages.",
            "4. Enforce least-privilege database user permissions.",
        ],
        code_examples={
            "sql": CodeSnippet(
                stack_name="SQL Prepared Statements",
                vulnerable_code="-- Vulnerable: String concatenation\nSELECT * FROM users WHERE email = '\" + email + \"';",
                secure_code="-- Secure: Parameterized prepared statement\nSELECT * FROM users WHERE email = $1;",
                explanation="Use numbered ($1) or named (:email) placeholders so the database driver separates SQL code from data.",
            ),
            "python_fastapi": CodeSnippet(
                stack_name="Python / SQLAlchemy",
                vulnerable_code=(
                    "# Vulnerable: Raw string interpolation in text query\n"
                    "await session.execute(text(f'SELECT * FROM users WHERE email = {email}'))"
                ),
                secure_code=(
                    "# Secure: Parameterized text query or SQLAlchemy select()\n"
                    "await session.execute(\n"
                    "    select(User).where(User.email == email)\n"
                    ")"
                ),
                explanation="Use SQLAlchemy ORM queries or pass parameters as a dictionary to text() to ensure proper binding.",
            ),
            "nodejs_express": CodeSnippet(
                stack_name="Node.js / pg",
                vulnerable_code="const res = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
                secure_code="const res = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);",
                explanation="Pass parameters in the second argument array to pg.query() to leverage prepared statements.",
            ),
            "java_spring": CodeSnippet(
                stack_name="Java / Spring Data JPA",
                vulnerable_code="String sql = \"SELECT * FROM users WHERE email = '\" + email + \"'\"; // vulnerable",
                secure_code="@Query(\"SELECT u FROM User u WHERE u.email = :email\")\nUser findByEmail(@Param(\"email\") String email);",
                explanation="Use Spring Data JPA named query parameters (@Param) which automatically parameterize queries.",
            ),
        },
        framework_guidance={},
        fix_verification=FixVerificationCriteria(
            what_should_change="Probing with a single quote must not return database error syntax strings; it should return 400 or empty results.",
            check_to_rerun="Submit a benign single quote in the query parameter and inspect response.",
            expected_evidence="No database engine error strings (e.g., 'syntax error', 'psycopg2', 'ORA-') in response.",
            inconclusive_conditions="Application implements WAF that blocks single quotes at network perimeter.",
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    )
)

# ---------------------------------------------------------------------------
# A06: Insecure Design
# ---------------------------------------------------------------------------
_register(
    RemediationGuide(
        check_id="A06-CSRF-FORM",
        owasp_category="A06",
        title="Missing Cross-Site Request Forgery (CSRF) Protection",
        vulnerability_meaning="State-changing HTML forms lack unique anti-CSRF tokens, allowing malicious sites to submit requests on behalf of users.",
        why_it_occurs="Forms do not include a cryptographically random, unpredictable token that is validated on form submission.",
        internal_workings="Browsers automatically attach cookies (including session cookies) on cross-origin form submissions unless SameSite=Strict is set.",
        safe_exploitation_scenario="A malicious third-party site submits a hidden form targeting '/account/update' while the victim is logged in.",
        business_impact="Unauthorized state changes: password changes, email address updates, fund transfers, or unauthorized orders.",
        root_cause="Missing anti-CSRF token verification and failure to enforce SameSite=Lax/Strict cookie policies.",
        step_by_step_remediation=[
            "1. Include a cryptographically strong anti-CSRF token in all state-changing HTML forms.",
            "2. Verify the anti-CSRF token on the server before processing POST/PUT/DELETE requests.",
            "3. Set `SameSite=Lax` or `SameSite=Strict` on session cookies.",
            "4. For APIs, require custom headers (e.g., `X-Requested-With`) or `Authorization: Bearer` tokens.",
        ],
        code_examples={
            "python_fastapi": CodeSnippet(
                stack_name="Python / FastAPI",
                vulnerable_code="# Vulnerable: HTML form endpoint without CSRF protection",
                secure_code=(
                    "# Secure: Use fastapi-csrf-protect or session-backed CSRF tokens\n"
                    "from fastapi_csrf_protect import CsrfProtect\n\n"
                    "@app.post('/transfer')\n"
                    "async def transfer(request: Request, csrf_protect: CsrfProtect = Depends()):\n"
                    "    await csrf_protect.validate_csrf(request)\n"
                    "    ..."
                ),
                explanation="Validate CSRF token header or form field using CsrfProtect middleware.",
            ),
            "nodejs_express": CodeSnippet(
                stack_name="Node.js / Express",
                vulnerable_code="// Vulnerable: Direct POST handler without csurf middleware",
                secure_code=(
                    "// Secure: Use csurf or csurf-replacement csrf-csrf middleware\n"
                    "const { doubleCsrf } = require('csrf-csrf');\n"
                    "const { doubleCsrfProtection } = doubleCsrf({ ... });\n"
                    "app.post('/transfer', doubleCsrfProtection, (req, res) => { ... });"
                ),
                explanation="Use double-submit cookie CSRF protection middleware on all state-changing routes.",
            ),
            "python_django": CodeSnippet(
                stack_name="Python / Django",
                vulnerable_code="<!-- Vulnerable: Form without csrf_token tag -->\n<form method=\"post\"><input ...></form>",
                secure_code="<!-- Secure: Include {% csrf_token %} tag -->\n<form method=\"post\">{% csrf_token %}<input ...></form>",
                explanation="Django provides built-in CSRF middleware; always place {% csrf_token %} inside template forms.",
            ),
        },
        framework_guidance={},
        fix_verification=FixVerificationCriteria(
            what_should_change="All state-changing HTML forms must include a hidden input containing an anti-CSRF token.",
            check_to_rerun="Fetch the HTML page and inspect form inputs for CSRF tokens.",
            expected_evidence="Presence of `<input type=\"hidden\" name=\"csrf_token\" ...>` in form body.",
            inconclusive_conditions="Form submits via AJAX with client-side header tokens rather than standard form submission.",
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
    )
)

# ---------------------------------------------------------------------------
# A07: Authentication Failures
# ---------------------------------------------------------------------------
_register(
    RemediationGuide(
        check_id="A07-COOKIE-HTTPONLY",
        owasp_category="A07",
        title="Session Cookies Missing HttpOnly / SameSite Attributes",
        vulnerability_meaning="Session cookies can be read by JavaScript (missing HttpOnly) or sent on cross-origin requests (missing SameSite).",
        why_it_occurs="Cookie generation options omit `httpOnly: true` and `sameSite: 'lax'` flags.",
        internal_workings="When `HttpOnly` is omitted, `document.cookie` in a malicious script or via XSS has direct access to the session token.",
        safe_exploitation_scenario="If an XSS vulnerability occurs anywhere on the domain, an attacker reads `document.cookie` and steals the session.",
        business_impact="Complete session hijacking, user impersonation, account takeover.",
        root_cause="Insecure cookie issuance configuration in application or session middleware.",
        step_by_step_remediation=[
            "1. Set `HttpOnly=true` on all authentication and session cookies.",
            "2. Set `Secure=true` to ensure cookies are only transmitted over TLS/HTTPS.",
            "3. Set `SameSite=Lax` (or `Strict`) to mitigate cross-site request forgery.",
            "4. Set an explicit `Path` and reasonable `Max-Age` / `Expires` attribute.",
        ],
        code_examples={
            "nodejs_express": CodeSnippet(
                stack_name="Node.js / express-session",
                vulnerable_code="// Vulnerable: Default cookie settings\napp.use(session({ secret: 'secret' }));",
                secure_code=(
                    "// Secure: Explicitly configure cookie security flags\n"
                    "app.use(session({\n"
                    "    secret: process.env.SESSION_SECRET,\n"
                    "    cookie: {\n"
                    "        httpOnly: true,\n"
                    "        secure: true,\n"
                    "        sameSite: 'lax',\n"
                    "        maxAge: 24 * 60 * 60 * 1000\n"
                    "    }\n"
                    "}));"
                ),
                explanation="Always configure express-session cookie options with httpOnly: true, secure: true, and sameSite: 'lax'.",
            ),
            "python_fastapi": CodeSnippet(
                stack_name="Python / FastAPI",
                vulnerable_code="response.set_cookie(key='session_id', value=token)",
                secure_code=(
                    "response.set_cookie(\n"
                    "    key='session_id',\n"
                    "    value=token,\n"
                    "    httponly=True,\n"
                    "    secure=True,\n"
                    "    samesite='lax',\n"
                    "    max_age=86400\n"
                    ")"
                ),
                explanation="Pass httponly=True, secure=True, and samesite='lax' to FastAPI's response.set_cookie().",
            ),
        },
        framework_guidance={},
        fix_verification=FixVerificationCriteria(
            what_should_change="The Set-Cookie response header must contain '; HttpOnly; Secure; SameSite=Lax'.",
            check_to_rerun="Send a GET request to the login/session endpoint and inspect Set-Cookie headers.",
            expected_evidence="Set-Cookie header includes HttpOnly and SameSite directives.",
            inconclusive_conditions="Endpoint does not issue cookies on anonymous requests.",
        ),
        references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
    )
)

# ---------------------------------------------------------------------------
# A08: Software and Data Integrity Failures
# ---------------------------------------------------------------------------
_register(
    RemediationGuide(
        check_id="A08-MISSING-SRI",
        owasp_category="A08",
        title="Third-Party Scripts Missing Subresource Integrity (SRI)",
        vulnerability_meaning="External scripts from third-party CDNs are loaded without cryptographic hashes to verify their integrity.",
        why_it_occurs="Developers copy standard CDN script tags without generating and including the `integrity` attribute.",
        internal_workings="If the third-party CDN is compromised or DNS is spoofed, the browser executes the modified script without warning.",
        safe_exploitation_scenario="A compromised CDN delivers tampered JavaScript that logs keystrokes or exfiltrates user session tokens.",
        business_impact="Supply chain compromise, script tampering, user data exfiltration.",
        root_cause="Omitting the `integrity` hash attribute on external `<script>` and `<link>` tags.",
        step_by_step_remediation=[
            "1. Generate a cryptographic hash of the external resource (e.g., `openssl dgst -sha384 -binary file.js | openssl base64 -A`).",
            "2. Add `integrity=\"sha384-...\"` and `crossorigin=\"anonymous\"` to every external `<script>` tag.",
            "3. Alternatively, host third-party dependencies locally from your own origin.",
        ],
        code_examples={
            "html": CodeSnippet(
                stack_name="HTML5 Markup",
                vulnerable_code="<!-- Vulnerable: Loading CDN script without SRI -->\n<script src=\"https://cdn.example.com/lib.js\"></script>",
                secure_code=(
                    "<!-- Secure: Including cryptographic SRI hash and crossorigin -->\n"
                    "<script src=\"https://cdn.example.com/lib.js\"\n"
                    "        integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\"\n"
                    "        crossorigin=\"anonymous\"></script>"
                ),
                explanation="The browser validates the cryptographic hash before executing the external script.",
            ),
        },
        framework_guidance={},
        fix_verification=FixVerificationCriteria(
            what_should_change="External script elements must contain valid integrity='sha384-...' attributes.",
            check_to_rerun="Fetch the HTML page and parse `<script>` tags.",
            expected_evidence="Every third-party script tag includes an integrity attribute.",
            inconclusive_conditions="Scripts are loaded dynamically via JavaScript loader rather than HTML tags.",
        ),
        references=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
    )
)

# ---------------------------------------------------------------------------
# A10: Exceptional Conditions
# ---------------------------------------------------------------------------
_register(
    RemediationGuide(
        check_id="A10-STACK-TRACE",
        owasp_category="A10",
        title="Verbose Runtime Stack Trace Disclosure",
        vulnerability_meaning="The application leaks detailed runtime stack traces, code snippets, or framework debug screens to clients.",
        why_it_occurs="Debug mode is enabled in production or exceptions are unhandled by a generic error boundary.",
        internal_workings="When an unhandled exception occurs, the default framework error handler formats the full traceback and sends it in the response.",
        safe_exploitation_scenario="Triggering an invalid path or malformed parameter causes a 500 error showing internal file paths and framework versions.",
        business_impact="Intelligence leakage to attackers regarding internal code structures, library versions, and database schemas.",
        root_cause="Debug flags enabled in production and missing centralized exception-handling middleware.",
        step_by_step_remediation=[
            "1. Disable debug mode in production (e.g., `DEBUG = False` in Django, `NODE_ENV=production` in Node).",
            "2. Implement a global exception handler that catches unhandled errors and returns a generic error message.",
            "3. Log the detailed stack trace to secure server-side logging systems instead of the client response.",
        ],
        code_examples={
            "python_fastapi": CodeSnippet(
                stack_name="Python / FastAPI",
                vulnerable_code="# Vulnerable: Letting unhandled exceptions bubble to client in debug mode",
                secure_code=(
                    "# Secure: Centralized exception handler returning generic error\n"
                    "from fastapi.responses import JSONResponse\n\n"
                    "@app.exception_handler(Exception)\n"
                    "async def global_exception_handler(request: Request, exc: Exception):\n"
                    "    logger.exception('Unhandled exception occurred: %s', exc)\n"
                    "    return JSONResponse(\n"
                    "        status_code=500,\n"
                    "        content={'error': 'InternalServerError', 'message': 'An unexpected error occurred.'}\n"
                    "    )"
                ),
                explanation="Catch general exceptions globally and log them securely while returning generic messages.",
            ),
            "nodejs_express": CodeSnippet(
                stack_name="Node.js / Express",
                vulnerable_code="// Vulnerable: Default express error handler printing err.stack in dev",
                secure_code=(
                    "// Secure: Production error middleware\n"
                    "app.use((err, req, res, next) => {\n"
                    "    logger.error(err.stack);\n"
                    "    res.status(500).json({ error: 'Internal Server Error' });\n"
                    "});"
                ),
                explanation="Custom Express 4-argument error handler that logs the stack internally and sends a sanitized response.",
            ),
        },
        framework_guidance={},
        fix_verification=FixVerificationCriteria(
            what_should_change="Triggering errors must return generic error messages (e.g., HTTP 500 JSON) without call stacks.",
            check_to_rerun="Submit malformed input and verify response body.",
            expected_evidence="Absence of 'Traceback (most recent call last)', 'NullPointerException', or file paths in response.",
            inconclusive_conditions="Endpoint does not throw error on the test input.",
        ),
        references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
    )
)


def get_remediation_guide(
    check_id: str,
    *,
    owasp_category: str | None = None,
) -> RemediationGuide | None:
    """Retrieve comprehensive remediation guidance for a check ID or category."""
    # 1. Exact match
    if check_id in _KNOWLEDGEBASE:
        return _KNOWLEDGEBASE[check_id]

    # 2. Check prefix match (e.g., A01-ADMIN matches A01-ADMIN-EXPOSED)
    for key, guide in _KNOWLEDGEBASE.items():
        if check_id.startswith(key) or key.startswith(check_id):
            return guide

    # 3. Fallback by OWASP category
    if owasp_category:
        cat_clean = owasp_category.upper()[:3]
        for key, guide in _KNOWLEDGEBASE.items():
            if key.startswith(cat_clean):
                return guide

    return None


def list_available_guides() -> list[RemediationGuide]:
    """Return all registered remediation guides in the Knowledgebase."""
    return list(_KNOWLEDGEBASE.values())
