"""Discovery module: robots.txt, sitemap.xml, security.txt, and technology indicators."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from app.recon.client import ReconResponse, SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope, normalize_hostname


@dataclass
class RobotsTxtData:
    found: bool
    status_code: int
    disallowed_paths: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    raw_content: str | None = None


@dataclass
class SitemapData:
    found: bool
    status_code: int
    urls: list[str] = field(default_factory=list)


@dataclass
class SecurityTxtData:
    found: bool
    status_code: int
    contacts: list[str] = field(default_factory=list)
    policy_url: str | None = None
    raw_content: str | None = None


@dataclass
class TechnologyProfile:
    name: str
    category: str  # Web Server, Framework, Frontend, CDN, CMS, etc.
    confidence: str  # certain, firm, tentative
    evidence: str


@dataclass
class DiscoverySummary:
    robots: RobotsTxtData
    sitemap: SitemapData
    security_txt: SecurityTxtData
    technologies: list[TechnologyProfile]
    discovered_urls: set[str] = field(default_factory=set)


async def probe_robots_txt(
    target: TargetScope,
    client: SafeReconClient,
) -> RobotsTxtData:
    """Fetch and parse robots.txt for disallowed endpoints and sitemap declarations."""
    robots_url = urljoin(target.canonical_url, "/robots.txt")
    try:
        resp = await client.fetch(robots_url)
    except Exception:
        return RobotsTxtData(found=False, status_code=0)

    if resp.status_code != 200 or not resp.body_text:
        return RobotsTxtData(found=False, status_code=resp.status_code)

    # If the server returned an HTML error page with 200 status, ignore
    if "<html" in resp.body_text.lower() or "<!doctype" in resp.body_text.lower():
        return RobotsTxtData(found=False, status_code=resp.status_code)

    disallowed: list[str] = []
    allowed: list[str] = []
    sitemaps: list[str] = []

    for line in resp.body_text.splitlines():
        clean = line.strip()
        if not clean or clean.startswith("#"):
            continue
        parts = clean.split(":", 1)
        if len(parts) != 2:
            continue
        directive = parts[0].strip().lower()
        val = parts[1].strip()

        if directive == "disallow" and val:
            disallowed.append(val)
        elif directive == "allow" and val:
            allowed.append(val)
        elif directive == "sitemap" and val:
            sitemaps.append(val)

    return RobotsTxtData(
        found=True,
        status_code=resp.status_code,
        disallowed_paths=disallowed,
        allowed_paths=allowed,
        sitemaps=sitemaps,
        raw_content=resp.body_text[:10000],
    )


async def probe_sitemap(
    target: TargetScope,
    client: SafeReconClient,
    candidate_urls: list[str] | None = None,
    max_urls: int = 25,
) -> SitemapData:
    """Fetch and parse sitemap.xml to discover in-scope published URLs."""
    urls_to_try = list(candidate_urls or [])
    urls_to_try.append(urljoin(target.canonical_url, "/sitemap.xml"))

    for sitemap_url in urls_to_try:
        try:
            resp = await client.fetch(sitemap_url)
        except Exception:
            continue

        if resp.status_code != 200 or not resp.body_text:
            continue

        # Basic check for XML sitemap format
        if "<?xml" not in resp.body_text and "<urlset" not in resp.body_text and "<sitemapindex" not in resp.body_text:
            continue

        discovered: list[str] = []
        try:
            # Defuse XML parsing using standard ElementTree (safe since no entities expanded)
            root = ET.fromstring(resp.body_text)
            # Handle XML namespace
            for elem in root.iter():
                if elem.tag.endswith("loc") and elem.text:
                    loc = elem.text.strip()
                    loc_host = normalize_hostname(urlsplit(loc).hostname or "")
                    if loc_host == target.hostname:
                        discovered.append(loc)
                    if len(discovered) >= max_urls:
                        break
        except Exception:
            # Fallback regex extraction of <loc>
            loc_matches = re.findall(r"<loc>\s*(https?://[^\s<>]+)\s*</loc>", resp.body_text)
            for loc in loc_matches:
                loc_host = normalize_hostname(urlsplit(loc).hostname or "")
                if loc_host == target.hostname:
                    discovered.append(loc)
                if len(discovered) >= max_urls:
                    break

        if discovered:
            return SitemapData(
                found=True,
                status_code=resp.status_code,
                urls=discovered,
            )

    return SitemapData(found=False, status_code=404)


async def probe_security_txt(
    target: TargetScope,
    client: SafeReconClient,
) -> SecurityTxtData:
    """Check for /.well-known/security.txt (RFC 9116) or /security.txt."""
    candidates = [
        urljoin(target.canonical_url, "/.well-known/security.txt"),
        urljoin(target.canonical_url, "/security.txt"),
    ]
    for url in candidates:
        try:
            resp = await client.fetch(url)
        except Exception:
            continue

        if resp.status_code == 200 and resp.body_text:
            # Must not be HTML error page
            if "<html" in resp.body_text.lower():
                continue

            contacts: list[str] = []
            policy_url: str | None = None
            for line in resp.body_text.splitlines():
                clean = line.strip()
                if clean.lower().startswith("contact:"):
                    contacts.append(clean.split(":", 1)[1].strip())
                elif clean.lower().startswith("policy:"):
                    policy_url = clean.split(":", 1)[1].strip()

            return SecurityTxtData(
                found=True,
                status_code=resp.status_code,
                contacts=contacts,
                policy_url=policy_url,
                raw_content=resp.body_text[:5000],
            )

    return SecurityTxtData(found=False, status_code=404)


def detect_technologies(
    http_data: HttpReconData,
    html_data: HtmlReconData,
) -> list[TechnologyProfile]:
    """Correlate HTTP response, headers, cookies, scripts, and HTML to identify stack technologies."""
    detected: dict[str, TechnologyProfile] = {}

    def add(name: str, cat: str, conf: str, ev: str) -> None:
        if name not in detected or (conf == "certain" and detected[name].confidence != "certain"):
            detected[name] = TechnologyProfile(name=name, category=cat, confidence=conf, evidence=ev)

    headers = http_data.headers
    raw_body = http_data.raw_body.lower()

    # 1. Web Servers
    server = headers.get("server", "")
    if "apache" in server.lower():
        add("Apache HTTP Server", "Web Server", "certain", f"Header Server: {server}")
    elif "nginx" in server.lower():
        add("Nginx", "Web Server", "certain", f"Header Server: {server}")
    elif "caddy" in server.lower():
        add("Caddy", "Web Server", "certain", f"Header Server: {server}")
    elif "iis" in server.lower() or "microsoft-iis" in server.lower():
        add("Microsoft IIS", "Web Server", "certain", f"Header Server: {server}")
    elif "cloudflare" in server.lower():
        add("Cloudflare", "CDN / Proxy", "certain", f"Header Server: {server}")
    elif "uvicorn" in server.lower():
        add("Uvicorn", "ASGI Server", "certain", f"Header Server: {server}")
    elif server:
        add(server.split("/")[0], "Web Server", "firm", f"Header Server: {server}")

    # 2. CDNs / Proxies
    if "cf-ray" in headers:
        add("Cloudflare", "CDN / Proxy", "certain", "Header CF-Ray present")
    if "x-amz-cf-id" in headers:
        add("AWS CloudFront", "CDN", "certain", "Header X-Amz-Cf-Id present")
    if "x-varnish" in headers:
        add("Varnish", "Cache / Proxy", "certain", "Header X-Varnish present")

    # 3. Backend Frameworks & Runtimes
    powered = headers.get("x-powered-by", "").lower()
    if "express" in powered:
        add("Express.js", "Web Framework", "certain", f"Header X-Powered-By: {headers.get('x-powered-by')}")
    elif "php" in powered or "php" in server.lower():
        add("PHP", "Programming Language", "certain", "Header X-Powered-By / Server")
    elif "asp.net" in powered or "x-aspnet-version" in headers:
        add("ASP.NET", "Web Framework", "certain", "Header X-Powered-By / X-AspNet-Version")
    elif "next.js" in powered:
        add("Next.js", "Fullstack Framework", "certain", "Header X-Powered-By: Next.js")

    # FastAPI / OpenAPI indicators
    if '{"openapi":' in raw_body or '"swagger":' in raw_body or "fastapi" in raw_body or "redoc" in raw_body:
        add("FastAPI / OpenAPI", "Web Framework", "firm", "OpenAPI schema / Swagger UI indicators")

    # Cookie Indicators
    cookie_names = [c["name"].lower() for c in http_data.cookies]
    if "phpsessid" in cookie_names:
        add("PHP", "Programming Language", "certain", "Cookie PHPSESSID")
    if "jsessionid" in cookie_names:
        add("Java / Servlet Container", "Web Framework", "certain", "Cookie JSESSIONID")
    if "csrftoken" in cookie_names or "sessionid" in cookie_names:
        add("Django", "Web Framework", "firm", "Django session / csrftoken cookies")
    if "connect.sid" in cookie_names:
        add("Node.js / Express", "Web Framework", "certain", "Cookie connect.sid")
    if "laravel_session" in cookie_names:
        add("Laravel", "Web Framework", "certain", "Cookie laravel_session")

    # 4. Frontend Frameworks & Libraries
    # Generator meta tag
    gen = html_data.meta_tags.get("generator", "")
    if gen:
        add(gen, "CMS / Framework", "certain", f"Meta generator: {gen}")

    # Inspect Scripts & DOM
    all_scripts_str = " ".join(html_data.scripts + html_data.external_scripts).lower()

    if "_next" in all_scripts_str or "__next_data__" in raw_body or "id=\"__next\"" in raw_body:
        add("Next.js", "Frontend Framework", "certain", "Next.js __NEXT_DATA__ / script bundles")
    elif "react" in all_scripts_str or "react-dom" in all_scripts_str:
        add("React", "Frontend Library", "firm", "React script bundles")

    if "angular" in all_scripts_str or "ng-version" in raw_body or "app-root" in raw_body:
        add("Angular", "Frontend Framework", "firm", "Angular bundles or ng-version")

    if "vue" in all_scripts_str or "v-data" in raw_body or "data-v-" in raw_body:
        add("Vue.js", "Frontend Framework", "firm", "Vue.js indicators in scripts/DOM")

    if "jquery" in all_scripts_str:
        add("jQuery", "JavaScript Library", "certain", "jQuery script found")

    if "bootstrap" in all_scripts_str or any("bootstrap" in s.lower() for s in html_data.stylesheets):
        add("Bootstrap", "CSS Framework", "firm", "Bootstrap CSS/JS found")

    if any("tailwind" in s.lower() for s in html_data.stylesheets):
        add("Tailwind CSS", "CSS Framework", "firm", "Tailwind CSS stylesheet")

    # Intentionally vulnerable test labs detection (Juice Shop, DVWA, WebGoat)
    if "juice shop" in raw_body or "juice-shop" in raw_body or "owasp juice shop" in (html_data.title or "").lower():
        add("OWASP Juice Shop", "Vulnerable Test Lab", "certain", "Juice Shop branding and DOM structure")
    if "damn vulnerable web application" in raw_body or "dvwa" in raw_body:
        add("DVWA", "Vulnerable Test Lab", "certain", "DVWA signature")

    return list(detected.values())


async def perform_full_discovery(
    target: TargetScope,
    client: SafeReconClient,
    http_data: HttpReconData,
    html_data: HtmlReconData,
) -> DiscoverySummary:
    """Run all discovery checks and consolidate discovered endpoints."""
    # Run safe checks
    robots = await probe_robots_txt(target, client)
    sitemap = await probe_sitemap(target, client, candidate_urls=robots.sitemaps)
    security_txt = await probe_security_txt(target, client)

    # Technology detection
    technologies = detect_technologies(http_data, html_data)

    discovered_urls: set[str] = set()

    # 1. Add base URL
    discovered_urls.add(target.canonical_url)

    # 2. Add internal links from HTML
    for link in html_data.internal_links:
        discovered_urls.add(link)

    # 3. Add form action endpoints
    for form in html_data.forms:
        if form.action:
            discovered_urls.add(form.action)

    # 4. Add robots.txt disallowed paths (resolved against base)
    for path in robots.disallowed_paths:
        if path.startswith("/"):
            full_url = urljoin(target.canonical_url, path)
            discovered_urls.add(full_url)

    # 5. Add sitemap discovered URLs
    for url in sitemap.urls:
        discovered_urls.add(url)

    # 6. Add interesting endpoints from inline scripts/comments
    for ep in html_data.interesting_endpoints:
        if ep.startswith("/"):
            full_url = urljoin(target.canonical_url, ep)
            discovered_urls.add(full_url)

    return DiscoverySummary(
        robots=robots,
        sitemap=sitemap,
        security_txt=security_txt,
        technologies=technologies,
        discovered_urls=discovered_urls,
    )
