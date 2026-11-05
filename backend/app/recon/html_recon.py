"""HTML reconnaissance: parsing with BeautifulSoup to extract DOM structures and endpoints."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup, Comment

from app.recon.validator import normalize_hostname

# Regular expressions for detecting interesting API or file endpoints in inline code/comments
ENDPOINT_REGEXES = (
    re.compile(r"""["'](/api/[a-zA-Z0-9_\-\./]+)["']""", re.IGNORECASE),
    re.compile(r"""["'](/v[1-9][0-9]*/[a-zA-Z0-9_\-\./]+)["']""", re.IGNORECASE),
    re.compile(r"""["'](/[a-zA-Z0-9_\-\./]+\.(?:json|xml|php|aspx?|jsp))["']""", re.IGNORECASE),
    re.compile(r"""["'](/(?:auth|login|admin|dashboard|user|users|account|v1|graphql|swagger|openapi)[a-zA-Z0-9_\-\./]*)["']""", re.IGNORECASE),
)


@dataclass
class FormInput:
    name: str | None
    input_type: str
    required: bool
    default_value: str | None = None


@dataclass
class HtmlForm:
    action: str
    method: str
    inputs: list[FormInput] = field(default_factory=list)
    enctype: str | None = None
    has_file_upload: bool = False
    has_password: bool = False


@dataclass
class HtmlReconData:
    """Structured data extracted from HTML response body."""

    title: str | None
    meta_tags: dict[str, str]
    internal_links: list[str]
    external_links: list[str]
    forms: list[HtmlForm]
    scripts: list[str]
    external_scripts: list[str]
    stylesheets: list[str]
    interesting_endpoints: list[str]
    comments_with_paths: list[str]


def _clean_and_resolve_url(base_url: str, raw_url: str | None) -> str | None:
    """Resolve a relative URL to an absolute URL and strip query/fragment."""
    if not raw_url:
        return None
    cleaned = raw_url.strip()
    if not cleaned or cleaned.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    try:
        joined = urljoin(base_url, cleaned)
        parts = urlsplit(joined)
        if parts.scheme.lower() not in {"http", "https"}:
            return None
        # Canonical representation without fragment
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", "", ""))
    except Exception:
        return None


def parse_html_recon(base_url: str, html_content: str) -> HtmlReconData:
    """Analyze HTML content using BeautifulSoup and regex extraction."""
    soup = BeautifulSoup(html_content, "html.parser")
    base_host = normalize_hostname(urlsplit(base_url).hostname or "")

    # 1. Page Title
    title = soup.title.string.strip() if (soup.title and soup.title.string) else None

    # 2. Meta Tags
    meta_tags: dict[str, str] = {}
    for meta in soup.find_all("meta"):
        name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
        content = meta.get("content")
        if name and content:
            meta_tags[name.lower().strip()] = content.strip()

    # 3. Links (<a href>, <area href>)
    internal_links: set[str] = set()
    external_links: set[str] = set()

    for tag in soup.find_all(["a", "area"]):
        href = tag.get("href")
        resolved = _clean_and_resolve_url(base_url, href)
        if not resolved:
            continue
        link_host = normalize_hostname(urlsplit(resolved).hostname or "")
        if link_host == base_host:
            internal_links.add(resolved)
        else:
            external_links.add(resolved)

    # 4. Forms (<form>)
    forms: list[HtmlForm] = []
    for form in soup.find_all("form"):
        raw_action = form.get("action")
        resolved_action = _clean_and_resolve_url(base_url, raw_action) or base_url
        method = (form.get("method") or "GET").upper()
        enctype = form.get("enctype")

        form_inputs: list[FormInput] = []
        has_file_upload = False
        has_password = False

        # Parse inputs
        for inp in form.find_all(["input", "textarea", "select"]):
            tag_name = inp.name.lower()
            if tag_name == "input":
                itype = (inp.get("type") or "text").lower()
                name = inp.get("name")
                required = inp.has_attr("required")
                val = inp.get("value")
                if itype == "file":
                    has_file_upload = True
                if itype == "password":
                    has_password = True
                form_inputs.append(
                    FormInput(
                        name=name,
                        input_type=itype,
                        required=required,
                        default_value=val,
                    )
                )
            elif tag_name == "textarea":
                form_inputs.append(
                    FormInput(
                        name=inp.get("name"),
                        input_type="textarea",
                        required=inp.has_attr("required"),
                        default_value=inp.string.strip() if inp.string else None,
                    )
                )
            elif tag_name == "select":
                form_inputs.append(
                    FormInput(
                        name=inp.get("name"),
                        input_type="select",
                        required=inp.has_attr("required"),
                    )
                )

        forms.append(
            HtmlForm(
                action=resolved_action,
                method=method,
                inputs=form_inputs,
                enctype=enctype,
                has_file_upload=has_file_upload,
                has_password=has_password,
            )
        )

    # 5. Scripts (<script src="...">)
    scripts: set[str] = set()
    external_scripts: set[str] = set()
    for s in soup.find_all("script"):
        src = s.get("src")
        resolved = _clean_and_resolve_url(base_url, src)
        if not resolved:
            continue
        script_host = normalize_hostname(urlsplit(resolved).hostname or "")
        if script_host == base_host:
            scripts.add(resolved)
        else:
            external_scripts.add(resolved)

    # 6. Stylesheets (<link rel="stylesheet">)
    stylesheets: set[str] = set()
    for link in soup.find_all("link", rel=lambda r: r and "stylesheet" in r):
        href = link.get("href")
        resolved = _clean_and_resolve_url(base_url, href)
        if resolved:
            stylesheets.add(resolved)

    # 7. HTML Comments with path-like references
    comments_with_paths: set[str] = set()
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        c_text = str(comment).strip()
        if "/" in c_text:
            # Look for words starting with /
            for word in c_text.split():
                if word.startswith("/") and len(word) > 1 and not word.startswith(("//", "/*")):
                    comments_with_paths.add(word.rstrip(";,.)]\"'"))

    # 8. Potentially interesting endpoints from inline text, scripts, and attributes
    interesting_endpoints: set[str] = set()

    # Search inline scripts
    for script_tag in soup.find_all("script"):
        if not script_tag.get("src") and script_tag.string:
            content = script_tag.string
            for pattern in ENDPOINT_REGEXES:
                for match in pattern.findall(content):
                    interesting_endpoints.add(match)

    # Search data- attributes
    for element in soup.find_all(lambda tag: any(attr.startswith("data-") for attr in tag.attrs)):
        for attr, val in element.attrs.items():
            if attr.startswith("data-") and isinstance(val, str) and val.startswith("/"):
                interesting_endpoints.add(val)

    # Add comments paths to interesting endpoints
    interesting_endpoints.update(comments_with_paths)

    return HtmlReconData(
        title=title,
        meta_tags=meta_tags,
        internal_links=sorted(internal_links),
        external_links=sorted(external_links),
        forms=forms,
        scripts=sorted(scripts),
        external_scripts=sorted(external_scripts),
        stylesheets=sorted(stylesheets),
        interesting_endpoints=sorted(interesting_endpoints),
        comments_with_paths=sorted(comments_with_paths),
    )
