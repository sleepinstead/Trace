"""Active checks: follow redirects (with an SSRF guard) and inspect the landing page's HTML."""

from __future__ import annotations

import html
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from ..config import get_settings
from ..core.net import BlockedTarget, ensure_public_host, http_client
from ..core.urltools import brand_label, brand_owns, brands_mentioned, parse_ip, registered_domain
from ..core.indicators import BRANDS
from ..schemas import Finding

_META_REFRESH = re.compile(r"<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]*content=[\"']?\s*\d*\s*;?\s*url=([^\"'>]+)", re.I)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_PASSWORD = re.compile(r"<input[^>]+type=[\"']?password", re.I)
_FORM_ACTION = re.compile(r"<form[^>]*?action=[\"']?([^\"' >]+)", re.I)
_FORM = re.compile(r"<form\b", re.I)
_JS_REDIRECT = re.compile(r"(window\.)?location(\.href)?\s*=\s*[\"']https?://|location\.replace\(\s*[\"']https?://", re.I)
_OBFUSCATION = re.compile(r"eval\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(|String\.fromCharCode\s*\((\s*\d+\s*,){20,}|document\.write\s*\(\s*(unescape|atob)\s*\(", re.I)
_RESOURCE = re.compile(r"(?:src|href)=[\"'](https?://[^\"']+)", re.I)
_SENSITIVE_FIELDS = re.compile(r"name=[\"']?(cc|card|cardnumber|cvv|cvc|ssn|pin|otp|seed|mnemonic|passphrase)\b", re.I)


async def follow_redirects(url: str) -> dict[str, Any]:
    """GET the URL hop by hop (max N), validating every hop's address. Returns chain + final page."""
    settings = get_settings()
    chain: list[dict[str, Any]] = []
    current = url
    body = ""
    error: str | None = None
    blocked = False
    async with http_client(verify=False) as client:
        for _hop in range(settings.max_redirects + 1):
            host = urlsplit(current).hostname or ""
            try:
                await ensure_public_host(host)
            except BlockedTarget as exc:
                error, blocked = str(exc), True
                break
            except (socket.gaierror, OSError):
                error = f"Could not resolve {host}"
                chain.append({"url": current, "status": None, "error": "DNS resolution failed"})
                break
            try:
                async with client.stream("GET", current) as resp:
                    entry: dict[str, Any] = {"url": current, "status": resp.status_code}
                    location = resp.headers.get("location")
                    if resp.is_redirect and location:
                        nxt = urljoin(current, location.strip())
                        entry["location"], entry["via"] = nxt, "http"
                        chain.append(entry)
                        current = nxt
                        continue
                    ctype = resp.headers.get("content-type", "")
                    entry["content_type"] = ctype.split(";")[0]
                    if "html" in ctype or not ctype:
                        buf = bytearray()
                        async for chunk in resp.aiter_bytes():
                            buf.extend(chunk)
                            if len(buf) >= settings.max_page_bytes:
                                break
                        body = buf.decode(resp.encoding or "utf-8", errors="replace")
                    chain.append(entry)
            except httpx.TimeoutException:
                error = "Timed out fetching page"
                chain.append({"url": current, "status": None, "error": "timeout"})
                break
            except httpx.HTTPError as exc:
                error = f"Fetch failed: {exc.__class__.__name__}"
                chain.append({"url": current, "status": None, "error": exc.__class__.__name__})
                break
            # Follow a single meta-refresh hop (common in phishing redirect chains).
            meta = _META_REFRESH.search(body[:20_000]) if body else None
            if meta and sum(1 for c in chain if c.get("via") == "meta-refresh") < 2:
                nxt = urljoin(current, html.unescape(meta.group(1).strip()))
                if nxt != current and nxt.startswith(("http://", "https://")):
                    chain[-1]["location"], chain[-1]["via"] = nxt, "meta-refresh"
                    current, body = nxt, ""
                    continue
            break
        else:
            error = f"More than {settings.max_redirects} redirects"
    return {"chain": chain, "final_url": current, "html": body, "error": error, "blocked": blocked}


def inspect_page(page_html: str, page_url: str) -> dict[str, Any]:
    if not page_html:
        return {}
    host = (urlsplit(page_url).hostname or "").lower()
    reg = registered_domain(host)
    title_m = _TITLE.search(page_html)
    title = html.unescape(re.sub(r"\s+", " ", title_m.group(1))).strip()[:200] if title_m else ""

    actions = [html.unescape(a) for a in _FORM_ACTION.findall(page_html)]
    external_actions = []
    for action in actions:
        absolute = urljoin(page_url, action)
        if absolute.startswith(("http://", "https://")):
            ah = (urlsplit(absolute).hostname or "").lower()
            if ah and registered_domain(ah) != reg:
                external_actions.append(absolute)
        elif action.lower().startswith("mailto:"):
            external_actions.append(action)

    brand_assets: dict[str, int] = {}
    for res in _RESOURCE.findall(page_html[:300_000]):
        rh = (urlsplit(res).hostname or "").lower()
        rreg = registered_domain(rh)
        for brand, domains in BRANDS.items():
            if rreg in domains and not brand_owns(brand, reg):
                brand_assets[brand] = brand_assets.get(brand, 0) + 1

    text_sample = re.sub(r"<[^>]+>", " ", page_html[:60_000])
    title_brands = [b for b in brands_mentioned(title) if not brand_owns(b, reg)]
    body_brands = [b for b in brands_mentioned(text_sample[:20_000]) if not brand_owns(b, reg)]
    return {
        "title": title,
        "forms": len(_FORM.findall(page_html)),
        "password_fields": len(_PASSWORD.findall(page_html)),
        "sensitive_fields": sorted({m.lower() for m in _SENSITIVE_FIELDS.findall(page_html)}),
        "external_form_actions": external_actions[:5],
        "js_redirect": bool(_JS_REDIRECT.search(page_html)),
        "obfuscated_js": bool(_OBFUSCATION.search(page_html)),
        "title_brands": title_brands,
        "body_brands": body_brands[:5],
        "brand_assets": brand_assets,
        "size_bytes": len(page_html),
    }


def redirect_findings(result: dict[str, Any], original_url: str, *, from_shortener: bool) -> list[Finding]:
    out: list[Finding] = []
    chain = result.get("chain", [])
    hops = [c for c in chain if c.get("location")]
    start_reg = registered_domain(urlsplit(original_url).hostname or "")
    final_url = result.get("final_url", original_url)
    final_host = urlsplit(final_url).hostname or ""
    final_reg = registered_domain(final_host)

    if result.get("blocked"):
        out.append(Finding(id="web.blocked", category="redirect", kind="info", severity="info", title="Active checks skipped",
                           detail=f"{result.get('error')}. Trace does not connect to private network addresses."))
        return out
    if result.get("error") and not chain:
        out.append(Finding(id="web.unreachable", category="redirect", kind="info", severity="info", title="Page could not be fetched", detail=result["error"]))
        return out
    if result.get("error"):
        out.append(Finding(id="web.fetch_error", category="redirect", kind="info", severity="info", title="Fetch incomplete", detail=result["error"]))
    if len(hops) >= 3:
        out.append(Finding(id="redirect.many_hops", category="redirect", severity="medium" if len(hops) >= 5 else "low",
                           weight=0.2 if len(hops) >= 5 else 0.1, title=f"{len(hops)}-step redirect chain",
                           detail="Long redirect chains are used to evade link scanners."))
    if final_reg != start_reg and hops:
        if from_shortener:
            out.append(Finding(id="redirect.shortener_target", category="redirect", kind="info", severity="info",
                               title="Shortened link resolved", detail=f"Expands to {final_url}"))
        else:
            out.append(Finding(id="redirect.cross_domain", category="redirect", severity="low", weight=0.12,
                               title="Redirects to a different site", detail=f"{start_reg} sends visitors to {final_reg}."))
    if parse_ip(final_host) is not None and hops:
        out.append(Finding(id="redirect.to_ip", category="redirect", severity="high", weight=0.4,
                           title="Redirects to a raw IP address", detail=f"Final destination is {final_host}."))
    if any(c["url"].startswith("https://") and c.get("location", "").startswith("http://") for c in hops):
        out.append(Finding(id="redirect.downgrade", category="redirect", severity="low", weight=0.1,
                           title="Redirect downgrades HTTPS to HTTP", detail="The chain moves from an encrypted to an unencrypted connection."))
    if any(c.get("via") == "meta-refresh" for c in hops):
        out.append(Finding(id="redirect.meta_refresh", category="redirect", severity="low", weight=0.08,
                           title="Meta-refresh redirect", detail="The page silently forwards the browser via an HTML meta tag."))
    return out


def page_findings(page: dict[str, Any], page_url: str, *, popular: bool) -> list[Finding]:
    out: list[Finding] = []
    if not page:
        return out
    reg = registered_domain(urlsplit(page_url).hostname or "")
    has_password = page.get("password_fields", 0) > 0
    impersonated = page.get("title_brands") or []
    if has_password and impersonated and not popular:
        brand = impersonated[0]
        out.append(Finding(id="page.brand_login", category="content", severity="critical", weight=0.6,
                           title=f"Fake {brand_label(brand)} login page",
                           detail=f"The page title '{page.get('title')}' claims to be {brand_label(brand)} and asks for a password, but the site is {reg}."))
    elif has_password and not popular:
        out.append(Finding(id="page.password_form", category="content", severity="medium", weight=0.2,
                           title="Page requests a password", detail="A credential form is present on a site that is not well known."))
    elif impersonated and not popular:
        out.append(Finding(id="page.brand_title", category="content", severity="medium", weight=0.25,
                           title=f"Page claims to be {brand_label(impersonated[0])}", detail=f"Title '{page.get('title')}' on {reg}."))
    if page.get("external_form_actions") and (has_password or page.get("sensitive_fields")):
        out.append(Finding(id="page.external_form", category="content", severity="high", weight=0.45,
                           title="Form sends data to another site", detail=f"Submits to {page['external_form_actions'][0]}"))
    if page.get("sensitive_fields") and not popular:
        out.append(Finding(id="page.sensitive_fields", category="content", severity="high", weight=0.35,
                           title="Requests card, PIN or wallet details", detail=f"Fields: {', '.join(page['sensitive_fields'])}."))
    if page.get("brand_assets") and not popular:
        brand, n = max(page["brand_assets"].items(), key=lambda kv: kv[1])
        out.append(Finding(id="page.brand_assets", category="content", severity="medium", weight=0.2,
                           title=f"Loads {brand_label(brand)} assets", detail=f"{n} resource(s) hot-linked from {brand_label(brand)}'s servers, typical of cloned pages."))
    if page.get("js_redirect"):
        out.append(Finding(id="page.js_redirect", category="content", severity="low", weight=0.06,
                           title="JavaScript redirect", detail="The page contains script that sends visitors elsewhere."))
    if page.get("obfuscated_js"):
        out.append(Finding(id="page.obfuscated_js", category="content", severity="low", weight=0.12,
                           title="Obfuscated JavaScript", detail="Encoded script (eval/atob/fromCharCode) can hide malicious behaviour."))
    return out
