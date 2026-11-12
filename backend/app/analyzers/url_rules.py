"""Rule-based lexical analysis of a URL. Pure functions, no network access."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote

from ..core.indicators import BRANDS, HIGH_RISK_TLDS, MEDIUM_RISK_TLDS, SUSPICIOUS_KEYWORDS
from ..core.urltools import (
    brand_label,
    ParsedURL,
    brand_owns,
    brands_mentioned,
    combosquat_target,
    free_hosting_platform,
    is_popular,
    is_shortener,
    parse_url,
    shannon_entropy,
    typosquat_target,
)
from ..schemas import Finding

_REDIRECT_PARAMS = {"url", "u", "redirect", "redirect_uri", "redirect_url", "next", "goto", "target", "dest", "destination", "continue", "return", "returnurl", "return_to", "r", "link", "out", "to", "q"}
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def _decode_idna(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def url_rules(u: ParsedURL, *, domain_only: bool = False, prefix: str = "") -> list[Finding]:
    """Return lexical findings. `domain_only` skips path/scheme rules (for domain scans)."""
    out: list[Finding] = []

    def add(fid: str, title: str, detail: str, severity: str, weight: float, kind: str = "risk", evidence: list[str] | None = None) -> None:
        out.append(Finding(id=f"{prefix}{fid}", category="url", kind=kind, severity=severity,
                           title=(f"Destination: {title[0].lower()}{title[1:]}" if prefix else title), detail=detail, weight=weight,
                           evidence=evidence or []))

    host, reg = u.host, u.registered_domain
    platform = free_hosting_platform(host)
    popular = is_popular(reg) and platform is None

    if u.is_ip:
        add("url.ip_host", "IP address used instead of a domain", f"The link points directly at {host}. Legitimate services almost always use a domain name.", "high", 0.45)

    if u.userinfo and not domain_only:
        looks_like_domain = "." in u.userinfo
        add("url.userinfo", "Deceptive '@' in address",
            f"Everything before '@' is ignored by the browser: '{u.userinfo}@' makes the link look like it goes to "
            f"{u.userinfo if looks_like_domain else 'a trusted site'}, but it actually opens {host}.",
            "high", 0.55 if looks_like_domain else 0.35)

    if "xn--" in host:
        add("url.punycode", "Internationalised (punycode) domain",
            f"{host} renders as '{_decode_idna(host)}'. Lookalike Unicode characters are used in homograph attacks.", "medium", 0.3)

    # Brand impersonation
    if not u.is_ip:
        typo = typosquat_target(u.domain)
        if typo:
            brand, technique = typo
            add("url.typosquat", f"Lookalike of {brand_label(brand)} domain",
                f"'{u.domain}' imitates '{brand}' ({technique}). Official domains: {official_domains(brand)}.", "high", 0.55, evidence=[u.domain])
        combo = combosquat_target(u.domain)
        if combo and not brand_owns(combo, reg) and not typo:
            add("url.combosquat", f"{brand_label(combo)} name in unrelated domain",
                f"{reg} contains the brand '{combo}' but is not owned by {brand_label(combo)} ({official_domains(combo)}).", "high", 0.45, evidence=[combo])
        sub_brands = [b for b in brands_mentioned(u.subdomain) if not brand_owns(b, reg)] if u.subdomain else []
        if sub_brands:
            add("url.brand_subdomain", f"{brand_label(sub_brands[0])} name used as subdomain",
                f"'{u.subdomain}' places '{sub_brands[0]}' in front of the real domain {reg} to look legitimate.", "high", 0.5, evidence=[sub_brands[0]])

    if not domain_only:
        path_text = unquote(u.path + " " + u.query)
        path_brands = [b for b in brands_mentioned(path_text) if not brand_owns(b, reg)]
        if path_brands and not popular:
            add("url.brand_path", f"{brand_label(path_brands[0])} name in path", f"The path references '{path_brands[0]}' but the site is {reg}.", "medium", 0.18, evidence=[path_brands[0]])

        lowered = unquote(u.url).lower()
        hits = sorted({k for k in SUSPICIOUS_KEYWORDS if k in lowered})
        # Collapse overlapping keywords (e.g. 'suspend' within 'suspended').
        hits = [k for k in hits if not any(k != o and k in o for o in hits)]
        if hits:
            n = len(hits)
            weight = 0.08 if n == 1 else 0.15 if n == 2 else 0.25
            add("url.keywords", "Phishing-related keywords", f"Contains: {', '.join(hits[:8])}.", "medium" if n >= 3 else "low", weight, evidence=hits)
    else:
        hits = [k for k in SUSPICIOUS_KEYWORDS if len(k) >= 5 and k in host]
        if hits:
            add("url.keywords", "Phishing-related keywords in domain", f"Contains: {', '.join(hits[:6])}.", "medium" if len(hits) > 1 else "low", 0.12 * min(len(hits), 3), evidence=hits)

    if u.tld in HIGH_RISK_TLDS:
        add("url.tld_high", f"High-abuse TLD .{u.tld}", f".{u.tld} domains are cheap and disproportionately used for phishing and malware.", "medium", 0.25)
    elif u.tld in MEDIUM_RISK_TLDS:
        add("url.tld_medium", f"Elevated-abuse TLD .{u.tld}", f".{u.tld} has an above-average abuse rate.", "low", 0.08)

    if is_shortener(host) and not domain_only:
        add("url.shortener", "URL shortener hides the destination", f"{host} links redirect elsewhere; the final destination cannot be seen from the link.", "low", 0.15)

    if platform:
        add("url.free_hosting", "Hosted on a free/user-content platform",
            f"{host} is on {platform}, where anyone can publish pages. Attackers use these to borrow a trusted parent domain.", "medium", 0.2)

    if not domain_only and u.scheme == "http":
        add("url.no_https", "Unencrypted HTTP link", "Data sent to this page is not encrypted.", "low", 0.08)

    if not domain_only and len(u.url) > 100:
        add("url.long", "Unusually long URL", f"{len(u.url)} characters. Long URLs can hide the real domain off-screen.", "low", 0.12 if len(u.url) > 200 else 0.06)

    levels = [s for s in u.subdomain.split(".") if s and s != "www"] if u.subdomain else []
    if len(levels) >= 3 and not popular:
        add("url.many_subdomains", "Deeply nested subdomains", f"{len(levels)} subdomain levels ({u.subdomain}).", "medium", 0.3 if len(levels) >= 4 else 0.2)

    if host.count("-") >= 3:
        add("url.hyphens", "Many hyphens in hostname", f"{host.count('-')} hyphens; common in keyword-stuffed phishing domains.", "low", 0.12)

    if u.port and u.port not in (80, 443):
        add("url.port", "Non-standard port", f"Uses port {u.port}.", "medium", 0.2)

    if not u.is_ip and ("https" in host or "http-" in host or host.startswith("http")):
        add("url.https_token", "'http(s)' inside the hostname", f"{host} embeds 'http' to appear secure.", "medium", 0.3)

    if not domain_only and "//" in u.path:
        add("url.double_slash", "'//' inside the path", "Can indicate an embedded redirect.", "low", 0.1)

    label = u.domain or ""
    letters = [c for c in label if c.isalpha()]
    vowel_ratio = sum(c in "aeiou" for c in letters) / max(len(letters), 1)
    if not u.is_ip and len(label) >= 10 and (shannon_entropy(label) > 3.4 and (vowel_ratio < 0.25 or sum(c.isdigit() for c in label) >= 3)):
        add("url.random_domain", "Randomly generated-looking domain", f"'{label}' has high character randomness, typical of throwaway or algorithmically generated domains.", "medium", 0.2)
    elif not u.is_ip and len(label) >= 6 and sum(c.isdigit() for c in label) / len(label) > 0.3:
        add("url.digits_domain", "Many digits in domain name", f"'{label}'.", "low", 0.1)

    if not domain_only:
        query_text = unquote(u.query)
        if _EMAIL_RE.search(query_text) or _EMAIL_RE.search(unquote(u.fragment)):
            add("url.email_in_url", "Email address embedded in link", "Pre-filling the victim's address is a hallmark of targeted credential phishing.", "medium", 0.2)
        if re.search(r"\.(exe|scr|msi|bat|cmd|apk|jar|vbs|js|iso|img|zip|rar|7z)$", u.path, re.I):
            add("url.download", "Link downloads a file", f"Path ends with an executable or archive ({u.path.rsplit('/', 1)[-1]}).", "medium", 0.25)
        if u.url.count("%") > 10 or re.search(r"[0-9a-f]{32,}", u.url, re.I):
            add("url.obfuscated", "Heavily encoded or tokenised URL", "Long encoded or hex sequences can disguise the destination.", "low", 0.06)
        for key, value in parse_qsl(u.query, keep_blank_values=False):
            if key.lower() in _REDIRECT_PARAMS and re.match(r"(https?:)?//", value.strip(), re.I):
                try:
                    target = parse_url(value)
                except ValueError:
                    continue
                if target.registered_domain != reg:
                    add("url.embedded_redirect", "Embedded redirect to another site",
                        f"Parameter '{key}' forwards to {target.host}. Open redirects on trusted domains are abused to disguise phishing links.", "medium", 0.2)
                    break

    if popular:
        add("url.popular_domain", "Well-known domain", f"{reg} is a widely used, established site.", "info", 0.85, kind="trust")
    return out


def official_domains(brand: str) -> str:
    return ", ".join(BRANDS.get(brand, ())[:3])
