"""URL parsing helpers and lexical primitives shared by the rule engine and the ML features."""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import unquote, urlsplit

import tldextract

from .indicators import (
    BRANDS,
    FREE_HOSTING,
    HOMOGLYPHS,
    MULTI_CHAR_HOMOGLYPHS,
    POPULAR_DOMAINS,
    URL_SHORTENERS,
    WHOLE_TOKEN_BRANDS,
)

# Offline extractor using the bundled public-suffix snapshot (no network fetch at runtime).
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


class InvalidURL(ValueError):
    pass


@dataclass(frozen=True)
class ParsedURL:
    url: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str
    userinfo: str
    subdomain: str
    domain: str  # registrable label, e.g. "paypal" in paypal.co.uk
    suffix: str  # public suffix, e.g. "co.uk"
    registered_domain: str  # e.g. "paypal.co.uk" (or the IP itself)
    is_ip: bool

    @property
    def tld(self) -> str:
        return self.suffix.rsplit(".", 1)[-1] if self.suffix else ""


def normalize_url(raw: str) -> str:
    url = raw.strip().strip("<>\"'")
    if not url:
        raise InvalidURL("Empty URL")
    if url.startswith("//"):
        url = "http:" + url
    if not _SCHEME_RE.match(url):
        url = "http://" + url
    return url


def parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    # Obfuscated IPv4 forms: decimal (3232235777), hex (0xC0A80101), dotted hex/octal.
    try:
        if re.fullmatch(r"\d{8,10}", h):
            return ipaddress.IPv4Address(int(h))
        if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", h):
            return ipaddress.IPv4Address(int(h, 16))
        parts = h.split(".")
        if len(parts) == 4 and all(re.fullmatch(r"0x[0-9a-fA-F]+|\d+", p) for p in parts):
            vals = []
            for p in parts:
                if p.lower().startswith("0x"):
                    vals.append(int(p, 16))
                elif len(p) > 1 and p.startswith("0"):
                    vals.append(int(p, 8))
                else:
                    vals.append(int(p))
            return ipaddress.IPv4Address(bytes(vals))
    except (ValueError, OverflowError):
        return None
    return None


def parse_url(raw: str) -> ParsedURL:
    url = normalize_url(raw)
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise InvalidURL(f"Malformed URL: {exc}") from exc
    if parts.scheme.lower() not in ("http", "https"):
        raise InvalidURL(f"Unsupported scheme '{parts.scheme}' (only http/https)")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise InvalidURL("URL has no host")
    userinfo = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else ""
    ip = parse_ip(host)
    if ip is not None:
        sub, dom, suf, reg = "", str(ip), "", str(ip)
    else:
        ext = _extract(host)
        sub, dom, suf = ext.subdomain, ext.domain, ext.suffix
        reg = f"{dom}.{suf}" if dom and suf else host
    return ParsedURL(
        url=url,
        scheme=parts.scheme.lower(),
        host=host,
        port=port,
        path=parts.path,
        query=parts.query,
        fragment=parts.fragment,
        userinfo=userinfo,
        subdomain=sub,
        domain=dom,
        suffix=suf,
        registered_domain=reg,
        is_ip=ip is not None,
    )


def split_domain(host: str) -> tuple[str, str, str]:
    """Return (subdomain, domain, suffix) for a bare hostname."""
    ext = _extract(host.lower().rstrip("."))
    return ext.subdomain, ext.domain, ext.suffix


def registered_domain(host: str) -> str:
    sub, dom, suf = split_domain(host)
    return f"{dom}.{suf}" if dom and suf else host.lower()


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_SPLIT.split(unquote(text).lower()) if t]


def host_matches(host: str, domains) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in domains)


def is_shortener(host: str) -> bool:
    return host_matches(host, URL_SHORTENERS)


# Platforms whose bare hostname itself serves user content (path-based hosting).
_PATH_HOSTED = {"sites.google.com", "storage.googleapis.com", "s3.amazonaws.com", "ipfs.io", "forms.gle"}


def free_hosting_platform(host: str) -> str | None:
    host = host.lower()
    for platform in FREE_HOSTING:
        if host.endswith("." + platform) or (host == platform and platform in _PATH_HOSTED):
            return platform
    return None


def is_popular(registered: str) -> bool:
    return registered.lower() in POPULAR_DOMAINS


def deobfuscate_label(label: str) -> str:
    out = label.lower()
    for src, dst in MULTI_CHAR_HOMOGLYPHS:
        out = out.replace(src, dst)
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in out)


@lru_cache(maxsize=4096)
def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_owns(brand: str, registered: str) -> bool:
    return registered.lower() in BRANDS.get(brand, ())


def _brand_in_tokens(brand: str, toks: list[str], joined: str) -> bool:
    if brand in WHOLE_TOKEN_BRANDS or len(brand) <= 4:
        return brand in toks
    return brand in joined


def brands_mentioned(text: str) -> list[str]:
    """Brands referenced anywhere in a piece of text (host labels, path, display name...)."""
    toks = tokens(text)
    joined = "".join(toks)
    return [b for b in BRANDS if _brand_in_tokens(b, toks, joined)]


def _typo_match(clean: str) -> tuple[str, str] | None:
    deob = deobfuscate_label(clean)
    for brand in BRANDS:
        if clean == brand or len(brand) < 5:
            continue
        if deob == brand:
            return brand, "homoglyph substitution"
        if brand in WHOLE_TOKEN_BRANDS:
            continue  # dictionary words (apple, chase, booking...): edit distance gives false positives
        dist = levenshtein(clean, brand)
        max_dist = 1 if len(brand) < 8 else 2
        if 0 < dist <= max_dist and abs(len(clean) - len(brand)) <= max_dist:
            return brand, f"edit distance {dist}"
    return None


def typosquat_target(label: str) -> tuple[str, str] | None:
    """If a domain label (or one of its hyphen-separated parts) imitates a brand, return (brand, technique)."""
    label = label.lower()
    if not label or len(label) < 4:
        return None
    clean = label.replace("-", "")
    if clean in BRANDS:
        return None  # exact brand label; ownership is checked elsewhere
    if hit := _typo_match(clean):
        return hit
    for part in re.split(r"[-_]", label):
        if len(part) >= 5 and part not in BRANDS and (hit := _typo_match(part)):
            return hit
    return None


def combosquat_target(label: str) -> str | None:
    """Brand embedded in a longer registrable label, e.g. 'paypal-secure' or 'appleidsupport'."""
    label = label.lower()
    parts = [p for p in re.split(r"[-_]", label) if p]
    for brand in BRANDS:
        if label == brand:
            continue
        if brand in parts:
            return brand
        if len(brand) >= 6 and brand in label and brand not in WHOLE_TOKEN_BRANDS:
            return brand
    return None


BRAND_LABELS = {
    "paypal": "PayPal", "icloud": "iCloud", "office365": "Office 365", "onedrive": "OneDrive",
    "sharepoint": "SharePoint", "linkedin": "LinkedIn", "whatsapp": "WhatsApp", "docusign": "DocuSign",
    "wellsfargo": "Wells Fargo", "bankofamerica": "Bank of America", "hsbc": "HSBC",
    "americanexpress": "American Express", "capitalone": "Capital One", "dhl": "DHL", "fedex": "FedEx",
    "usps": "USPS", "royalmail": "Royal Mail", "metamask": "MetaMask", "ebay": "eBay", "github": "GitHub",
    "irs": "IRS", "hmrc": "HMRC", "steamcommunity": "Steam Community", "coinbase": "Coinbase",
}


def brand_label(brand: str) -> str:
    return BRAND_LABELS.get(brand, brand.title())
