"""Lexical feature extraction for the URL classifier.

Features are computed from the URL string alone so the model can run offline and in
milliseconds. Network-derived signals (domain age, TLS, redirects) are handled by the
rule engine instead.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

from ..core.indicators import HIGH_RISK_TLDS, MEDIUM_RISK_TLDS, SUSPICIOUS_KEYWORDS
from ..core.urltools import (
    InvalidURL,
    brand_owns,
    brands_mentioned,
    combosquat_target,
    free_hosting_platform,
    is_popular,
    is_shortener,
    parse_url,
    shannon_entropy,
    tokens,
    typosquat_target,
)

FEATURE_NAMES: list[str] = [
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "num_dots_host",
    "num_hyphens_host",
    "num_hyphens_url",
    "num_underscores",
    "num_slashes",
    "num_query_params",
    "num_at",
    "num_percent",
    "num_tilde",
    "num_digits_url",
    "digit_ratio_host",
    "num_subdomain_levels",
    "is_ip_host",
    "has_port",
    "is_https",
    "has_punycode",
    "tld_high_risk",
    "tld_medium_risk",
    "tld_length",
    "is_shortener",
    "is_free_hosting",
    "is_popular_domain",
    "host_entropy",
    "path_entropy",
    "num_suspicious_keywords",
    "brand_in_subdomain",
    "brand_in_path",
    "brand_typosquat",
    "brand_combosquat",
    "brand_not_owned",
    "https_token_in_host",
    "double_slash_in_path",
    "longest_host_token",
    "longest_path_token",
    "num_path_segments",
    "has_php_or_html",
    "has_exe_ext",
    "has_email_in_url",
    "has_hex_run",
    "domain_label_length",
    "domain_label_digits",
    "vowel_ratio_domain",
]

_KEYWORDS = sorted({k.replace("-", "") for k in SUSPICIOUS_KEYWORDS})
_HEX_RUN = re.compile(r"[0-9a-f]{16,}", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+(@|%40)[\w-]+\.[\w.-]+", re.I)


def extract_features(raw_url: str) -> dict[str, float]:
    try:
        u = parse_url(raw_url)
    except InvalidURL:
        return {name: 0.0 for name in FEATURE_NAMES}

    full = u.url
    host = u.host
    path = unquote(u.path)
    query = u.query
    host_tokens = tokens(host)
    path_tokens = tokens(path + " " + query)
    lower_full = unquote(full).lower()

    sub_brands = brands_mentioned(u.subdomain) if u.subdomain else []
    path_brands = brands_mentioned(path + " " + query)
    typo = typosquat_target(u.domain) if not u.is_ip else None
    combo = combosquat_target(u.domain) if not u.is_ip else None
    all_brands = set(sub_brands + path_brands + ([typo[0]] if typo else []) + ([combo] if combo else []))
    not_owned = any(not brand_owns(b, u.registered_domain) for b in all_brands)

    keyword_hits = sum(1 for k in _KEYWORDS if k in lower_full.replace("-", ""))
    domain_label = u.domain or ""
    letters = [c for c in domain_label if c.isalpha()]
    vowels = sum(1 for c in letters if c in "aeiou")

    f = {
        "url_length": len(full),
        "host_length": len(host),
        "path_length": len(u.path),
        "query_length": len(query),
        "num_dots_host": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_hyphens_url": full.count("-"),
        "num_underscores": full.count("_"),
        "num_slashes": max(full.count("/") - 2, 0),
        "num_query_params": len([p for p in query.split("&") if p]),
        "num_at": full.count("@"),
        "num_percent": full.count("%"),
        "num_tilde": full.count("~"),
        "num_digits_url": sum(c.isdigit() for c in full),
        "digit_ratio_host": sum(c.isdigit() for c in host) / max(len(host), 1),
        "num_subdomain_levels": len([s for s in u.subdomain.split(".") if s]) if u.subdomain else 0,
        "is_ip_host": float(u.is_ip),
        "has_port": float(u.port is not None and u.port not in (80, 443)),
        "is_https": float(u.scheme == "https"),
        "has_punycode": float("xn--" in host),
        "tld_high_risk": float(u.tld in HIGH_RISK_TLDS),
        "tld_medium_risk": float(u.tld in MEDIUM_RISK_TLDS),
        "tld_length": len(u.tld),
        "is_shortener": float(is_shortener(host)),
        "is_free_hosting": float(free_hosting_platform(host) is not None),
        "is_popular_domain": float(is_popular(u.registered_domain) and not free_hosting_platform(host)),
        "host_entropy": shannon_entropy(host),
        "path_entropy": shannon_entropy(u.path + query),
        "num_suspicious_keywords": keyword_hits,
        "brand_in_subdomain": float(any(not brand_owns(b, u.registered_domain) for b in sub_brands)),
        "brand_in_path": float(any(not brand_owns(b, u.registered_domain) for b in path_brands)),
        "brand_typosquat": float(typo is not None),
        "brand_combosquat": float(combo is not None and not brand_owns(combo, u.registered_domain)),
        "brand_not_owned": float(not_owned),
        "https_token_in_host": float("https" in host or "http" in host_tokens),
        "double_slash_in_path": float("//" in u.path),
        "longest_host_token": max((len(t) for t in host_tokens), default=0),
        "longest_path_token": max((len(t) for t in path_tokens), default=0),
        "num_path_segments": len([s for s in u.path.split("/") if s]),
        "has_php_or_html": float(bool(re.search(r"\.(php|html?|aspx?|jsp)$", u.path, re.I))),
        "has_exe_ext": float(bool(re.search(r"\.(exe|scr|zip|rar|apk|msi|bat|js|vbs)$", u.path, re.I))),
        "has_email_in_url": float(bool(_EMAIL_RE.search(unquote(path + "?" + query)))),
        "has_hex_run": float(bool(_HEX_RUN.search(full))),
        "domain_label_length": len(domain_label),
        "domain_label_digits": sum(c.isdigit() for c in domain_label),
        "vowel_ratio_domain": vowels / max(len(letters), 1),
    }
    return {k: float(v) for k, v in f.items()}


def feature_vector(raw_url: str) -> list[float]:
    feats = extract_features(raw_url)
    return [feats[name] for name in FEATURE_NAMES]
