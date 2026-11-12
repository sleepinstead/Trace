"""External threat-intelligence lookups: VirusTotal, Google Safe Browsing, URLhaus, PhishTank.

Every provider is optional and only queried when its API key is configured. Responses are
cached in SQLite to stay within free-tier quotas. Lookups never submit new URLs for
scanning; they only query what each service already knows.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Literal
from urllib.parse import quote

import httpx

from .. import database
from ..config import get_settings

log = logging.getLogger(__name__)

Status = Literal["malicious", "suspicious", "clean", "unknown", "error", "disabled"]


@dataclass
class IntelResult:
    source: str
    status: Status
    detail: str
    reference: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def provider_status() -> list[dict[str, Any]]:
    s = get_settings()
    return [
        {"source": "virustotal", "name": "VirusTotal", "enabled": bool(s.virustotal_api_key), "env": "TRACE_VIRUSTOTAL_API_KEY"},
        {"source": "safebrowsing", "name": "Google Safe Browsing", "enabled": bool(s.google_safe_browsing_api_key), "env": "TRACE_GOOGLE_SAFE_BROWSING_API_KEY"},
        {"source": "urlhaus", "name": "URLhaus (abuse.ch)", "enabled": bool(s.urlhaus_auth_key), "env": "TRACE_URLHAUS_AUTH_KEY"},
        {"source": "phishtank", "name": "PhishTank", "enabled": bool(s.phishtank_app_key), "env": "TRACE_PHISHTANK_APP_KEY"},
        {"source": "local", "name": "Local threat records", "enabled": True, "env": None},
    ]


async def _cached(source: str, kind: str, indicator: str, fetch) -> IntelResult:
    key = f"{source}:{kind}:{indicator}"
    ttl = get_settings().intel_cache_ttl_hours
    hit = database.cache_get(key, ttl)
    if hit:
        return IntelResult(**{**hit, "cached": True})
    try:
        result: IntelResult = await fetch()
    except httpx.TimeoutException:
        return IntelResult(source, "error", "Request timed out")
    except httpx.HTTPError as exc:
        return IntelResult(source, "error", f"Request failed: {exc.__class__.__name__}")
    except Exception as exc:  # provider returned something unexpected
        log.exception("%s lookup failed", source)
        return IntelResult(source, "error", f"Lookup failed: {exc}")
    if result.status not in ("error", "disabled"):
        database.cache_put(key, source, {**result.to_dict(), "cached": False})
    return result


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=get_settings().http_timeout)


# ------------------------------------------------------------------------ VirusTotal


def _vt_verdict(source: str, stats: dict[str, int], reference: str, what: str) -> IntelResult:
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    total = sum(stats.values())
    detail = f"{mal} malicious, {sus} suspicious of {total} engines"
    if mal >= 2:
        status: Status = "malicious"
    elif mal == 1 or sus >= 2:
        status = "suspicious"
    else:
        status = "clean"
        detail = f"No engines flag this {what} ({total} checked)"
    return IntelResult(source, status, detail, reference, {"stats": stats})


async def virustotal_url(url: str) -> IntelResult:
    key = get_settings().virustotal_api_key
    if not key:
        return IntelResult("virustotal", "disabled", "No API key configured")
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    async def fetch() -> IntelResult:
        async with _client() as client:
            r = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": key})
        if r.status_code == 404:
            return IntelResult("virustotal", "unknown", "URL not previously analysed by VirusTotal")
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
        return _vt_verdict("virustotal", attrs.get("last_analysis_stats", {}), f"https://www.virustotal.com/gui/url/{url_id}", "URL")

    return await _cached("virustotal", "url", url, fetch)


async def virustotal_domain(domain: str) -> IntelResult:
    key = get_settings().virustotal_api_key
    if not key:
        return IntelResult("virustotal", "disabled", "No API key configured")

    async def fetch() -> IntelResult:
        async with _client() as client:
            r = await client.get(f"https://www.virustotal.com/api/v3/domains/{quote(domain)}", headers={"x-apikey": key})
        if r.status_code == 404:
            return IntelResult("virustotal", "unknown", "Domain not known to VirusTotal")
        r.raise_for_status()
        attrs = r.json()["data"]["attributes"]
        res = _vt_verdict("virustotal", attrs.get("last_analysis_stats", {}), f"https://www.virustotal.com/gui/domain/{domain}", "domain")
        res.data["reputation"] = attrs.get("reputation")
        res.data["categories"] = sorted(set((attrs.get("categories") or {}).values()))[:6]
        return res

    return await _cached("virustotal", "domain", domain, fetch)


# --------------------------------------------------------------- Google Safe Browsing


async def safebrowsing_urls(urls: list[str]) -> IntelResult:
    key = get_settings().google_safe_browsing_api_key
    if not key:
        return IntelResult("safebrowsing", "disabled", "No API key configured")

    async def fetch() -> IntelResult:
        body = {
            "client": {"clientId": "trace", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        }
        async with _client() as client:
            r = await client.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body)
        r.raise_for_status()
        matches = r.json().get("matches", [])
        if not matches:
            return IntelResult("safebrowsing", "clean", "Not on Google Safe Browsing lists")
        types = sorted({m.get("threatType", "?") for m in matches})
        return IntelResult(
            "safebrowsing", "malicious", f"Listed as {', '.join(t.replace('_', ' ').lower() for t in types)}",
            "https://transparencyreport.google.com/safe-browsing/search?url=" + quote(urls[0], safe=""),
            {"threat_types": types},
        )

    return await _cached("safebrowsing", "urls", "|".join(urls), fetch)


# --------------------------------------------------------------------------- URLhaus


async def urlhaus_url(url: str) -> IntelResult:
    key = get_settings().urlhaus_auth_key
    if not key:
        return IntelResult("urlhaus", "disabled", "No Auth-Key configured")

    async def fetch() -> IntelResult:
        async with _client() as client:
            r = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": key})
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") != "ok":
            return IntelResult("urlhaus", "clean", "URL not listed in URLhaus")
        status = data.get("url_status", "unknown")
        threat = data.get("threat") or "malware distribution"
        return IntelResult(
            "urlhaus", "malicious", f"Listed for {threat.replace('_', ' ')} (status: {status})",
            data.get("urlhaus_reference"), {"url_status": status, "tags": data.get("tags") or []},
        )

    return await _cached("urlhaus", "url", url, fetch)


async def urlhaus_host(host: str) -> IntelResult:
    key = get_settings().urlhaus_auth_key
    if not key:
        return IntelResult("urlhaus", "disabled", "No Auth-Key configured")

    async def fetch() -> IntelResult:
        async with _client() as client:
            r = await client.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host}, headers={"Auth-Key": key})
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") != "ok":
            return IntelResult("urlhaus", "clean", "Host not listed in URLhaus")
        urls = data.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        return IntelResult(
            "urlhaus", "suspicious",
            f"Host has served {data.get('url_count', len(urls))} malicious URL(s), {online} currently online",
            data.get("urlhaus_reference"), {"url_count": data.get("url_count"), "online": online},
        )

    return await _cached("urlhaus", "host", host, fetch)


# ------------------------------------------------------------------------- PhishTank


async def phishtank_url(url: str) -> IntelResult:
    s = get_settings()
    if not s.phishtank_app_key:
        return IntelResult("phishtank", "disabled", "No app key configured")

    async def fetch() -> IntelResult:
        async with _client() as client:
            r = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data={"url": url, "format": "json", "app_key": s.phishtank_app_key},
                headers={"User-Agent": f"phishtank/{s.phishtank_username}"},
            )
        r.raise_for_status()
        res = r.json().get("results", {})
        if not res.get("in_database"):
            return IntelResult("phishtank", "clean", "Not in the PhishTank database")
        ref = res.get("phish_detail_page")
        if res.get("verified") and res.get("valid"):
            return IntelResult("phishtank", "malicious", f"Verified phish (ID {res.get('phish_id')})", ref)
        return IntelResult("phishtank", "suspicious", "Reported to PhishTank, not yet verified", ref)

    return await _cached("phishtank", "url", url, fetch)


# --------------------------------------------------------------- local threat records


def local_lookup(indicators: list[tuple[str, str]]) -> IntelResult:
    matches = database.match_threats(indicators)
    if not matches:
        return IntelResult("local", "clean", "No match in local threat records")
    first = matches[0]
    detail = f"Matches {first['indicator_type']} record '{first['indicator']}' ({first['threat_type']})"
    if len(matches) > 1:
        detail += f" and {len(matches) - 1} more"
    return IntelResult("local", "malicious", detail, None, {"records": matches})
