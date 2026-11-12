"""Orchestrates URL and domain scans: rules + ML + active checks + domain intel + threat feeds."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

from ..core import scoring
from ..core.urltools import InvalidURL, free_hosting_platform, is_popular, is_shortener, parse_url, split_domain
from ..database import utcnow
from ..intel import aggregator
from ..ml.predictor import classifier
from ..schemas import Finding
from . import domain_intel, web
from .url_rules import url_rules

DOMAIN_TIMEOUT = 15
WEB_TIMEOUT = 25
INTEL_TIMEOUT = 15


async def _with_timeout(coro, timeout: float, default):
    try:
        return await asyncio.wait_for(coro, timeout)
    except TimeoutError:
        return default


def _ml_finding(ml: dict[str, Any], prefix: str = "") -> Finding | None:
    p = ml["probability"]
    reasons = ", ".join(e["label"].lower() for e in ml["explanations"] if e["direction"] == "phishing")[:200]
    title_prefix = "Destination: " if prefix else ""
    if p >= 0.8:
        return Finding(id=f"{prefix}ml.phishing", category="ml", severity="high", weight=0.0,
                       title=f"{title_prefix}ML model: likely phishing ({p:.0%})", detail=f"Main factors: {reasons or 'combined lexical features'}.")
    if p >= 0.5:
        return Finding(id=f"{prefix}ml.suspicious", category="ml", severity="medium", weight=0.0,
                       title=f"{title_prefix}ML model: leans phishing ({p:.0%})", detail=f"Main factors: {reasons or 'combined lexical features'}.")
    return None


def build_result(scan_type: str, target: str, findings: list[Finding], combined: dict, details: dict, started: float, subject: str) -> dict[str, Any]:
    findings = scoring.sort_findings(findings)
    return {
        "id": uuid.uuid4().hex,
        "scan_type": scan_type,
        "target": target,
        "verdict": combined["verdict"],
        "risk_score": combined["risk_score"],
        "summary": scoring.summarize(combined["verdict"], findings, subject),
        "findings": [f.model_dump() for f in findings],
        "score_breakdown": combined["breakdown"],
        "details": details,
        "created_at": utcnow().isoformat(),
        "duration_ms": int((time.perf_counter() - started) * 1000),
    }


# ------------------------------------------------------------------------------- URL


async def scan_url(raw_url: str, *, deep: bool = True, use_intel: bool = True) -> dict[str, Any]:
    started = time.perf_counter()
    u = parse_url(raw_url)  # raises InvalidURL
    findings: list[Finding] = url_rules(u)
    ml = classifier.predict(u.url)

    tasks: dict[str, Any] = {
        "intel": _with_timeout(aggregator.check_url(u.url, u.host, u.registered_domain, external=use_intel), INTEL_TIMEOUT, []),
    }
    if deep:
        tasks["web"] = _with_timeout(web.follow_redirects(u.url), WEB_TIMEOUT, {"chain": [], "final_url": u.url, "html": "", "error": "Timed out", "blocked": False})
        if not u.is_ip:
            tasks["registration"] = _with_timeout(domain_intel.lookup_registration(u.registered_domain), DOMAIN_TIMEOUT, {"found": None, "error": "Timed out"})
            tasks["dns"] = _with_timeout(domain_intel.lookup_dns(u.host, u.registered_domain), DOMAIN_TIMEOUT, None)
            if u.scheme == "https":
                tasks["tls"] = _with_timeout(domain_intel.fetch_certificate(u.host, u.port or 443), DOMAIN_TIMEOUT, {"available": False, "error": "Timed out"})
    results = dict(zip(tasks, await asyncio.gather(*tasks.values()), strict=True))

    details: dict[str, Any] = {
        "url": u.url,
        "parsed": {
            "scheme": u.scheme, "userinfo": u.userinfo, "host": u.host, "port": u.port, "path": u.path,
            "query": u.query, "fragment": u.fragment,
            "subdomain": u.subdomain, "domain": u.domain, "suffix": u.suffix,
            "registered_domain": u.registered_domain, "is_ip": u.is_ip,
        },
        "ml": ml,
        "deep": deep,
    }
    ml_prob = ml["probability"]

    final_popular = is_popular(u.registered_domain) and not free_hosting_platform(u.host)
    if deep:
        web_result = results["web"]
        final_url = web_result.get("final_url", u.url)
        page = web.inspect_page(web_result.get("html", ""), final_url)
        details["redirects"] = {"chain": web_result.get("chain", []), "final_url": final_url, "error": web_result.get("error")}
        details["page"] = page
        findings += web.redirect_findings(web_result, u.url, from_shortener=is_shortener(u.host))

        try:
            fu = parse_url(final_url)
        except InvalidURL:
            fu = u
        if fu.registered_domain != u.registered_domain:
            # Judge the landing site on its own merits, and drop trust earned by the first hop.
            final_popular = is_popular(fu.registered_domain) and not free_hosting_platform(fu.host)
            findings = [f for f in findings if f.id != "url.popular_domain"]
            final_findings = url_rules(fu, prefix="final.")
            findings += [f for f in final_findings if f.kind == "risk"]
            if final_popular:
                findings += [f for f in final_findings if f.kind == "trust"]
            final_ml = classifier.predict(fu.url)
            details["final_ml"] = final_ml
            if (mf := _ml_finding(final_ml, prefix="final.")) is not None:
                findings.append(mf)
            if is_shortener(u.host):
                # The shortener's own URL says nothing once we know where it leads.
                ml_prob = final_ml["probability"]
                findings = [f for f in findings if f.id not in ("url.shortener", "ml.phishing", "ml.suspicious")]
                details["ml_note"] = "Score uses the resolved destination; the short link itself carries no signal."
            else:
                ml_prob = max(ml_prob, final_ml["probability"])
        findings += web.page_findings(page, final_url, popular=final_popular)

        if not u.is_ip:
            reg, dns_info, tls = results.get("registration"), results.get("dns"), results.get("tls")
            details["domain"] = {"registration": reg, "dns": dns_info, "tls": tls}
            if reg:
                findings += domain_intel.registration_findings(reg, u.registered_domain)
            if dns_info:
                findings += domain_intel.dns_findings(dns_info, u.host)
            if tls:
                findings += domain_intel.tls_findings(tls, u.host)

    if "ml_note" not in details and (mf := _ml_finding(ml)) is not None:
        findings.append(mf)

    intel_results = results["intel"]
    findings += aggregator.to_findings(intel_results)
    intel_summary = aggregator.summarize(intel_results)
    details["intel"] = intel_summary

    # Trust from an established registration should not offset a known-bad landing page.
    if not final_popular:
        findings = [f for f in findings if not (f.kind == "trust" and f.id == "url.popular_domain")]

    combined = scoring.combine(
        findings, ml_probability=ml_prob, ml_weight=0.45,
        intel_malicious=intel_summary["malicious"], intel_suspicious=intel_summary["suspicious"],
    )
    return build_result("url", u.url, findings, combined, details, started, "This URL")


# ---------------------------------------------------------------------------- domain


def normalize_domain(raw: str) -> str:
    value = raw.strip().lower()
    if "://" in value or "/" in value or "@" in value:
        value = parse_url(value).host
    value = value.strip(".")
    if not value or " " in value or "." not in value:
        raise InvalidURL("Enter a domain name such as example.com")
    return value


async def scan_domain(raw_domain: str, *, use_intel: bool = True) -> dict[str, Any]:
    started = time.perf_counter()
    domain = normalize_domain(raw_domain)
    u = parse_url(f"https://{domain}/")
    registered = u.registered_domain
    findings: list[Finding] = url_rules(u, domain_only=True)
    ml = classifier.predict(f"https://{domain}/")

    registration, dns_info, tls, homepage, intel_results = await asyncio.gather(
        _with_timeout(domain_intel.lookup_registration(registered), DOMAIN_TIMEOUT, {"found": None, "error": "Timed out"}),
        _with_timeout(domain_intel.lookup_dns(domain, registered), DOMAIN_TIMEOUT, None),
        _with_timeout(domain_intel.fetch_certificate(domain), DOMAIN_TIMEOUT, {"available": False, "error": "Timed out"}),
        _with_timeout(web.follow_redirects(f"https://{domain}/"), WEB_TIMEOUT, {"chain": [], "final_url": f"https://{domain}/", "html": "", "error": "Timed out", "blocked": False}),
        _with_timeout(aggregator.check_domain(domain, registered, external=use_intel), INTEL_TIMEOUT, []),
    )

    popular = is_popular(registered) and not free_hosting_platform(domain)
    findings += domain_intel.registration_findings(registration, registered)
    if dns_info:
        findings += domain_intel.dns_findings(dns_info, domain)
    findings += domain_intel.tls_findings(tls, domain)
    page = web.inspect_page(homepage.get("html", ""), homepage.get("final_url", ""))
    findings += web.page_findings(page, homepage.get("final_url", f"https://{domain}/"), popular=popular)
    if (mf := _ml_finding(ml)) is not None:
        findings.append(mf)
    findings += aggregator.to_findings(intel_results)
    intel_summary = aggregator.summarize(intel_results)

    sub, dom, suf = split_domain(domain)
    details = {
        "domain": domain,
        "registered_domain": registered,
        "subdomain": sub,
        "suffix": suf,
        "registration": registration,
        "dns": dns_info,
        "tls": tls,
        "homepage": {"chain": homepage.get("chain", []), "final_url": homepage.get("final_url"), "error": homepage.get("error"), "page": page},
        "ml": ml,
        "intel": intel_summary,
    }
    combined = scoring.combine(
        findings, ml_probability=ml["probability"], ml_weight=0.3,
        intel_malicious=intel_summary["malicious"], intel_suspicious=intel_summary["suspicious"],
    )
    return build_result("domain", domain, findings, combined, details, started, "This domain")
