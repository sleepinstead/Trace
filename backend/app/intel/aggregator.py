"""Fan out lookups to every configured intel provider and turn the answers into findings."""

from __future__ import annotations

import asyncio
from typing import Any

from ..schemas import Finding
from . import providers
from .providers import IntelResult

SOURCE_NAMES = {p["source"]: p["name"] for p in providers.provider_status()}


async def check_url(url: str, host: str, registered: str, *, external: bool = True) -> list[IntelResult]:
    local = providers.local_lookup([(url, "url"), (host, "domain"), (registered, "domain"), (host, "ip")])
    if not external:
        return [local]
    results = await asyncio.gather(
        providers.virustotal_url(url),
        providers.safebrowsing_urls([url]),
        providers.urlhaus_url(url),
        providers.phishtank_url(url),
    )
    return [local, *results]


async def check_domain(domain: str, registered: str, *, external: bool = True) -> list[IntelResult]:
    local = providers.local_lookup([(domain, "domain"), (registered, "domain")])
    if not external:
        return [local]
    results = await asyncio.gather(
        providers.virustotal_domain(domain),
        providers.safebrowsing_urls([f"http://{domain}/", f"https://{domain}/"]),
        providers.urlhaus_host(domain),
    )
    return [local, *results]


def to_findings(results: list[IntelResult], subject: str = "") -> list[Finding]:
    findings = []
    for r in results:
        name = SOURCE_NAMES.get(r.source, r.source)
        if r.status == "malicious":
            findings.append(Finding(
                id=f"intel.{r.source}", category="intel", kind="risk", severity="critical",
                title=f"Flagged by {name}", detail=f"{subject}{r.detail}", weight=0.9,
            ))
        elif r.status == "suspicious":
            findings.append(Finding(
                id=f"intel.{r.source}", category="intel", kind="risk", severity="high",
                title=f"Reported to {name}", detail=f"{subject}{r.detail}", weight=0.45,
            ))
    return findings


def summarize(results: list[IntelResult]) -> dict[str, Any]:
    return {
        "malicious": sum(r.status == "malicious" for r in results),
        "suspicious": sum(r.status == "suspicious" for r in results),
        "checked": sum(r.status in ("malicious", "suspicious", "clean", "unknown") for r in results),
        "sources": [r.to_dict() | {"name": SOURCE_NAMES.get(r.source, r.source)} for r in results],
    }
