"""Domain intelligence: registration age (RDAP / WHOIS), DNS records and TLS certificate."""

from __future__ import annotations

import asyncio
import logging
import ssl
from datetime import UTC, datetime
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from ..config import get_settings
from ..core.net import BlockedTarget, ensure_public_host
from ..schemas import Finding

log = logging.getLogger(__name__)


def _parse_date(value: Any) -> datetime | None:
    if isinstance(value, list):
        value = next((v for v in value if v), None)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------- registration


async def _rdap(domain: str) -> dict[str, Any] | None:
    async with httpx.AsyncClient(timeout=get_settings().http_timeout, follow_redirects=True) as client:
        r = await client.get(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"})
    if r.status_code == 404:
        return {"source": "rdap", "found": False}
    if r.status_code != 200:
        return None
    data = r.json()
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = None
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
    return {
        "source": "rdap",
        "found": True,
        "created": events.get("registration"),
        "expires": events.get("expiration"),
        "updated": events.get("last changed") or events.get("last update of RDAP database"),
        "registrar": registrar,
        "status": data.get("status", []),
        "nameservers": sorted({ns.get("ldhName", "").lower() for ns in data.get("nameservers", []) if ns.get("ldhName")}),
    }


def _whois_sync(domain: str) -> dict[str, Any] | None:
    import whois  # python-whois; imported lazily because it is slow to import

    w = whois.whois(domain)
    if not w or not w.get("domain_name"):
        return {"source": "whois", "found": False}
    created, expires, updated = (_parse_date(w.get(k)) for k in ("creation_date", "expiration_date", "updated_date"))
    ns = w.get("name_servers") or []
    return {
        "source": "whois",
        "found": True,
        "created": created.isoformat() if created else None,
        "expires": expires.isoformat() if expires else None,
        "updated": updated.isoformat() if updated else None,
        "registrar": w.get("registrar"),
        "status": w.get("status") if isinstance(w.get("status"), list) else [w.get("status")] if w.get("status") else [],
        "nameservers": sorted({n.lower() for n in (ns if isinstance(ns, list) else [ns])}),
    }


async def lookup_registration(domain: str) -> dict[str, Any]:
    result: dict[str, Any] | None = None
    try:
        result = await _rdap(domain)
    except (httpx.HTTPError, ValueError) as exc:
        log.info("RDAP failed for %s: %s", domain, exc)
    if not result or (result.get("found") and not result.get("created")):
        try:
            whois_result = await asyncio.wait_for(asyncio.to_thread(_whois_sync, domain), timeout=12)
            if whois_result and (whois_result.get("created") or not result):
                result = whois_result
        except Exception as exc:  # noqa: BLE001 - whois raises many unrelated exception types
            log.info("WHOIS failed for %s: %s", domain, exc)
    if not result:
        return {"found": None, "error": "Registration data unavailable"}
    created = _parse_date(result.get("created"))
    if created:
        result["age_days"] = (datetime.now(UTC) - created).days
    return result


# ------------------------------------------------------------------------------- DNS


async def lookup_dns(host: str, registered: str) -> dict[str, Any]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    resolver.timeout = 2.5

    async def query(name: str, rtype: str) -> list[str] | str:
        try:
            ans = await resolver.resolve(name, rtype)
            return [r.to_text().strip('"') if rtype != "TXT" else b"".join(r.strings).decode(errors="replace") for r in ans]
        except dns.resolver.NXDOMAIN:
            return "NXDOMAIN"
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.Timeout:
            return "TIMEOUT"
        except dns.exception.DNSException as exc:
            return f"ERROR: {exc.__class__.__name__}"

    keys = [("a", host, "A"), ("aaaa", host, "AAAA"), ("cname", host, "CNAME"), ("mx", registered, "MX"),
            ("ns", registered, "NS"), ("txt", registered, "TXT"), ("dmarc", f"_dmarc.{registered}", "TXT")]
    answers = await asyncio.gather(*(query(name, rtype) for _, name, rtype in keys))
    raw = {k: v for (k, _, _), v in zip(keys, answers, strict=True)}

    def lst(key: str) -> list[str]:
        v = raw[key]
        return v if isinstance(v, list) else []

    spf = [t for t in lst("txt") if t.lower().startswith("v=spf1")]
    dmarc = [t for t in lst("dmarc") if t.lower().startswith("v=dmarc1")]
    dmarc_policy = None
    if dmarc:
        for part in dmarc[0].split(";"):
            k, _, v = part.strip().partition("=")
            if k.lower() == "p":
                dmarc_policy = v.strip().lower()
    return {
        "nxdomain": raw["a"] == "NXDOMAIN" and raw["ns"] == "NXDOMAIN",
        "a": lst("a"),
        "aaaa": lst("aaaa"),
        "cname": lst("cname"),
        "mx": sorted(lst("mx")),
        "ns": sorted(lst("ns")),
        "spf": spf[0] if spf else None,
        "dmarc": dmarc[0] if dmarc else None,
        "dmarc_policy": dmarc_policy,
        "errors": {k: v for k, v in raw.items() if isinstance(v, str) and v != "NXDOMAIN"},
    }


# ------------------------------------------------------------------------------- TLS


def _name_attr(name: x509.Name, oid) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


async def fetch_certificate(host: str, port: int = 443) -> dict[str, Any]:
    try:
        await ensure_public_host(host)
    except BlockedTarget as exc:
        return {"available": False, "skipped": True, "error": str(exc)}
    except OSError:
        return {"available": False, "error": "Host does not resolve"}

    timeout = min(get_settings().http_timeout, 6.0)

    async def handshake(ctx: ssl.SSLContext) -> bytes:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=timeout
        )
        try:
            return writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        finally:
            writer.close()

    verified, verify_error = True, None
    try:
        der = await handshake(ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        verified, verify_error = False, exc.verify_message or str(exc)
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        try:
            der = await handshake(insecure)
        except (OSError, TimeoutError, ssl.SSLError) as exc2:
            return {"available": False, "verified": False, "error": f"{verify_error}; {exc2}"}
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        return {"available": False, "error": f"No HTTPS on port {port}: {exc.__class__.__name__}"}

    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    now = datetime.now(UTC)
    not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc
    return {
        "available": True,
        "verified": verified,
        "error": verify_error,
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "issuer_cn": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "self_signed": cert.issuer == cert.subject,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "age_days": (now - not_before).days,
        "days_remaining": (not_after - now).days,
        "validity_days": (not_after - not_before).days,
        "san": san[:50],
        "san_count": len(san),
        "serial": format(cert.serial_number, "x"),
    }


# -------------------------------------------------------------------------- findings


def registration_findings(reg: dict[str, Any], domain: str) -> list[Finding]:
    out: list[Finding] = []
    age = reg.get("age_days")
    if reg.get("found") is False:
        out.append(Finding(id="domain.unregistered", category="domain", severity="medium", weight=0.2,
                           title="Domain not registered", detail=f"No registration record exists for {domain}."))
    elif age is None:
        out.append(Finding(id="domain.age_unknown", category="domain", kind="info", severity="info",
                           title="Registration age unavailable", detail=reg.get("error") or "Registry did not return a creation date."))
    elif age < 30:
        out.append(Finding(id="domain.age_new", category="domain", severity="high", weight=0.5,
                           title="Newly registered domain", detail=f"{domain} was registered {age} day{'s' if age != 1 else ''} ago. Most phishing domains are used within weeks of registration."))
    elif age < 180:
        out.append(Finding(id="domain.age_young", category="domain", severity="medium", weight=0.25,
                           title="Recently registered domain", detail=f"{domain} is only {age} days old."))
    elif age < 365:
        out.append(Finding(id="domain.age_recent", category="domain", severity="low", weight=0.1,
                           title="Domain less than a year old", detail=f"{domain} was registered {age} days ago."))
    elif age >= 365 * 5:
        out.append(Finding(id="domain.age_established", category="domain", kind="trust", severity="info", weight=0.35,
                           title="Long-established domain", detail=f"Registered {age // 365} years ago."))
    elif age >= 365 * 2:
        out.append(Finding(id="domain.age_established", category="domain", kind="trust", severity="info", weight=0.2,
                           title="Established domain", detail=f"Registered {age // 365} years ago."))
    statuses = " ".join(reg.get("status") or []).lower().replace(" ", "")
    if "clienthold" in statuses or "serverhold" in statuses:
        out.append(Finding(id="domain.on_hold", category="domain", severity="medium", weight=0.25,
                           title="Domain placed on hold", detail="Registry status includes clientHold/serverHold, often applied to abusive domains."))
    return out


def dns_findings(dns_info: dict[str, Any], host: str) -> list[Finding]:
    out: list[Finding] = []
    if dns_info.get("nxdomain"):
        out.append(Finding(id="dns.nxdomain", category="dns", severity="medium", weight=0.2,
                           title="Domain does not resolve", detail=f"DNS returns NXDOMAIN for {host}; it may have been taken down."))
        return out
    if not dns_info.get("a") and not dns_info.get("aaaa") and not dns_info.get("errors"):
        out.append(Finding(id="dns.no_address", category="dns", severity="low", weight=0.08,
                           title="No address records", detail=f"{host} has no A/AAAA records."))
    if not dns_info.get("mx"):
        out.append(Finding(id="dns.no_mx", category="dns", severity="low", weight=0.04,
                           title="No mail servers", detail="The domain publishes no MX records, unusual for an established organisation."))
    if not dns_info.get("spf") and not dns_info.get("dmarc"):
        out.append(Finding(id="dns.no_email_auth", category="dns", severity="low", weight=0.04,
                           title="No SPF or DMARC", detail="The domain publishes no email authentication policy, so its name is easy to spoof."))
    elif dns_info.get("dmarc_policy") in ("reject", "quarantine"):
        out.append(Finding(id="dns.dmarc_enforced", category="dns", kind="trust", severity="info", weight=0.05,
                           title="Enforced DMARC policy", detail=f"DMARC p={dns_info['dmarc_policy']}."))
    return out


def tls_findings(cert: dict[str, Any], host: str, scheme_https: bool | None = None) -> list[Finding]:
    out: list[Finding] = []
    if cert.get("skipped"):
        return out
    if not cert.get("available"):
        if cert.get("verified") is False:
            out.append(Finding(id="tls.invalid", category="tls", severity="high", weight=0.35,
                               title="Invalid TLS certificate", detail=cert.get("error", "")))
        else:
            out.append(Finding(id="tls.unavailable", category="tls", severity="low", weight=0.1,
                               title="HTTPS not available", detail=cert.get("error") or f"{host} does not serve HTTPS."))
        return out
    if not cert.get("verified"):
        reason = cert.get("error") or "verification failed"
        if cert.get("self_signed"):
            reason = "self-signed certificate"
        out.append(Finding(id="tls.invalid", category="tls", severity="high", weight=0.35,
                           title="Invalid TLS certificate", detail=f"Certificate for {host} failed validation: {reason}."))
    age = cert.get("age_days", 999)
    # Certificates now rotate every few weeks, so only a brand-new one is (weakly) notable.
    if age <= 2:
        out.append(Finding(id="tls.new_cert", category="tls", severity="low", weight=0.06,
                           title="Certificate issued in the last 48 hours", detail=f"Issued {cert.get('not_before', '')[:10]} by {cert.get('issuer_org') or cert.get('issuer_cn')}."))
    if cert.get("verified"):
        out.append(Finding(id="tls.valid", category="tls", kind="info", severity="info",
                           title="Valid TLS certificate", detail=f"Issued by {cert.get('issuer_org') or cert.get('issuer_cn')}, expires in {cert.get('days_remaining')} days. Note: valid HTTPS does not imply a site is legitimate."))
    return out
