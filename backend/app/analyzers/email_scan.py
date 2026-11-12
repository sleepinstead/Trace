"""Email phishing analysis: sender, authentication (SPF/DKIM/DMARC), content, links and attachments."""

from __future__ import annotations

import asyncio
import email
import email.policy
from html.parser import HTMLParser
import re
import time
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from typing import Any
from urllib.parse import urlsplit

from ..core import scoring
from ..core.indicators import ARCHIVE_EXTENSIONS, FREE_EMAIL_PROVIDERS, RISKY_ATTACHMENT_EXTENSIONS
from ..core.urltools import (
    brand_label,
    InvalidURL,
    brand_owns,
    brands_mentioned,
    combosquat_target,
    is_shortener,
    parse_url,
    registered_domain,
    typosquat_target,
)
from ..intel import aggregator
from ..ml.predictor import classifier
from ..schemas import Finding
from . import domain_intel
from .scan import build_result
from .url_rules import url_rules

MAX_LINKS = 25
INTEL_LINKS = 5

PHRASES: dict[str, tuple[str, str, float, tuple[str, ...]]] = {
    "urgency": ("Urgent or time-pressure language", "medium", 0.15, (
        "urgent", "immediately", "within 24 hours", "within 48 hours", "act now", "as soon as possible",
        "final notice", "final warning", "expires today", "expire today", "limited time", "last warning",
        "action required", "immediate action", "respond now", "right away", "before it's too late", "deadline",
    )),
    "threat": ("Account threat or security alarm", "high", 0.25, (
        "will be suspended", "has been suspended", "been locked", "will be locked", "will be closed",
        "unusual activity", "unusual sign-in", "unauthorized access", "suspicious activity", "security alert",
        "verify your account", "confirm your identity", "account has been limited", "compromised",
        "permanently deleted", "lose access", "deactivated", "restricted",
    )),
    "credentials": ("Requests credentials or sensitive data", "high", 0.3, (
        "password", "login credentials", "social security", "ssn", "credit card number", "card number",
        "bank account", "verify your", "update your payment", "billing information", "pin number",
        "security code", "cvv", "one-time code", "mother's maiden", "seed phrase", "recovery phrase",
        "confirm your details", "update your details", "sign in to", "log in to",
    )),
    "lure": ("Financial lure or reward", "medium", 0.15, (
        "you have won", "you've won", "winner", "prize", "lottery", "gift card", "refund", "tax refund",
        "unclaimed", "wire transfer", "bitcoin", "crypto", "inheritance", "compensation", "cash reward",
        "claim your", "free gift", "investment opportunity", "outstanding invoice", "overdue invoice",
    )),
    "generic_greeting": ("Generic greeting", "low", 0.08, (
        "dear customer", "dear user", "dear valued", "dear account holder", "dear client", "hello user",
        "dear member", "dear sir/madam", "dear beneficiary", "dear email user",
    )),
    "bec": ("Business email compromise patterns", "high", 0.3, (
        "are you available", "quick favor", "quick favour", "purchase gift cards", "keep this confidential",
        "change of bank details", "updated banking details", "new bank account", "process a payment",
        "i need you to", "kindly", "do not share this with",
    )),
}

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+", re.I)
_BLOCK_TAGS = {"br", "p", "div", "tr", "li"}
MAX_HTML = 1_000_000  # characters parsed; the parser is linear, this just bounds the work


class _Html(HTMLParser):
    """One linear pass: anchors, visible text, and the text outside anchors."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self.text: list[str] = []
        self.loose: list[str] = []
        self._skip = 0
        self._href: str | None = None
        self._inner: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a" and self._href is None:
            self._href, self._inner = dict(attrs).get("href") or "", []
        elif tag in _BLOCK_TAGS:
            self.text.append("\n")
            self.loose.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag == "a" and self._href is not None:
            self.anchors.append((self._href, "".join(self._inner)))
            self._href = None
        elif tag in _BLOCK_TAGS:
            self.text.append("\n")
            self.loose.append("\n")

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        (self._inner if self._href is not None else self.loose).append(data)

    def close(self):
        super().close()
        if self._href is not None:  # unclosed <a>
            self.anchors.append((self._href, "".join(self._inner)))
            self._href = None


def _parse_html(markup: str) -> _Html:
    parser = _Html()
    parser.feed(markup[:MAX_HTML])
    parser.close()
    return parser


def _tidy(parts: list[str]) -> str:
    text = re.sub(r"[ \t\r\f\v]+", " ", " ".join(parts).replace(" \n ", "\n"))
    return re.sub(r"\n{3,}", "\n\n", "\n".join(line.strip() for line in text.split("\n"))).strip()


def html_to_text(markup: str) -> str:
    return _tidy(_parse_html(markup).text)


_DOMAINISH = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)



def parse_message(raw: str | None, sender: str | None, subject: str | None, body: str | None) -> EmailMessage:
    if raw and raw.strip():
        text = raw.replace("\r\n", "\n")
        msg = email.message_from_string(text, policy=email.policy.default)
        # A paste without headers parses as body-only; keep it usable.
        if not msg.keys() and text.strip():
            msg = EmailMessage()
            msg.set_content(text)
        return msg  # type: ignore[return-value]
    msg = EmailMessage()
    if sender:
        msg["From"] = sender
    if subject:
        msg["Subject"] = subject
    content = body or ""
    if re.search(r"<(html|body|a|div|p|table)\b", content, re.I):
        msg.set_content(content, subtype="html")
    else:
        msg.set_content(content)
    return msg


def _bodies(msg: EmailMessage) -> tuple[str, str]:
    plain, rich = [], []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        try:
            content = part.get_content()
        except (LookupError, ValueError, AssertionError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload)
        if not isinstance(content, str):
            continue
        if ctype == "text/html":
            rich.append(content)
        elif ctype == "text/plain":
            plain.append(content)
    return "\n".join(plain), "\n".join(rich)


def _attachments(msg: EmailMessage) -> list[dict[str, Any]]:
    out = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename and part.get_content_disposition() != "attachment":
            continue
        filename = filename or "(unnamed)"
        payload = part.get_payload(decode=True) or b""
        exts = [e.lower() for e in filename.split(".")[1:]]
        out.append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "size": len(payload) if isinstance(payload, bytes) else 0,
            "extension": exts[-1] if exts else "",
            "double_extension": len(exts) >= 2 and exts[-1] in RISKY_ATTACHMENT_EXTENSIONS,
        })
    return out


def _parse_auth_results(msg: EmailMessage) -> dict[str, Any]:
    results: dict[str, Any] = {"spf": None, "dkim": None, "dmarc": None, "source": None}
    headers = msg.get_all("Authentication-Results") or msg.get_all("ARC-Authentication-Results") or []
    if headers:
        # The topmost header was added by the receiving server, so it is the trustworthy one.
        text = str(headers[0])
        results["source"] = "Authentication-Results"
        results["raw"] = text[:500]
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"\b{mech}\s*=\s*([a-z]+)", text, re.I)
            if m:
                results[mech] = m.group(1).lower()
        if m := re.search(r"header\.from\s*=\s*([^\s;]+)", text, re.I):
            results["header_from"] = m.group(1).lower()
        if m := re.search(r"smtp\.mailfrom\s*=\s*([^\s;]+)", text, re.I):
            results["mailfrom"] = m.group(1).lower().rsplit("@", 1)[-1]
        if m := re.search(r"header\.d\s*=\s*([^\s;]+)", text, re.I):
            results["dkim_domain"] = m.group(1).lower()
    received_spf = msg.get("Received-SPF")
    if received_spf and not results["spf"]:
        results["spf"] = str(received_spf).split()[0].lower()
        results["source"] = results["source"] or "Received-SPF"
    sig = msg.get("DKIM-Signature")
    if sig:
        if m := re.search(r"\bd=([^;\s]+)", str(sig)):
            results["dkim_signature_domain"] = m.group(1).lower()
    return results


def extract_links(plain: str, rich: str) -> list[dict[str, Any]]:
    links: dict[str, dict[str, Any]] = {}
    parsed = _parse_html(rich) if rich else None
    for href, inner in parsed.anchors if parsed else []:
        href = href.strip()
        if not href.lower().startswith(("http://", "https://", "www.")):
            continue
        text = _tidy([inner])[:200]
        entry = links.setdefault(href, {"url": href, "anchor_texts": [], "mismatch": None})
        if text and text not in entry["anchor_texts"]:
            entry["anchor_texts"].append(text)
        shown = _DOMAINISH.search(text or "")
        if shown and "." in shown.group(1):
            try:
                shown_reg = registered_domain(shown.group(1))
                href_reg = parse_url(href).registered_domain
                if shown_reg != href_reg and "." in shown_reg and not shown_reg.endswith((".png", ".jpg", ".gif")):
                    entry["mismatch"] = {"shown": shown.group(1).lower(), "actual": parse_url(href).host}
            except InvalidURL:
                pass
    # Visible text of anchors is not a link; only scan text outside <a> elements.
    loose_html_text = _tidy(parsed.loose) if parsed else ""
    for match in _URL_RE.findall(plain + "\n" + loose_html_text):
        url = match.rstrip(".,;:!?")
        links.setdefault(url, {"url": url, "anchor_texts": [], "mismatch": None})
    return list(links.values())[:MAX_LINKS]


def _sender_findings(msg: EmailMessage, auth: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    out: list[Finding] = []
    display, address = parseaddr(str(msg.get("From", "")))
    address = address.lower()
    domain = address.rsplit("@", 1)[-1] if "@" in address else ""
    reg = registered_domain(domain) if domain else ""
    reply_to = [a.lower() for _, a in getaddresses([str(v) for v in msg.get_all("Reply-To") or []]) if a]
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1].lower()
    info = {
        "display_name": display, "address": address, "domain": domain, "registered_domain": reg,
        "reply_to": reply_to, "return_path": return_path,
        "subject": str(msg.get("Subject", "")), "date": str(msg.get("Date", "")),
        "message_id": str(msg.get("Message-ID", "")), "received_hops": len(msg.get_all("Received") or []),
        "x_mailer": str(msg.get("X-Mailer", "")) or None,
    }
    if not address:
        return out, info

    claimed = [b for b in brands_mentioned(display) if not brand_owns(b, reg)] if display else []
    if claimed:
        out.append(Finding(id="email.display_name_spoof", category="sender", severity="high", weight=0.45,
                           title=f"Sender name claims to be {brand_label(claimed[0])}",
                           detail=f"Display name '{display}' but the address is {address}, which {brand_label(claimed[0])} does not own."))
    if "@" in display and parseaddr(display)[1] and parseaddr(display)[1].lower() != address:
        out.append(Finding(id="email.display_address_mismatch", category="sender", severity="high", weight=0.4,
                           title="Display name shows a different address", detail=f"Shows '{display}' but sent from {address}."))
    if typo := typosquat_target(reg.split(".")[0] if reg else ""):
        out.append(Finding(id="email.lookalike_domain", category="sender", severity="high", weight=0.55,
                           title=f"Sender domain imitates {brand_label(typo[0])}", detail=f"{domain} ({typo[1]})."))
    elif (combo := combosquat_target(reg.split(".")[0] if reg else "")) and not brand_owns(combo, reg):
        out.append(Finding(id="email.brand_domain", category="sender", severity="high", weight=0.4,
                           title=f"Sender domain uses the {brand_label(combo)} name", detail=f"{domain} is not an official {brand_label(combo)} domain."))
    if reg in FREE_EMAIL_PROVIDERS and display and re.search(r"\b(support|security|team|billing|service|admin|account|helpdesk|it department|payroll|hr)\b", display, re.I):
        out.append(Finding(id="email.free_provider_org", category="sender", severity="medium", weight=0.25,
                           title="Organisation name on a free email account", detail=f"'{display}' is sending from a personal {reg} address."))
    for rt in reply_to:
        rt_reg = registered_domain(rt.rsplit("@", 1)[-1])
        if rt_reg and rt_reg != reg:
            out.append(Finding(id="email.reply_to_mismatch", category="sender", severity="medium", weight=0.25,
                               title="Replies go to a different domain", detail=f"Reply-To is {rt}, not {reg}."))
            break
    if return_path and "@" in return_path:
        rp_reg = registered_domain(return_path.rsplit("@", 1)[-1])
        if rp_reg != reg and not auth.get("dmarc") == "pass":
            out.append(Finding(id="email.return_path_mismatch", category="sender", severity="low", weight=0.06,
                               title="Envelope sender differs from From", detail=f"Return-Path {return_path}. Common with mailing services, but also with spoofing."))
    return out, info


def _auth_findings(auth: dict[str, Any], sender_reg: str, dns_info: dict[str, Any] | None) -> list[Finding]:
    out: list[Finding] = []
    spf, dkim, dmarc = auth.get("spf"), auth.get("dkim"), auth.get("dmarc")
    if dmarc == "fail":
        out.append(Finding(id="auth.dmarc_fail", category="authentication", severity="critical", weight=0.6,
                           title="DMARC failed", detail="The message failed the sender domain's DMARC policy; the From address is likely forged."))
    if spf in ("fail", "softfail"):
        out.append(Finding(id="auth.spf_fail", category="authentication", severity="high" if spf == "fail" else "medium",
                           weight=0.35 if spf == "fail" else 0.2, title=f"SPF {spf}", detail="The sending server is not authorised to send mail for this domain."))
    if dkim in ("fail", "neutral", "permerror"):
        out.append(Finding(id="auth.dkim_fail", category="authentication", severity="high", weight=0.3,
                           title=f"DKIM {dkim}", detail="The message signature is missing or invalid, so its content may have been altered or forged."))
    if auth.get("source") and spf == "pass" and dkim == "pass" and dmarc == "pass":
        out.append(Finding(id="auth.all_pass", category="authentication", kind="trust", severity="info", weight=0.3,
                           title="SPF, DKIM and DMARC pass", detail=f"The message genuinely comes from {auth.get('header_from') or sender_reg}. Note: attackers can authenticate their own lookalike domains."))
    if not auth.get("source"):
        out.append(Finding(id="auth.no_results", category="authentication", kind="info", severity="info",
                           title="No authentication results in headers",
                           detail="Paste the full original message (with headers) to evaluate SPF, DKIM and DMARC."))
    if dns_info is not None and sender_reg:
        if dns_info.get("nxdomain"):
            out.append(Finding(id="auth.sender_nxdomain", category="authentication", severity="high", weight=0.45,
                               title="Sender domain does not exist", detail=f"{sender_reg} has no DNS records."))
        elif not dns_info.get("dmarc") and not dns_info.get("spf"):
            out.append(Finding(id="auth.sender_no_policy", category="authentication", severity="low", weight=0.1,
                               title="Sender domain has no SPF or DMARC", detail=f"{sender_reg} publishes no anti-spoofing policy, so anyone can forge it."))
        elif dns_info.get("dmarc_policy") == "none" or not dns_info.get("dmarc"):
            out.append(Finding(id="auth.sender_weak_dmarc", category="authentication", kind="info", severity="info",
                               title="Sender domain does not enforce DMARC", detail=f"{sender_reg} DMARC policy: {dns_info.get('dmarc_policy') or 'none published'}."))
    return out


def _content_findings(subject: str, text: str) -> tuple[list[Finding], dict[str, list[str]]]:
    haystack = f"{subject}\n{text}".lower()
    out: list[Finding] = []
    matched: dict[str, list[str]] = {}
    for key, (title, severity, weight, phrases) in PHRASES.items():
        hits = [p for p in phrases if p in haystack]
        if hits:
            matched[key] = hits
            w = min(weight * (1 + 0.25 * (len(hits) - 1)), weight * 2)
            out.append(Finding(id=f"content.{key}", category="content", severity=severity, weight=round(w, 3),
                               title=title, detail="Found: " + ", ".join(f"'{h}'" for h in hits[:6]) + ".", evidence=hits))
    return out, matched


def _attachment_findings(attachments: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    for att in attachments:
        ext, name = att["extension"], att["filename"]
        if att["double_extension"]:
            out.append(Finding(id="attachment.double_extension", category="attachment", severity="critical", weight=0.6,
                               title="Attachment disguised with a double extension", detail=f"'{name}' looks like a document but is a .{ext} file."))
        elif ext in RISKY_ATTACHMENT_EXTENSIONS:
            sev, w = ("high", 0.45) if ext not in ("html", "htm", "shtml", "svg") else ("high", 0.4)
            reason = "HTML/SVG attachments are used to open fake login pages offline" if ext in ("html", "htm", "shtml", "svg") else "it can run code on your computer"
            out.append(Finding(id="attachment.risky", category="attachment", severity=sev, weight=w,
                               title=f"Risky attachment type (.{ext})", detail=f"'{name}': {reason}."))
        elif ext in ARCHIVE_EXTENSIONS:
            out.append(Finding(id="attachment.archive", category="attachment", severity="low", weight=0.1,
                               title=f"Archive attachment (.{ext})", detail=f"'{name}' may hide executable content from scanners."))
    return out


async def _analyze_links(links: list[dict[str, Any]], use_intel: bool) -> list[dict[str, Any]]:
    analyzed = []
    for link in links:
        try:
            u = parse_url(link["url"])
        except InvalidURL:
            continue
        rules = url_rules(u)
        ml = classifier.predict(u.url)
        combined = scoring.combine(rules, ml_probability=ml["probability"])
        analyzed.append({
            **link,
            "url": u.url,
            "host": u.host,
            "registered_domain": u.registered_domain,
            "risk_score": combined["risk_score"],
            "verdict": combined["verdict"],
            "ml_probability": ml["probability"],
            "findings": [f.title for f in scoring.sort_findings(rules) if f.kind == "risk"][:4],
            "intel": None,
        })
    # Threat-feed lookups for the riskiest links only, to respect API quotas.
    candidates = sorted(analyzed, key=lambda a: a["risk_score"], reverse=True)[:INTEL_LINKS]
    if candidates:
        intel = await asyncio.gather(*(aggregator.check_url(a["url"], a["host"], a["registered_domain"], external=use_intel) for a in candidates))
        for a, res in zip(candidates, intel, strict=True):
            summary = aggregator.summarize(res)
            a["intel"] = summary
            if summary["malicious"]:
                a["risk_score"], a["verdict"] = max(a["risk_score"], 90), "malicious"
            elif summary["suspicious"]:
                a["risk_score"] = max(a["risk_score"], 50)
                a["verdict"] = scoring.verdict_for(a["risk_score"])
    return analyzed


def _link_findings(links: list[dict[str, Any]], sender_reg: str) -> list[Finding]:
    out: list[Finding] = []
    for link in links:
        if link.get("mismatch"):
            mm = link["mismatch"]
            out.append(Finding(id="link.text_mismatch", category="links", severity="high", weight=0.45,
                               title="Link text shows a different site", detail=f"Displays '{mm['shown']}' but opens {mm['actual']}.",
                               evidence=[t for t in link.get("anchor_texts", []) if mm["shown"] in t.lower()][:1] or [mm["shown"]]))
            break
    flagged = [l for l in links if l.get("intel") and l["intel"]["malicious"]]
    if flagged:
        out.append(Finding(id="link.known_malicious", category="links", severity="critical", weight=0.9,
                           title="Contains a known malicious link", detail=f"{flagged[0]['url']} is listed by threat intelligence."))
    risky = sorted((l for l in links if l["verdict"] != "safe"), key=lambda l: l["risk_score"], reverse=True)
    if risky and not flagged:
        top = risky[0]
        sev = "high" if top["verdict"] == "malicious" else "medium"
        reasons = "; ".join(top["findings"][:3]) or "ML classifier"
        out.append(Finding(id="link.risky", category="links", severity=sev, weight=round(top["risk_score"] / 100 * 0.8, 3),
                           title=f"{'Phishing' if top['verdict'] == 'malicious' else 'Suspicious'} link ({top['risk_score']}/100)",
                           detail=f"{top['url']} — {reasons}." + (f" {len(risky) - 1} more risky link(s)." if len(risky) > 1 else "")))
    if any(is_shortener(l["host"]) for l in links):
        out.append(Finding(id="link.shortener", category="links", severity="low", weight=0.1,
                           title="Shortened link", detail="A shortened URL hides where the link really goes."))
    other_domains = {l["registered_domain"] for l in links if l["registered_domain"] != sender_reg}
    if sender_reg and links and len(other_domains) == len({l["registered_domain"] for l in links}):
        out.append(Finding(id="link.offsite", category="links", kind="info", severity="info",
                           title="No links point to the sender's own domain", detail=f"Links go to {', '.join(sorted(other_domains)[:4])}."))
    return out


async def scan_email(raw: str | None = None, *, sender: str | None = None, subject: str | None = None,
                     body: str | None = None, deep: bool = True, use_intel: bool = True) -> dict[str, Any]:
    started = time.perf_counter()
    msg = parse_message(raw, sender, subject, body)
    plain, rich = _bodies(msg)
    text = plain or html_to_text(rich)
    if rich and plain:
        text = plain + "\n" + html_to_text(rich)
    attachments = _attachments(msg)
    auth = _parse_auth_results(msg)

    findings, sender_info = _sender_findings(msg, auth)
    sender_reg = sender_info.get("registered_domain") or ""

    links = extract_links(plain, rich)
    tasks: dict[str, Any] = {"links": _analyze_links(links, use_intel)}
    if deep and sender_reg and sender_reg not in FREE_EMAIL_PROVIDERS:
        tasks["dns"] = asyncio.wait_for(domain_intel.lookup_dns(sender_reg, sender_reg), 12)
        tasks["registration"] = asyncio.wait_for(domain_intel.lookup_registration(sender_reg), 15)
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    results = {k: (None if isinstance(v, BaseException) else v) for k, v in zip(tasks, gathered, strict=True)}
    analyzed_links = results["links"] or []

    findings += _auth_findings(auth, sender_reg, results.get("dns"))
    content, matched_phrases = _content_findings(sender_info["subject"], text)
    findings += content
    findings += _attachment_findings(attachments)
    findings += _link_findings(analyzed_links, sender_reg)
    if rich and re.search(r"<form\b", rich, re.I):
        findings.append(Finding(id="content.html_form", category="content", severity="high", weight=0.4,
                                title="Email contains a form", detail="Legitimate senders do not collect information through forms embedded in email."))
    if registration := results.get("registration"):
        for f in domain_intel.registration_findings(registration, sender_reg):
            f.id = "sender." + f.id
            f.title = ("Sender d" + f.title[1:]) if f.title.startswith("Domain") else f"Sender: {f.title[0].lower()}{f.title[1:]}"
            findings.append(f)
    local_sender = aggregator.providers.local_lookup([(sender_info.get("address", ""), "email"), (sender_reg, "domain")]) if sender_reg else None
    if local_sender and local_sender.status == "malicious":
        findings += aggregator.to_findings([local_sender], subject="Sender: ")

    malicious_links = sum(1 for l in analyzed_links if l.get("intel") and l["intel"]["malicious"])
    combined = scoring.combine(findings, intel_malicious=malicious_links + (1 if local_sender and local_sender.status == "malicious" else 0))
    details = {
        "sender": sender_info,
        "authentication": auth,
        "sender_dns": results.get("dns"),
        "sender_registration": results.get("registration"),
        "links": analyzed_links,
        "attachments": attachments,
        "matched_phrases": matched_phrases,
        "body_preview": text[:1500],
        "has_html": bool(rich),
    }
    target = sender_info.get("subject") or sender_info.get("address") or "(email)"
    return build_result("email", target[:300], findings, combined, details, started, "This email")
