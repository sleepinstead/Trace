import type { Finding } from "./api";
import { strongestTone, toneOf, type Tone } from "./format";

export interface ParsedUrl {
  scheme: string;
  userinfo?: string;
  host: string;
  port: number | null;
  path: string;
  query: string;
  fragment?: string;
  subdomain: string;
  domain: string;
  suffix: string;
  registered_domain: string;
  is_ip: boolean;
}

export type Role = "scheme" | "userinfo" | "subdomain" | "site" | "port" | "path" | "query" | "fragment";

export interface Part {
  role: Role;
  text: string;
  before?: string;
  after?: string;
  label: string;
  hint: string;
  findings: Finding[];
  tone: Tone;
}

export interface Term {
  term: string;
  tone: Tone;
  title: string;
}

const ROLE_RULES: Record<Role, (id: string) => boolean> = {
  scheme: (id) => id === "url.no_https" || id === "tls.unavailable",
  userinfo: (id) => id === "url.userinfo",
  subdomain: (id) => ["url.brand_subdomain", "url.many_subdomains"].includes(id),
  site: (id) =>
    [
      "url.typosquat", "url.combosquat", "url.random_domain", "url.digits_domain", "url.hyphens", "url.https_token",
      "url.punycode", "url.ip_host", "url.tld_high", "url.tld_medium", "url.free_hosting", "url.popular_domain", "url.shortener",
      "domain.age_new", "domain.age_young", "domain.age_recent", "domain.age_established", "domain.unregistered", "domain.on_hold",
      "dns.nxdomain", "dns.no_address", "tls.invalid", "tls.new_cert", "intel.local", "intel.virustotal", "intel.safebrowsing",
      "intel.urlhaus", "intel.phishtank",
    ].includes(id),
  port: (id) => id === "url.port",
  path: (id) => ["url.double_slash", "url.download", "url.brand_path", "url.keywords"].includes(id),
  query: (id) => ["url.email_in_url", "url.embedded_redirect", "url.obfuscated"].includes(id),
  fragment: () => false,
};

export function urlParts(p: ParsedUrl, findings: Finding[], { hostOnly = false } = {}): Part[] {
  const pick = (role: Role) => findings.filter((f) => ROLE_RULES[role](f.id) && f.kind !== "info");
  const make = (role: Role, text: string, label: string, hint: string, extra: Partial<Part> = {}): Part => {
    const fs = pick(role);
    return { role, text, label, hint, findings: fs, tone: strongestTone(fs), ...extra };
  };
  const parts: Part[] = [];
  if (!hostOnly) {
    parts.push(
      make("scheme", p.scheme, "Protocol", p.scheme === "https" ? "Encrypted, though attackers get certificates too." : "Unencrypted: anything typed here can be read in transit.", { after: "://" }),
    );
    if (p.userinfo) {
      parts.push(make("userinfo", p.userinfo, "Decoy before @", "Browsers ignore everything before the @, so this text is only there to mislead.", { after: "@" }));
    }
  }
  if (p.subdomain) {
    parts.push(make("subdomain", p.subdomain, "Subdomain", `Whoever owns ${p.registered_domain} can put any words here.`, { after: "." }));
  }
  parts.push(
    make("site", p.is_ip ? p.host : p.registered_domain, p.is_ip ? "Raw IP address" : "Real destination", p.is_ip ? "No domain name vouches for this server." : "The registered domain decides who controls the page."),
  );
  if (!hostOnly) {
    if (p.port) parts.push(make("port", String(p.port), "Port", "A non-standard port.", { before: ":" }));
    if (p.path && p.path !== "/") parts.push(make("path", p.path, "Path", `A page on ${p.registered_domain}, named however its owner likes.`));
    else if (p.path === "/") parts.push(make("path", "/", "Path", "The site's front page."));
    if (p.query) parts.push(make("query", p.query, "Query string", "Extra data passed to the page.", { before: "?" }));
    if (p.fragment) parts.push(make("fragment", p.fragment, "Fragment", "Only read by the page itself.", { before: "#" }));
  }
  return parts;
}

/** Highlightable words (keywords, brands) from findings that carry evidence. */
export function evidenceTerms(findings: Finding[], ids: (id: string) => boolean): Term[] {
  return findings
    .filter((f) => ids(f.id) && f.evidence?.length && f.kind === "risk")
    .flatMap((f) => f.evidence.map((term) => ({ term, tone: toneOf(f), title: f.title })));
}
