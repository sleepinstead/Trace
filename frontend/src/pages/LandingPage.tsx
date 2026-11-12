import { Link } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import Anatomy from "../components/Anatomy";
import { BrandMark, VerdictBadge } from "../components/ui";
import type { Finding } from "../lib/api";
import type { ParsedUrl } from "../lib/anatomy";
import { useOnboarding } from "../lib/onboarding";

const DEMO_URL: ParsedUrl = {
  scheme: "http",
  host: "paypal.com.account-verify.xyz",
  port: null,
  path: "/webscr/login.php",
  query: "",
  subdomain: "paypal.com",
  domain: "account-verify",
  suffix: "xyz",
  registered_domain: "account-verify.xyz",
  is_ip: false,
};

const finding = (id: string, severity: Finding["severity"], title: string, evidence: string[] = []): Finding => ({ id, category: "url", kind: "risk", severity, title, detail: "", weight: 0, evidence });

const DEMO_FINDINGS = [
  finding("url.no_https", "low", "Unencrypted HTTP link"),
  finding("url.brand_subdomain", "high", "PayPal name used as subdomain", ["paypal"]),
  finding("url.tld_high", "medium", "High-abuse TLD .xyz"),
  finding("url.keywords", "medium", "Phishing-related keywords", ["webscr", "login"]),
];

const STEPS = [
  { title: "Paste it", body: "A link, a domain or a whole email with its headers. Trace works out which one you gave it." },
  { title: "See it taken apart", body: "Every part of the address, every sender check and every pressure tactic, marked where it appears." },
  { title: "Decide with evidence", body: "A 0–100 risk score with every point explained, from rules, a trained model and threat feeds." },
];

const CHECKS = [
  ["Address", "Lookalike spellings, brands in subdomains, @ tricks, raw IPs and risky TLDs."],
  ["Destination", "Redirect chains, what the page asks for, domain age, DNS and certificates."],
  ["Email", "Forged senders, SPF, DKIM and DMARC, disguised links and risky attachments."],
  ["Known threats", "Your own blocklist, plus VirusTotal, Safe Browsing, URLhaus and PhishTank."],
];

export default function LandingPage() {
  const { onboarded } = useOnboarding();
  const start = onboarded ? "/scan" : "/onboarding";
  return (
    <div className="landing">
      <header className="l-nav">
        <Link to="/welcome" className="brand">
          <BrandMark />
        </Link>
        <Link to={start} className="btn btn-primary btn-sm">
          {onboarded ? "Open Trace" : "Get started"}
        </Link>
      </header>

      <main>
        <section className="l-hero">
          <h1>See exactly why a link is a trap.</h1>
          <p>Trace takes links, domains and emails apart, follows them to where they really lead, and shows you the evidence.</p>
          <Link to={start} className="btn btn-primary btn-lg">
            {onboarded ? "Open Trace" : "Get started"}
            <ArrowRight size={16} aria-hidden="true" />
          </Link>
        </section>

        <section className="l-demo" aria-label="Example result">
          <div className="l-demo-head">
            <div>
              <h2>Likely phishing</h2>
              <p>Hover any part of the address</p>
            </div>
            <VerdictBadge verdict="malicious" />
          </div>
          <Anatomy parsed={DEMO_URL} findings={DEMO_FINDINGS} />
        </section>

        <section className="l-steps" aria-label="How it works">
          {STEPS.map((s, i) => (
            <div key={s.title}>
              <span className="l-num">{i + 1}</span>
              <h3>{s.title}</h3>
              <p>{s.body}</p>
            </div>
          ))}
        </section>

        <section className="l-checks">
          <h2>What it looks at</h2>
          <dl>
            {CHECKS.map(([k, v]) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
        </section>

        <section className="l-end">
          <h2>Check the next one before you click it.</h2>
          <Link to={start} className="btn btn-primary btn-lg">
            {onboarded ? "Open Trace" : "Get started"}
            <ArrowRight size={16} aria-hidden="true" />
          </Link>
        </section>
      </main>

      <footer className="l-foot">
        <span>Trace</span>
        <span>Scans are stored on this machine.</span>
      </footer>
    </div>
  );
}
