import { useId, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";
import { ArrowDown, CircleCheck, CircleDashed, CircleX, ExternalLink, FileWarning, KeyRound, Paperclip, ScanSearch } from "lucide-react";
import type { DnsInfo, IntelSummary, MlResult, PageInfo, RedirectHop, Registration, TlsInfo, Verdict } from "../lib/api";
import { formatAge, formatDate, pct, VERDICT_TONE } from "../lib/format";
import { Breakable } from "./Highlight";
import { Ring } from "./ui";

/* ---------------------------------------------------------------- tabs */

export interface TabDef {
  id: string;
  label: string;
  badge?: ReactNode;
  content: ReactNode;
}

export function Tabs({ tabs, label }: { tabs: TabDef[]; label: string }) {
  const [active, setActive] = useState(tabs[0]?.id);
  const uid = useId();
  const current = tabs.find((t) => t.id === active) ?? tabs[0];
  const move = (dir: number) => {
    const i = tabs.findIndex((t) => t.id === current.id);
    const next = tabs[(i + dir + tabs.length) % tabs.length];
    setActive(next.id);
    document.getElementById(`${uid}-tab-${next.id}`)?.focus();
  };
  return (
    <div className="tabs">
      <div
        className="tab-list"
        role="tablist"
        aria-label={label}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight") move(1);
          if (e.key === "ArrowLeft") move(-1);
        }}
      >
        {tabs.map((t) => (
          <button
            key={t.id}
            id={`${uid}-tab-${t.id}`}
            role="tab"
            type="button"
            aria-selected={t.id === current.id}
            aria-controls={`${uid}-panel`}
            tabIndex={t.id === current.id ? 0 : -1}
            className="tab"
            onClick={() => setActive(t.id)}
          >
            {t.label}
            {t.badge}
            {t.id === current.id && <motion.span layoutId={`${uid}-ink`} className="tab-ink" transition={{ type: "spring", stiffness: 500, damping: 40 }} />}
          </button>
        ))}
      </div>
      <div id={`${uid}-panel`} role="tabpanel" aria-labelledby={`${uid}-tab-${current.id}`} className="tab-panel">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div key={current.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }} transition={{ duration: 0.2 }}>
            {current.content}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}

export function Dot({ tone }: { tone: string }) {
  return <span className="tab-dot" data-tone={tone} aria-hidden="true" />;
}

/* ---------------------------------------------------------------- facts */

export function Facts({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="facts">
      {rows.map(([k, v]) => (
        <div key={k} className="fact">
          <dt>{k}</dt>
          <dd>{v ?? "None"}</dd>
        </div>
      ))}
    </dl>
  );
}

function Block({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="ev-block">
      <div className="ev-head">
        <h4>{title}</h4>
        {aside}
      </div>
      {children}
    </section>
  );
}

/* ---------------------------------------------------------------- model */

export function ModelPanel({ ml, title = "URL model", note }: { ml: MlResult; title?: string; note?: string }) {
  const max = Math.max(0.5, ...ml.explanations.map((e) => Math.abs(e.contribution)));
  const verdict: Verdict = ml.probability >= 0.65 ? "malicious" : ml.probability >= 0.35 ? "suspicious" : "safe";
  return (
    <Block title={title}>
      <div className="model-top">
        <Ring score={Math.round(ml.probability * 100)} verdict={verdict} size={76} stroke={6} />
        <div>
          <p className="model-prob">{pct(ml.probability, 1)} likely phishing</p>
          <p className="muted small">
            XGBoost {pct(ml.models.xgboost, 1)}, random forest {pct(ml.models.random_forest, 1)}. Trained on {Object.keys(ml.features).length} features of the URL text.
            {note ? ` ${note}` : ""}
          </p>
        </div>
      </div>
      {ml.explanations.length > 0 && (
        <>
          <p className="ev-sub">What swayed the model</p>
          <ul className="contrib">
            {ml.explanations.map((e) => (
              <li key={e.feature}>
                <span className="contrib-label">
                  {e.label} <span className="faint">{Number.isInteger(e.value) ? e.value : e.value.toFixed(2)}</span>
                </span>
                <span className="contrib-track" aria-label={`pushes toward ${e.direction}`}>
                  <motion.span
                    className="contrib-bar"
                    data-tone={e.direction === "phishing" ? "danger" : "trust"}
                    style={e.direction === "phishing" ? { left: "50%" } : { right: "50%" }}
                    initial={{ width: 0 }}
                    animate={{ width: `${(Math.abs(e.contribution) / max) * 50}%` }}
                    transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
                  />
                </span>
              </li>
            ))}
          </ul>
          <div className="contrib-scale" aria-hidden="true">
            <span>toward legitimate</span>
            <span>toward phishing</span>
          </div>
        </>
      )}
    </Block>
  );
}

/* ---------------------------------------------------------------- redirects + page */

export function RedirectPanel({ chain, error }: { chain: RedirectHop[]; error?: string | null }) {
  return (
    <Block title="Redirect chain">
      {!chain.length ? (
        <p className="muted small">{error ?? "The page was not fetched."}</p>
      ) : (
        <ol className="chain">
          {chain.map((hop, i) => (
            <motion.li key={i} className="hop" data-state={hop.error ? "error" : hop.location ? "redirect" : "final"}>
              <span className="hop-code">{hop.error ? "!" : hop.status ?? "?"}</span>
              <div className="hop-body">
                <span className="mono hop-url">
                  <Breakable text={hop.url} />
                </span>
                <span className="faint small">
                  {hop.error
                    ? `Failed: ${hop.error}`
                    : hop.location
                      ? hop.via === "meta-refresh"
                        ? "Forwards with a meta refresh"
                        : "Redirects"
                      : `Final page${hop.content_type ? `, ${hop.content_type}` : ""}`}
                </span>
              </div>
              {i < chain.length - 1 ? <ArrowDown className="hop-arrow" size={14} aria-hidden="true" /> : null}
            </motion.li>
          ))}
        </ol>
      )}
    </Block>
  );
}

export function PagePanel({ page }: { page?: PageInfo }) {
  if (!page || !Object.keys(page).length) {
    return (
      <Block title="Landing page">
        <p className="muted small">No HTML page was retrieved.</p>
      </Block>
    );
  }
  const flag = (on: boolean | undefined, yes: string, no: string) => (
    <span className="flag" data-tone={on ? "danger" : "neutral"}>
      {on ? <CircleX size={15} aria-hidden="true" /> : <CircleDashed size={15} aria-hidden="true" />}
      {on ? yes : no}
    </span>
  );
  return (
    <Block title="Landing page">
      <Facts
        rows={[
          ["Title", page.title || "None"],
          ["Forms", String(page.forms ?? 0)],
          ["Password fields", flag((page.password_fields ?? 0) > 0, `${page.password_fields} found`, "None")],
          ["Card, PIN or seed fields", flag(!!page.sensitive_fields?.length, page.sensitive_fields?.join(", ") ?? "", "None")],
          ["Form sends data to", page.external_form_actions?.length ? <span className="mono">{page.external_form_actions[0]}</span> : "Same site"],
          ["Brand named in title", page.title_brands?.length ? page.title_brands.join(", ") : "None"],
          ["Scripted redirect", flag(page.js_redirect, "Yes", "No")],
          ["Obfuscated script", flag(page.obfuscated_js, "Yes", "No")],
        ]}
      />
    </Block>
  );
}

/* ---------------------------------------------------------------- domain */

export function RegistrationPanel({ reg, domain }: { reg?: Registration | null; domain: string }) {
  if (!reg) return <Block title="Registration"><p className="muted small">Not checked.</p></Block>;
  if (reg.found === false) return <Block title="Registration"><p className="small">No registration record exists for {domain}.</p></Block>;
  if (reg.found === null || reg.found === undefined)
    return (
      <Block title="Registration">
        <p className="muted small">{reg.error ?? "Registration data unavailable."}</p>
      </Block>
    );
  const created = reg.created ? new Date(reg.created).getTime() : null;
  const expires = reg.expires ? new Date(reg.expires).getTime() : null;
  const now = Date.now();
  const nowPct = created && expires && expires > created ? Math.min(100, ((now - created) / (expires - created)) * 100) : null;
  const age = reg.age_days ?? null;
  const ageTone = age === null ? "neutral" : age < 30 ? "danger" : age < 365 ? "warn" : "trust";
  return (
    <Block title="Registration" aside={<span className="tag">{reg.source === "rdap" ? "RDAP" : "WHOIS"}</span>}>
      <div className="age" data-tone={ageTone}>
        <span className="age-num">{formatAge(age)}</span>
        <span className="age-label">old</span>
      </div>
      {nowPct !== null && (
        <div className="timeline" aria-label={`Registered ${formatDate(reg.created)}, expires ${formatDate(reg.expires)}`}>
          <div className="tl-track">
            <motion.span className="tl-fill" data-tone={ageTone} initial={{ width: 0 }} animate={{ width: `${nowPct}%` }} transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }} />
            <motion.span className="tl-now" initial={{ left: 0, opacity: 0 }} animate={{ left: `${nowPct}%`, opacity: 1 }} transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }} />
          </div>
          <div className="tl-labels">
            <span>Registered {formatDate(reg.created)}</span>
            <span>Expires {formatDate(reg.expires)}</span>
          </div>
        </div>
      )}
      <Facts
        rows={[
          ["Registrar", reg.registrar ?? "Unknown"],
          ["Last updated", formatDate(reg.updated)],
          ["Name servers", reg.nameservers?.length ? <span className="mono">{reg.nameservers.slice(0, 4).join(", ")}</span> : "Unknown"],
        ]}
      />
    </Block>
  );
}

export function DnsPanel({ dns }: { dns?: DnsInfo | null }) {
  if (!dns) return <Block title="DNS"><p className="muted small">Not checked.</p></Block>;
  if (dns.nxdomain) return <Block title="DNS"><p className="small">The name doesn't exist in DNS (NXDOMAIN), so the site may already have been taken down.</p></Block>;
  const recs = (v: string[]) =>
    v.length ? (
      <span className="records">
        {v.slice(0, 5).map((x) => (
          <code key={x}>{x}</code>
        ))}
      </span>
    ) : (
      <span className="faint">None</span>
    );
  return (
    <Block title="DNS">
      <Facts
        rows={[
          ["Addresses", recs([...dns.a, ...dns.aaaa])],
          ...(dns.cname.length ? ([["CNAME", recs(dns.cname)]] as [string, ReactNode][]) : []),
          ["Mail servers", recs(dns.mx)],
          ["SPF", dns.spf ? <code className="wrap-code">{dns.spf}</code> : <span className="faint">None published</span>],
          ["DMARC", dns.dmarc ? <span className="tag" data-tone={dns.dmarc_policy === "none" ? "warn" : "trust"}>p={dns.dmarc_policy ?? "?"}</span> : <span className="faint">None published</span>],
        ]}
      />
    </Block>
  );
}

export function TlsPanel({ tls }: { tls?: TlsInfo | null }) {
  if (!tls) return <Block title="Certificate"><p className="muted small">Not checked: the link uses plain HTTP.</p></Block>;
  if (tls.skipped) return <Block title="Certificate"><p className="muted small">{tls.error}</p></Block>;
  if (!tls.available) return <Block title="Certificate"><p className="small">{tls.error ?? "HTTPS is not available."}</p></Block>;
  const total = (tls.age_days ?? 0) + (tls.days_remaining ?? 0);
  const used = total > 0 ? ((tls.age_days ?? 0) / total) * 100 : 0;
  return (
    <Block
      title="Certificate"
      aside={
        <span className="flag" data-tone={tls.verified ? "trust" : "danger"}>
          {tls.verified ? <CircleCheck size={15} aria-hidden="true" /> : <CircleX size={15} aria-hidden="true" />}
          {tls.verified ? "Valid" : "Invalid"}
        </span>
      }
    >
      <div className="cert">
        <KeyRound size={20} aria-hidden="true" />
        <div>
          <div className="mono cert-cn">{tls.subject_cn ?? "Unknown subject"}</div>
          <div className="faint small">Issued by {tls.issuer_org ?? tls.issuer_cn ?? "unknown"}</div>
        </div>
      </div>
      <div className="timeline">
        <div className="tl-track">
          <motion.span className="tl-fill" data-tone={tls.verified ? "trust" : "danger"} initial={{ width: 0 }} animate={{ width: `${used}%` }} transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }} />
        </div>
        <div className="tl-labels">
          <span>Issued {formatDate(tls.not_before)}</span>
          <span>Expires in {tls.days_remaining} days</span>
        </div>
      </div>
      <Facts rows={[["Valid", tls.verified ? "Yes" : `No: ${tls.error ?? "verification failed"}`], ["Names covered", String(tls.san_count ?? 0)]]} />
      <p className="faint small" style={{ marginTop: 12 }}>
        A valid certificate only proves the connection is encrypted, not that the site is honest.
      </p>
    </Block>
  );
}

/* ---------------------------------------------------------------- intel */

const INTEL_TONE: Record<string, string> = { malicious: "danger", suspicious: "warn", clean: "trust", unknown: "neutral", error: "neutral", disabled: "neutral" };
const INTEL_TEXT: Record<string, string> = { malicious: "Listed", suspicious: "Reported", clean: "Not listed", unknown: "No data", error: "Error", disabled: "Not connected" };

export function IntelPanel({ intel }: { intel?: IntelSummary }) {
  if (!intel) return null;
  const sources = [...intel.sources].sort((a, b) => Number(a.status === "disabled") - Number(b.status === "disabled"));
  return (
    <Block title="Threat feeds" aside={<Link to="/setup" className="small">Connect feeds</Link>}>
      <ul className="intel">
        {sources.map((s) => (
          <motion.li key={s.source} className="intel-row" data-tone={INTEL_TONE[s.status]} data-off={s.status === "disabled" ? "true" : undefined}>
            <span className="intel-name">{s.name}</span>
            <span className="intel-status">{INTEL_TEXT[s.status]}</span>
            <span className="intel-detail">
              {s.status === "disabled" ? "Add an API key to include it" : s.detail}
              {s.cached ? " (cached)" : ""}
              {s.reference ? (
                <a href={s.reference} target="_blank" rel="noreferrer noopener" className="intel-link">
                  Report <ExternalLink size={12} aria-hidden="true" />
                </a>
              ) : null}
            </span>
          </motion.li>
        ))}
      </ul>
    </Block>
  );
}

/* ---------------------------------------------------------------- email */

interface EmailLink {
  url: string;
  host: string;
  mismatch: { shown: string; actual: string } | null;
  risk_score: number;
  verdict: Verdict;
  findings: string[];
}

export function LinksPanel({ links }: { links: EmailLink[] }) {
  if (!links.length) return <Block title="Links"><p className="muted small">The message contains no links.</p></Block>;
  const sorted = [...links].sort((a, b) => b.risk_score - a.risk_score);
  return (
    <Block title={`${links.length} link${links.length === 1 ? "" : "s"}, riskiest first`}>
      <ul className="link-list">
        {sorted.map((l) => (
          <motion.li key={l.url} className="link-row" data-tone={VERDICT_TONE[l.verdict]}>
            <Ring score={l.risk_score} verdict={l.verdict} size={44} />
            <div className="link-body">
              <span className="mono link-url">
                <Breakable text={l.url} />
              </span>
              {l.mismatch ? (
                <span className="small link-mm">
                  Shows <mark className="hl" data-tone="danger">{l.mismatch.shown}</mark> but opens <strong>{l.mismatch.actual}</strong>
                </span>
              ) : null}
              <span className="faint small">{l.findings.length ? l.findings.join("; ") : "Nothing notable"}</span>
            </div>
            <Link className="btn btn-ghost btn-sm" to={`/scan?url=${encodeURIComponent(l.url)}`}>
              <ScanSearch size={15} aria-hidden="true" />
              Scan
            </Link>
          </motion.li>
        ))}
      </ul>
    </Block>
  );
}

interface Attachment {
  filename: string;
  content_type: string;
  size: number;
  extension: string;
  double_extension: boolean;
}

export function AttachmentsPanel({ attachments }: { attachments: Attachment[] }) {
  if (!attachments.length) return <Block title="Attachments"><p className="muted small">No attachments.</p></Block>;
  return (
    <Block title="Attachments">
      <ul className="link-list">
        {attachments.map((a, i) => {
          const risky = a.double_extension || ["exe", "scr", "js", "vbs", "html", "htm", "svg", "iso", "lnk", "hta", "docm", "xlsm"].includes(a.extension);
          return (
            <li key={i} className="link-row" data-tone={risky ? "danger" : "neutral"}>
              <span className="att-icon">{risky ? <FileWarning size={20} aria-hidden="true" /> : <Paperclip size={20} aria-hidden="true" />}</span>
              <div className="link-body">
                <span className="mono link-url">{a.filename}</span>
                <span className="faint small">
                  {a.content_type}, {a.size.toLocaleString()} bytes{a.double_extension ? ", disguised with a double extension" : ""}
                </span>
              </div>
            </li>
          );
        })}
      </ul>
    </Block>
  );
}

export function AuthPanel({ auth }: { auth: Record<string, string | undefined> }) {
  if (!auth.source)
    return (
      <Block title="Authentication headers">
        <p className="muted small">The message had no Authentication-Results header. Paste the full original message, including headers, to evaluate SPF, DKIM and DMARC.</p>
      </Block>
    );
  return (
    <Block title="Authentication headers">
      <Facts
        rows={[
          ["Reported by", auth.source],
          ["Visible From domain", auth.header_from ? <span className="mono">{auth.header_from}</span> : "Unknown"],
          ["Envelope sender", auth.mailfrom ? <span className="mono">{auth.mailfrom}</span> : "Unknown"],
          ["DKIM signer", auth.dkim_domain || auth.dkim_signature_domain ? <span className="mono">{auth.dkim_domain ?? auth.dkim_signature_domain}</span> : "None"],
        ]}
      />
      {auth.raw ? <pre className="raw">{auth.raw}</pre> : null}
    </Block>
  );
}
