import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { Ban, Globe, Link2, Mail, RotateCw, Trash2 } from "lucide-react";
import { api, type ScanResult } from "../lib/api";
import { formatDateTime, toneOf, TYPE_LABEL, VERDICT_LABEL } from "../lib/format";
import type { ParsedUrl } from "../lib/anatomy";
import { useToast } from "../lib/toast";
import Gauge from "../components/Gauge";
import Anatomy from "../components/Anatomy";
import EmailAnatomy from "../components/EmailAnatomy";
import Findings from "../components/Findings";
import ScoreFlow from "../components/ScoreFlow";
import {
  AttachmentsPanel,
  AuthPanel,
  DnsPanel,
  Dot,
  IntelPanel,
  LinksPanel,
  ModelPanel,
  PagePanel,
  RedirectPanel,
  RegistrationPanel,
  Tabs,
  TlsPanel,
  type TabDef,
} from "../components/Evidence";
import { ConfirmButton, CopyButton, Empty, SeverityIcon } from "../components/ui";

const ADVICE = {
  malicious: "Don't open it, reply to it or type anything into it.",
  suspicious: "Treat it with caution. Check it through a channel you already trust before acting on it.",
  safe: "No phishing signs found. No scanner catches everything, so stay alert to anything unexpected.",
};

const TYPE_ICON = { url: Link2, domain: Globe, email: Mail };

export default function ResultPage() {
  const { id } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const toast = useToast();
  const initial = (location.state as { result?: ScanResult } | null)?.result;
  const [result, setResult] = useState<ScanResult | null>(initial && initial.id === id ? initial : null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (result?.id === id) return;
    setResult(null);
    setError(null);
    api.scan(id!).then(setResult).catch((e) => setError(e.message));
  }, [id, result?.id]);

  useEffect(() => {
    if (!result) return;
    document.title = `${VERDICT_LABEL[result.verdict]}: ${result.target.slice(0, 60)} | Trace`;
    return () => {
      document.title = "Trace";
    };
  }, [result]);

  if (error)
    return (
      <Empty title="Scan not found" action={<Link className="btn btn-primary" to="/history">Back to history</Link>}>
        {error}
      </Empty>
    );
  if (!result) return <ResultSkeleton />;

  const d = result.details;
  const TypeIcon = TYPE_ICON[result.scan_type];
  const topReasons = result.findings.filter((f) => f.kind === "risk" && f.category !== "ml").slice(0, 3);

  const blockTarget = (): { indicator: string; indicator_type: string } | null => {
    if (result.scan_type === "email") return d.sender?.address ? { indicator: d.sender.address, indicator_type: "email" } : null;
    if (result.scan_type === "domain") return { indicator: result.target, indicator_type: "domain" };
    return { indicator: result.target, indicator_type: "url" };
  };

  const addToBlocklist = async () => {
    const rec = blockTarget();
    if (!rec) return;
    try {
      const saved = await api.addThreat({ ...rec, threat_type: "phishing", description: `From scan ${result.id.slice(0, 8)}: ${result.summary}`.slice(0, 2000) });
      toast({ tone: "success", title: "Blocked", body: saved.indicator, action: { label: "Undo", run: () => void api.deleteThreat(saved.id).then(() => toast({ tone: "info", title: "Unblocked", body: saved.indicator })) } });
    } catch (e) {
      toast({ tone: "error", title: "Couldn't block this", body: (e as Error).message });
    }
  };

  const remove = async () => {
    try {
      await api.deleteScan(result.id);
      toast({ tone: "success", title: "Scan deleted" });
      navigate("/history");
    } catch (e) {
      toast({ tone: "error", title: "Couldn't delete the scan", body: (e as Error).message });
    }
  };

  const rescan = () => navigate("/scan", { state: { autoScan: { kind: result.scan_type, value: result.target } } });

  const tabs = evidenceTabs(result);
  const anatomyTitle = result.scan_type === "url" ? "Anatomy of the link" : result.scan_type === "domain" ? "Anatomy of the domain" : "Anatomy of the message";
  const anatomySub =
    result.scan_type === "url"
      ? "Hover any part to see what it does. Attackers control everything except the real destination."
      : result.scan_type === "domain"
        ? "Only the registered domain says who owns the site."
        : "Who it claims to be from, whether that holds up, and the tactics used in the text.";

  return (
    <div className="result">
      <header className="result-head">
        <div className="rh-main">
          <div className="rh-meta">
            <TypeIcon size={14} aria-hidden="true" />
            {TYPE_LABEL[result.scan_type]} scanned {formatDateTime(result.created_at)} in {(result.duration_ms / 1000).toFixed(1)} s
          </div>
          <h1 className="rh-title">{VERDICT_LABEL[result.verdict]}</h1>
          <p className="rh-target mono" title={result.target}>
            {result.target}
          </p>
          <p className="rh-advice">{ADVICE[result.verdict]}</p>
          {topReasons.length > 0 && (
            <ul className="rh-reasons" aria-label="Main reasons">
              {topReasons.map((f, i) => (
                <li key={f.id + i}>
                  <SeverityIcon finding={f} size={14} />
                  {f.title}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="rh-side">
          <div className="result-actions">
            {result.scan_type !== "email" && (
              <button className="btn btn-outline btn-sm" onClick={rescan}>
                <RotateCw size={14} aria-hidden="true" />
                Scan again
              </button>
            )}
            <CopyButton text={result.target} label="Copy" />
            {result.verdict !== "safe" && blockTarget() && (
              <button className="btn btn-primary btn-sm" onClick={addToBlocklist}>
                <Ban size={14} aria-hidden="true" />
                Block
              </button>
            )}
            <ConfirmButton className="icon-btn" onConfirm={remove} title="Delete this scan?" body="Its findings and evidence will be gone for good." confirmLabel="Delete scan" ariaLabel="Delete scan" tip="Delete">
              <Trash2 size={15} aria-hidden="true" />
            </ConfirmButton>
          </div>
          <Gauge score={result.risk_score} verdict={result.verdict} thresholds={result.score_breakdown.thresholds} />
        </div>
      </header>

      <section className="panel panel-pad" aria-labelledby="anatomy-title">
        <div className="panel-head">
          <div>
            <h2 id="anatomy-title" className="panel-title">
              {anatomyTitle}
            </h2>
            <p className="panel-sub">{anatomySub}</p>
          </div>
        </div>
        {result.scan_type === "url" && (
          <Anatomy parsed={d.parsed as ParsedUrl} findings={result.findings} finalUrl={d.redirects?.final_url && d.redirects.final_url !== d.url ? d.redirects.final_url : null} />
        )}
        {result.scan_type === "domain" && <Anatomy parsed={domainParsed(d)} findings={result.findings} hostOnly />}
        {result.scan_type === "email" && <EmailAnatomy result={result} />}
      </section>

      <div className="result-grid">
        <section className="panel panel-pad" aria-labelledby="findings-title">
          <div className="panel-head">
            <div>
              <h2 id="findings-title" className="panel-title">
                Findings
              </h2>
              <p className="panel-sub">Every signal that moved the score, strongest first.</p>
            </div>
          </div>
          <Findings findings={result.findings} />
        </section>
        <aside className="panel panel-pad flow-panel" aria-labelledby="flow-title">
          <h2 id="flow-title" className="panel-title">
            How the score adds up
          </h2>
          <p className="panel-sub" style={{ marginBottom: 20 }}>
            Trust counts for less when the evidence against is strong.
          </p>
          <ScoreFlow b={result.score_breakdown} verdict={result.verdict} emailMode={result.scan_type === "email"} />
        </aside>
      </div>

      {tabs.length > 0 && (
        <section className="panel panel-pad" aria-labelledby="evidence-title">
          <div className="panel-head">
            <div>
              <h2 id="evidence-title" className="panel-title">
                Evidence
              </h2>
              <p className="panel-sub">
                {result.scan_type === "url" && !d.deep
                  ? "Quick scan: only the link text was analysed. Scan again with the investigation switch on to visit the page and check the domain."
                  : "The raw data behind the findings."}
              </p>
            </div>
          </div>
          <Tabs tabs={tabs} label="Evidence" />
        </section>
      )}
    </div>
  );
}

function domainParsed(d: ScanResult["details"]): ParsedUrl {
  const suffix: string = d.suffix ?? "";
  const label = suffix ? d.registered_domain.slice(0, -(suffix.length + 1)) : d.registered_domain;
  return { scheme: "https", host: d.domain, port: null, path: "", query: "", subdomain: d.subdomain ?? "", domain: label, suffix, registered_domain: d.registered_domain, is_ip: false };
}

function evidenceTabs(result: ScanResult): TabDef[] {
  const d = result.details;
  const tone = (ids: (id: string) => boolean) => {
    const fs = result.findings.filter((f) => ids(f.id) && f.kind === "risk");
    return fs.length ? <Dot tone={fs.some((f) => toneOf(f) === "danger") ? "danger" : "warn"} /> : null;
  };
  const intelDot = d.intel?.malicious ? <Dot tone="danger" /> : d.intel?.suspicious ? <Dot tone="warn" /> : null;

  if (result.scan_type === "url") {
    const tabs: TabDef[] = [
      {
        id: "model",
        label: "Model",
        badge: tone((id) => id.includes("ml.")),
        content: (
          <div className="ev-grid">
            <ModelPanel ml={d.ml} note={d.ml_note} />
            {d.final_ml ? <ModelPanel ml={d.final_ml} title="Model on the landing page" /> : null}
          </div>
        ),
      },
    ];
    if (d.deep) {
      tabs.push({
        id: "page",
        label: "Redirects and page",
        badge: tone((id) => id.startsWith("redirect.") || id.startsWith("page.")),
        content: (
          <div className="ev-grid">
            <RedirectPanel chain={d.redirects?.chain ?? []} error={d.redirects?.error} />
            <PagePanel page={d.page} />
          </div>
        ),
      });
      if (d.domain) {
        tabs.push({
          id: "domain",
          label: "Domain",
          badge: tone((id) => /^(domain|dns|tls)\./.test(id)),
          content: (
            <div className="ev-grid">
              <RegistrationPanel reg={d.domain.registration} domain={d.parsed.registered_domain} />
              <DnsPanel dns={d.domain.dns} />
              <TlsPanel tls={d.domain.tls} />
            </div>
          ),
        });
      }
    }
    tabs.push({ id: "intel", label: "Threat feeds", badge: intelDot, content: <IntelPanel intel={d.intel} /> });
    return tabs;
  }

  if (result.scan_type === "domain") {
    return [
      {
        id: "reg",
        label: "Registration and DNS",
        badge: tone((id) => /^(domain|dns)\./.test(id)),
        content: (
          <div className="ev-grid">
            <RegistrationPanel reg={d.registration} domain={d.registered_domain} />
            <DnsPanel dns={d.dns} />
          </div>
        ),
      },
      { id: "tls", label: "Certificate", badge: tone((id) => id.startsWith("tls.")), content: <TlsPanel tls={d.tls} /> },
      {
        id: "home",
        label: "Homepage",
        badge: tone((id) => id.startsWith("page.")),
        content: (
          <div className="ev-grid">
            <RedirectPanel chain={d.homepage?.chain ?? []} error={d.homepage?.error} />
            <PagePanel page={d.homepage?.page} />
          </div>
        ),
      },
      { id: "intel", label: "Threat feeds", badge: intelDot, content: <IntelPanel intel={d.intel} /> },
      { id: "model", label: "Model", content: <ModelPanel ml={d.ml} note="For a bare domain the model only sees the hostname." /> },
    ];
  }

  const tabs: TabDef[] = [
    { id: "links", label: "Links", badge: tone((id) => id.startsWith("link.")), content: <LinksPanel links={d.links ?? []} /> },
    { id: "att", label: "Attachments", badge: tone((id) => id.startsWith("attachment.")), content: <AttachmentsPanel attachments={d.attachments ?? []} /> },
    { id: "auth", label: "Authentication", badge: tone((id) => id.startsWith("auth.")), content: <AuthPanel auth={d.authentication ?? {}} /> },
  ];
  if (d.sender_dns || d.sender_registration) {
    tabs.push({
      id: "sender",
      label: "Sender domain",
      badge: tone((id) => id.startsWith("sender.")),
      content: (
        <div className="ev-grid">
          <RegistrationPanel reg={d.sender_registration} domain={d.sender?.registered_domain ?? ""} />
          <DnsPanel dns={d.sender_dns} />
        </div>
      ),
    });
  }
  return tabs;
}

function ResultSkeleton() {
  return (
    <div className="result" aria-busy="true" aria-label="Loading scan">
      <div className="skeleton" style={{ height: 34, width: 120 }} />
      <div className="skeleton" style={{ height: 260, borderRadius: 26 }} />
      <div className="skeleton" style={{ height: 320, borderRadius: 18 }} />
    </div>
  );
}

