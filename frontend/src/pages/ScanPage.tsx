import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { motion } from "motion/react";
import { ArrowRight, Check, FileUp, Globe, Link2, LoaderCircle, Mail, X } from "lucide-react";
import { api, type ScanListItem, type ScanType } from "../lib/api";
import { runScan, stepsFor, type ScanRequest } from "../lib/scan";
import { detectInputType, relativeTime, TYPE_LABEL } from "../lib/format";
import { updateOnboarding, useOnboarding } from "../lib/onboarding";
import { RiskBars, Segmented, Switch, VerdictBadge } from "../components/ui";

const MODES = [
  { value: "url" as const, label: "Link", icon: Link2 },
  { value: "domain" as const, label: "Domain", icon: Globe },
  { value: "email" as const, label: "Email", icon: Mail },
];

const PLACEHOLDER: Record<ScanType, string> = {
  url: "https://secure-login.example/verify",
  domain: "paypa1-support.com",
  email: "Paste the full original message, headers included.\n\nGmail: ⋮ › Show original.   Outlook: File › Properties › Internet headers.\nOr drop an .eml file here.",
};

const SAMPLE_EMAIL = `From: "PayPal Security" <service@paypal-account-review.com>
Reply-To: resolution-team@gmail.com
Subject: Urgent: your account has been limited
Authentication-Results: mx.example.com; spf=softfail smtp.mailfrom=mailer-x7.top; dkim=none; dmarc=fail header.from=paypal.com
Content-Type: text/html; charset="utf-8"

<p>Dear Customer,</p>
<p>We detected unusual activity on your account. It will be suspended within 24 hours unless you verify your account.</p>
<p><a href="http://paypal.com.account-verify.xyz/webscr/login.php">https://www.paypal.com/myaccount</a></p>`;

const EXAMPLES: { kind: ScanType; technique: string; value: string; shown?: string }[] = [
  { kind: "url", technique: "Brand used as a subdomain", value: "http://paypal.com.account-verify.xyz/webscr/login.php" },
  { kind: "url", technique: "Hidden behind an @", value: "https://www.google.com@secure-docs.top/view" },
  { kind: "url", technique: "Lookalike characters", value: "https://micros0ft-support.com/reset?email=you@company.com" },
  { kind: "email", technique: "Fake account notice", value: SAMPLE_EMAIL, shown: "service@paypal-account-review.com" },
  { kind: "url", technique: "The real thing", value: "https://github.com/login" },
];

type Phase = "idle" | "scanning" | "done";

export default function ScanPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [params] = useSearchParams();
  const ob = useOnboarding();
  const [kind, setKind] = useState<ScanType>("url");
  const [value, setValue] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [recent, setRecent] = useState<ScanListItem[]>([]);
  const [current, setCurrent] = useState<ScanRequest | null>(null);
  const inputRef = useRef<HTMLInputElement & HTMLTextAreaElement>(null);
  const started = useRef(false);
  const runId = useRef(0);

  useEffect(() => {
    api.scans({ limit: 5 }).then((r) => setRecent(r.items)).catch(() => {});
  }, []);

  const start = useCallback(
    async (req: ScanRequest) => {
      if (!req.value.trim() && !req.file) {
        setError(req.kind === "email" ? "Paste a message or drop an .eml file first." : `Enter a ${req.kind === "url" ? "link" : "domain"} to scan.`);
        inputRef.current?.focus();
        return;
      }
      const id = ++runId.current;
      window.scrollTo({ top: 0, behavior: "smooth" });
      setError(null);
      setCurrent(req);
      setPhase("scanning");
      try {
        const result = await runScan(req);
        if (id !== runId.current) return; // cancelled; the scan is still saved in history
        setPhase("done");
        await new Promise((r) => window.setTimeout(r, 400));
        if (id !== runId.current) return;
        navigate(`/scans/${result.id}`, { state: { result, fresh: true } });
      } catch (e) {
        if (id !== runId.current) return;
        setPhase("idle");
        setError((e as Error).message);
      }
    },
    [navigate],
  );

  // Scans requested from the command palette, a result page or a ?url= link.
  useEffect(() => {
    if (started.current) return;
    const auto = (location.state as { autoScan?: { kind: ScanType; value: string } } | null)?.autoScan;
    const preset = params.get("url");
    if (auto) {
      started.current = true;
      setKind(auto.kind);
      setValue(auto.value);
      navigate(".", { replace: true, state: null });
      void start({ kind: auto.kind, value: auto.value, deep: ob.deep, useIntel: ob.useIntel });
    } else if (preset) {
      setKind("url");
      setValue(preset);
    }
  }, [location.state, params, navigate, start, ob.deep, ob.useIntel]);

  // Paste anywhere on the page to fill the scanner.
  useEffect(() => {
    const onPaste = (e: ClipboardEvent) => {
      if (phase !== "idle" || (e.target as HTMLElement).closest("input, textarea, [contenteditable]")) return;
      const text = e.clipboardData?.getData("text") ?? "";
      const k = detectInputType(text);
      if (!k) return;
      e.preventDefault();
      setKind(k);
      setValue(text.trim());
      window.setTimeout(() => inputRef.current?.focus(), 30);
    };
    window.addEventListener("paste", onPaste);
    return () => window.removeEventListener("paste", onPaste);
  }, [phase]);

  const onInputPaste = (text: string) => {
    const k = detectInputType(text);
    if (k && k !== kind) setKind(k);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files?.[0];
    if (!f) return;
    setKind("email");
    setFile(f);
    setValue("");
  };

  const submit = (e?: FormEvent) => {
    e?.preventDefault();
    void start({ kind, value, file: kind === "email" ? file : null, deep: ob.deep, useIntel: ob.useIntel });
  };

  const scanLabel = kind === "url" ? "Scan link" : kind === "domain" ? "Scan domain" : "Scan email";

  return (
    <div className="scan-page">
      <h1 className="scan-title">What looks suspicious?</h1>

      <div
        id="scan-console"
        className="console"
        data-dragging={dragging || undefined}
        onDragOver={(e) => {
          e.preventDefault();
          if (phase === "idle") setDragging(true);
        }}
        onDragLeave={(e) => {
          if (!e.currentTarget.contains(e.relatedTarget as Node)) setDragging(false);
        }}
        onDrop={onDrop}
      >
        {phase === "idle" ? (
          <form onSubmit={submit} noValidate>
            <div className="console-top">
              <Segmented
                label="What to scan"
                value={kind}
                onChange={(v) => {
                  setKind(v);
                  setError(null);
                  window.setTimeout(() => inputRef.current?.focus(), 0);
                }}
                options={MODES}
              />
            </div>
            <label className="visually-hidden" htmlFor="scan-input">
              {scanLabel}
            </label>
            {kind === "email" ? (
              file ? (
                <div className="file-pill">
                  <FileUp size={16} aria-hidden="true" />
                  <span className="mono">{file.name}</span>
                  <span className="faint small">{(file.size / 1024).toFixed(1)} KB</span>
                  <button type="button" className="icon-btn icon-btn-sm" onClick={() => setFile(null)} aria-label="Remove file">
                    <X size={14} />
                  </button>
                </div>
              ) : (
                <textarea
                  id="scan-input"
                  ref={inputRef}
                  className="console-input console-textarea"
                  placeholder={PLACEHOLDER.email}
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) submit();
                  }}
                  spellCheck={false}
                  autoFocus
                />
              )
            ) : (
              <input
                id="scan-input"
                ref={inputRef}
                className="console-input"
                placeholder={PLACEHOLDER[kind]}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                onPaste={(e) => onInputPaste(e.clipboardData.getData("text"))}
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                autoFocus
              />
            )}
            {error && (
              <p className="field-error" role="alert">
                {error}
              </p>
            )}
            <div className="console-foot">
              <div className="console-toggles">
                {kind !== "domain" && <Switch checked={ob.deep} onChange={(deep) => updateOnboarding({ deep })} label={kind === "url" ? "Investigate" : "Check sender"} />}
                <Switch checked={ob.useIntel} onChange={(useIntel) => updateOnboarding({ useIntel })} label="Threat feeds" />
              </div>
              <div className="console-actions">
                {kind === "email" && (
                  <label className="btn btn-outline">
                    <FileUp size={15} aria-hidden="true" />
                    Upload .eml
                    <input
                      type="file"
                      accept=".eml,message/rfc822,text/plain"
                      className="visually-hidden"
                      onChange={(e) => {
                        setFile(e.target.files?.[0] ?? null);
                        setValue("");
                      }}
                    />
                  </label>
                )}
                <button className="btn btn-primary" type="submit">
                  {scanLabel}
                  <ArrowRight size={15} aria-hidden="true" />
                </button>
              </div>
            </div>
            {dragging && <div className="drop-overlay">Drop the .eml file to scan it</div>}
          </form>
        ) : (
          <Progress
            req={current!}
            phase={phase}
            onCancel={() => {
              runId.current += 1;
              setPhase("idle");
            }}
          />
        )}
      </div>

      <section className="scan-list" aria-labelledby="examples-title">
        <h2 id="examples-title">Try a known trick</h2>
        <ul className="rows">
          {EXAMPLES.map((ex) => (
            <li key={ex.technique}>
              <button
                type="button"
                className="row"
                disabled={phase !== "idle"}
                onClick={() => {
                  setKind(ex.kind);
                  setValue(ex.value);
                  void start({ kind: ex.kind, value: ex.value, deep: ob.deep, useIntel: ob.useIntel });
                }}
              >
                <span className="row-title">{ex.technique}</span>
                <span className="row-mono">{ex.shown ?? ex.value}</span>
                <ArrowRight size={15} className="row-arrow" aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      </section>

      {recent.length > 0 && (
        <section className="scan-list" aria-labelledby="recent-title">
          <div className="section-row">
            <h2 id="recent-title">Recent</h2>
            <Link to="/history">View all</Link>
          </div>
          <ul className="rows">
            {recent.map((r) => (
              <li key={r.id}>
                <Link to={`/scans/${r.id}`} className="row">
                  <span className="row-mono row-grow">{r.target}</span>
                  <span className="row-meta">
                    {TYPE_LABEL[r.scan_type]}, {relativeTime(r.created_at)}
                  </span>
                  <VerdictBadge verdict={r.verdict} />
                  <RiskBars score={r.risk_score} />
                </Link>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

function Progress({ req, phase, onCancel }: { req: ScanRequest; phase: Phase; onCancel: () => void }) {
  const steps = stepsFor(req.kind, req.deep, req.useIntel);
  const [localDone, setLocalDone] = useState(0);
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const locals = steps.filter((s) => s.local).length;
    let n = 0;
    const t = window.setInterval(() => {
      n += 1;
      setLocalDone(n);
      if (n >= locals) window.clearInterval(t);
    }, 220);
    const e = window.setInterval(() => setElapsed((x) => x + 0.1), 100);
    return () => {
      window.clearInterval(t);
      window.clearInterval(e);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  let localIndex = 0;
  const target = req.file && !req.value.trim() ? req.file.name : req.kind === "email" ? (req.value.match(/^subject:\s*(.+)$/im)?.[1] ?? "Email message") : req.value.trim();

  return (
    <motion.div className="progress" role="status" aria-live="polite" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.2 }}>
      <div className="progress-head">
        <div>
          <div className="progress-label">{phase === "done" ? "Scan complete" : "Scanning"}</div>
          <div className="progress-target">{target}</div>
        </div>
        <div className="progress-time">{elapsed.toFixed(1)} s</div>
      </div>
      <ol className="steps">
        {steps.map((s) => {
          let state: "wait" | "run" | "done";
          if (phase === "done") state = "done";
          else if (s.local) {
            localIndex += 1;
            state = localDone >= localIndex ? "done" : localDone + 1 === localIndex ? "run" : "wait";
          } else state = localDone >= 1 ? "run" : "wait";
          return (
            <li key={s.id} className="step" data-state={state}>
              <span className="step-icon" aria-hidden="true">
                {state === "done" ? <Check size={11} strokeWidth={3} /> : state === "run" ? <LoaderCircle size={13} className="spin" /> : null}
              </span>
              <span>{s.label}</span>
            </li>
          );
        })}
      </ol>
      {phase !== "done" && (
        <button type="button" className="btn btn-ghost btn-sm progress-cancel" onClick={onCancel}>
          Cancel
        </button>
      )}
    </motion.div>
  );
}
