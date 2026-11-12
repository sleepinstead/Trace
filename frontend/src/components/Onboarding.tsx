import { useEffect, useLayoutEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";
import { Check, ChevronDown, X } from "lucide-react";
import { api } from "../lib/api";
import { updateOnboarding, useOnboarding } from "../lib/onboarding";
import { Kbd, MOD } from "./ui";

const STEPS = [
  { target: "#scan-console", title: "Start here", body: "Paste a link, domain or full email. Trace works out which one it is.", art: "input" },
  { target: ".dock-search", title: "Scan from anywhere", body: "Open this on any page to scan something or jump to a past result.", art: "keys" },
  { target: '.dock a[href="/history"]', title: "Nothing gets lost", body: "Every scan stays on this machine with its full evidence.", art: "rows" },
] as const;

function Art({ kind }: { kind: (typeof STEPS)[number]["art"] }) {
  if (kind === "keys") {
    return (
      <div className="tour-art tour-art-keys">
        <Kbd keys={[MOD, "K"]} />
      </div>
    );
  }
  return (
    <div className="tour-art" data-kind={kind}>
      <span />
      <span />
      <span />
    </div>
  );
}

/** Three popovers pointing at the real interface, shown once after onboarding. */
export function Tour() {
  const [step, setStep] = useState(0);
  const [box, setBox] = useState<DOMRect | null>(null);
  const s = STEPS[step];
  const finish = () => updateOnboarding({ tourDone: true });

  useLayoutEffect(() => {
    const measure = () => setBox(document.querySelector(s.target)?.getBoundingClientRect() ?? null);
    measure();
    const t = window.setTimeout(measure, 300);
    window.addEventListener("resize", measure);
    return () => {
      window.clearTimeout(t);
      window.removeEventListener("resize", measure);
    };
  }, [s.target]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && updateOnboarding({ tourDone: true });
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (!box) return null;
  const width = 280;
  const margin = 12;
  const cx = box.left + box.width / 2;
  const left = Math.min(Math.max(margin, cx - width / 2), window.innerWidth - width - margin);
  const below = box.top < window.innerHeight / 2;
  const last = step === STEPS.length - 1;

  return (
    <motion.div
      key={step}
      className="tour"
      role="dialog"
      aria-label={s.title}
      data-below={below}
      style={{ left, width, ...(below ? { top: Math.min(box.bottom + 12, window.innerHeight - 280) } : { bottom: window.innerHeight - box.top + 12 }) }}
      initial={{ opacity: 0, y: below ? -6 : 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
    >
      <span className="tour-arrow" style={{ left: Math.min(Math.max(20, cx - left), width - 20) }} aria-hidden="true" />
      <Art kind={s.art} />
      <h2>{s.title}</h2>
      <p>{s.body}</p>
      <div className="tour-foot">
        <button type="button" className="tour-skip" onClick={finish}>
          Skip
        </button>
        <span className="tour-count">
          {step + 1} of {STEPS.length}
        </span>
        <button type="button" className="tour-next" onClick={() => (last ? finish() : setStep(step + 1))} autoFocus>
          {last ? "Done" : "Next"}
        </button>
      </div>
    </motion.div>
  );
}

/** Getting-started card. Items tick themselves off from what the user has really done. */
export function Checklist({ onOpenPalette }: { onOpenPalette: () => void }) {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const ob = useOnboarding();
  const [open, setOpen] = useState(false);
  const [counts, setCounts] = useState({ scans: 0, blocked: 0 });

  // Expanded only on the scanner, so it never sits over a result or table.
  useEffect(() => setOpen(pathname === "/scan" && window.innerWidth > 720), [pathname]);

  useEffect(() => {
    if (pathname.startsWith("/scans/") && !ob.openedResult) updateOnboarding({ openedResult: true });
    Promise.all([api.scans({ limit: 1 }), api.threats()])
      .then(([s, t]) => setCounts({ scans: s.total, blocked: t.total }))
      .catch(() => {});
  }, [pathname, ob.openedResult]);

  const items = [
    { label: "Run your first scan", done: counts.scans > 0, go: () => navigate("/scan") },
    { label: "Read a result", done: ob.openedResult, go: () => navigate("/history") },
    { label: "Block something", done: counts.blocked > 0, go: () => navigate("/blocklist") },
    { label: "Open quick search", done: ob.openedPalette, go: onOpenPalette },
  ];
  const done = items.filter((i) => i.done).length;

  return (
    <aside className="checklist" aria-label="Getting started">
      <div className="cl-head">
        <button type="button" className="cl-toggle" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
          <span>
            <strong>Getting started</strong>
            <small>
              {done} of {items.length} complete
            </small>
          </span>
          <motion.span animate={{ rotate: open ? 0 : 180 }} transition={{ duration: 0.2 }} style={{ display: "grid" }}>
            <ChevronDown size={16} aria-hidden="true" />
          </motion.span>
        </button>
        <button type="button" className="icon-btn icon-btn-sm" aria-label="Hide checklist" data-tip="Hide" onClick={() => updateOnboarding({ checklistHidden: true })}>
          <X size={14} />
        </button>
      </div>
      <AnimatePresence initial={false}>
        {open && (
          <motion.ul initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}>
            {items.map((it) => (
              <li key={it.label}>
                <button type="button" data-done={it.done} onClick={it.go}>
                  <span className="cl-check" aria-hidden="true">
                    {it.done ? <Check size={11} strokeWidth={3} /> : null}
                  </span>
                  <span className="cl-label">{it.label}</span>
                  <span className="visually-hidden">{it.done ? "done" : "not done"}</span>
                </button>
              </li>
            ))}
          </motion.ul>
        )}
      </AnimatePresence>
      <div className="cl-progress" aria-hidden="true">
        <motion.span animate={{ width: `${(done / items.length) * 100}%` }} transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }} />
      </div>
    </aside>
  );
}
