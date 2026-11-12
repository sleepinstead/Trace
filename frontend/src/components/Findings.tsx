import { useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import type { Finding } from "../lib/api";
import { SEVERITY_LABEL, toneOf } from "../lib/format";
import { SeverityIcon } from "./ui";

const CATEGORY: { id: string; label: string; match: (f: Finding) => boolean }[] = [
  { id: "address", label: "Address", match: (f) => f.category === "url" },
  { id: "page", label: "Page and redirects", match: (f) => f.category === "redirect" || (f.category === "content" && f.id.startsWith("page.")) },
  { id: "domain", label: "Domain", match: (f) => ["domain", "dns", "tls"].includes(f.category) },
  { id: "sender", label: "Sender", match: (f) => ["sender", "authentication"].includes(f.category) || f.id.startsWith("sender.") },
  { id: "message", label: "Message", match: (f) => (f.category === "content" && !f.id.startsWith("page.")) || f.category === "attachment" },
  { id: "links", label: "Links", match: (f) => f.category === "links" },
  { id: "ml", label: "Model", match: (f) => f.category === "ml" },
  { id: "intel", label: "Threat feeds", match: (f) => f.category === "intel" },
];

export default function Findings({ findings }: { findings: Finding[] }) {
  const [cat, setCat] = useState("all");
  const cats = useMemo(() => CATEGORY.map((c) => ({ ...c, n: findings.filter(c.match).length })).filter((c) => c.n > 0), [findings]);
  const visible = cat === "all" ? findings : findings.filter(CATEGORY.find((c) => c.id === cat)!.match);
  const groups = [
    { kind: "risk", title: "Red flags", items: visible.filter((f) => f.kind === "risk") },
    { kind: "trust", title: "In its favour", items: visible.filter((f) => f.kind === "trust") },
    { kind: "info", title: "Notes", items: visible.filter((f) => f.kind === "info") },
  ].filter((g) => g.items.length);
  const maxW = Math.max(0.3, ...findings.filter((f) => f.kind === "risk").map((f) => f.weight));

  return (
    <div className="findings">
      {cats.length > 1 && (
        <div className="chips" role="group" aria-label="Filter findings">
          <button type="button" className="chip" aria-pressed={cat === "all"} onClick={() => setCat("all")}>
            All <span className="n">{findings.length}</span>
          </button>
          {cats.map((c) => (
            <button key={c.id} type="button" className="chip" aria-pressed={cat === c.id} onClick={() => setCat(c.id)}>
              {c.label} <span className="n">{c.n}</span>
            </button>
          ))}
        </div>
      )}
      {groups.length === 0 && <p className="muted">No phishing indicators were found.</p>}
      {groups.map((g) => (
        <section key={g.kind} className="finding-group" aria-label={g.title}>
          <h3 className="fg-title">
            {g.title} <span className="faint">{g.items.length}</span>
          </h3>
          <ul className="finding-list">
            <AnimatePresence initial={false} mode="popLayout">
              {g.items.map((f) => (
                <motion.li
                  key={`${f.id}-${f.title}`}
                  layout
                  className="finding"
                  data-tone={toneOf(f)}
                  exit={{ opacity: 0, scale: 0.98, transition: { duration: 0.12 } }}
                  transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
                >
                  <SeverityIcon finding={f} />
                  <div className="finding-body">
                    <div className="finding-title">{f.title}</div>
                    {f.detail ? <p className="finding-detail">{f.detail}</p> : null}
                  </div>
                  <div className="finding-impact" title={f.kind === "trust" ? "How much this lowers the score, at most" : "How much this adds to the rule score"}>
                    {f.kind === "risk" && (
                      <>
                        <span className="impact-label">
                          {SEVERITY_LABEL[f.severity]}
                          {f.weight > 0 ? ` +${Math.round(f.weight * 100)}` : ""}
                        </span>
                        {f.weight > 0 && (
                          <span className="impact-bar" aria-hidden="true">
                            <motion.span initial={{ width: 0 }} animate={{ width: `${(f.weight / maxW) * 100}%` }} transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }} />
                          </span>
                        )}
                      </>
                    )}
                    {f.kind === "trust" && <span className="impact-label">up to −{Math.round(f.weight * 100)}%</span>}
                  </div>
                </motion.li>
              ))}
            </AnimatePresence>
          </ul>
        </section>
      ))}
    </div>
  );
}
