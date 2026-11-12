import { motion } from "motion/react";
import type { ScoreBreakdown, Verdict } from "../lib/api";
import { VERDICT_TONE } from "../lib/format";

function Bar({ value, tone, delay }: { value: number; tone: string; delay: number }) {
  return (
    <span className="flow-bar" data-tone={tone} aria-hidden="true">
      <motion.span initial={{ width: 0 }} animate={{ width: `${Math.max(value * 100, 1)}%` }} transition={{ delay, duration: 0.6, ease: [0.22, 1, 0.36, 1] }} />
    </span>
  );
}

/** How the final number was produced, step by step, with bars that fill in order. */
export default function ScoreFlow({ b, verdict, emailMode = false }: { b: ScoreBreakdown; verdict: Verdict; emailMode?: boolean }) {
  const hasMl = b.ml_probability !== null;
  const steps = [
    {
      label: "Rule engine",
      note: emailMode ? "Every red flag, combined so independent signals reinforce each other" : "All red flags, combined so independent signals reinforce each other",
      value: b.rule_score,
      shown: `${Math.round(b.rule_score * 100)}`,
      tone: "neutral",
    },
    ...(hasMl
      ? [
          {
            label: "Model",
            note: `Phishing probability from the URL model, weighted ${Math.round(b.ml_weight * 100)}%`,
            value: b.ml_probability!,
            shown: `${Math.round(b.ml_probability! * 100)}`,
            tone: "neutral",
          },
          { label: "Blended", note: "Rules and model together", value: b.blended, shown: `${Math.round(b.blended * 100)}`, tone: "neutral" },
        ]
      : []),
    {
      label: "Trust",
      note: b.trust_multiplier < 1 ? `Points in its favour take ${Math.round((1 - b.trust_multiplier) * 100)}% off` : "Nothing in its favour",
      value: 1 - b.trust_multiplier,
      shown: b.trust_multiplier < 1 ? `−${Math.round((1 - b.trust_multiplier) * 100)}%` : "0%",
      tone: "trust",
    },
    ...(b.intel_floor > 0
      ? [{ label: "Threat feed", note: "A known-bad match sets a minimum score", value: b.intel_floor, shown: `≥ ${Math.round(b.intel_floor * 100)}`, tone: "danger" }]
      : []),
  ];
  return (
    <div className="flow">
      <ol className="flow-steps">
        {steps.map((s) => (
          <li key={s.label} className="flow-step">
            <div className="flow-head">
              <span className="flow-label">{s.label}</span>
              <span className="flow-val">{s.shown}</span>
            </div>
            <Bar value={s.value} tone={s.tone} delay={0.1} />
            <p className="flow-note">{s.note}</p>
          </li>
        ))}
      </ol>
      <div className="flow-final" data-tone={VERDICT_TONE[verdict]}>
        <span>Risk score</span>
        <strong>{Math.round(b.final * 100)}</strong>
        <Bar value={b.final} tone={VERDICT_TONE[verdict]} delay={0.1} />
        <div className="flow-scale" aria-hidden="true">
          <span>0</span>
          <span style={{ left: `${b.thresholds.suspicious}%` }}>{b.thresholds.suspicious}</span>
          <span style={{ left: `${b.thresholds.malicious}%` }}>{b.thresholds.malicious}</span>
          <span style={{ left: "100%" }}>100</span>
        </div>
      </div>
    </div>
  );
}
