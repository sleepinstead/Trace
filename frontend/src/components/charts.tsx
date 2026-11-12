import { useState } from "react";
import { motion } from "motion/react";
import type { Stats } from "../lib/api";

const SERIES = [
  { key: "malicious", label: "Likely phishing", tone: "danger" },
  { key: "suspicious", label: "Suspicious", tone: "warn" },
  { key: "safe", label: "Looks safe", tone: "trust" },
] as const;

export function Legend() {
  return (
    <div className="legend" aria-hidden="true">
      {SERIES.map((s) => (
        <span key={s.key} data-tone={s.tone}>
          <i />
          {s.label}
        </span>
      ))}
    </div>
  );
}

/** Stacked daily bars with a hover readout. */
export function Timeline({ data }: { data: Stats["timeline"] }) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 960;
  const H = 220;
  const pad = { l: 26, r: 4, t: 8, b: 26 };
  const max = Math.max(1, ...data.map((d) => d.safe + d.suspicious + d.malicious));
  const step = (W - pad.l - pad.r) / data.length;
  const bw = Math.max(5, step * 0.64);
  const y = (v: number) => ((H - pad.t - pad.b) * v) / max;
  const ticks = max <= 4 ? Array.from({ length: max + 1 }, (_, i) => i) : [0, Math.round(max / 2), max];
  const hd = hover !== null ? data[hover] : null;
  const label = (date: string, opts: Intl.DateTimeFormatOptions) => new Date(`${date}T00:00:00`).toLocaleDateString(undefined, opts);

  return (
    <div className="timeline-chart" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} className="chart" role="img" aria-label={`Scans per day over the last ${data.length} days`}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.l} x2={W - pad.r} y1={H - pad.b - y(t)} y2={H - pad.b - y(t)} className="grid" />
            <text x={pad.l - 8} y={H - pad.b - y(t) + 4} textAnchor="end">
              {t}
            </text>
          </g>
        ))}
        {data.map((d, i) => {
          const x = pad.l + i * step + (step - bw) / 2;
          let acc = 0;
          return (
            <g key={d.date} onMouseEnter={() => setHover(i)}>
              <rect x={pad.l + i * step} y={pad.t} width={step} height={H - pad.t - pad.b} className="hit" data-on={hover === i ? "true" : undefined} />
              {[...SERIES].reverse().map((s) => {
                const v = d[s.key];
                if (!v) return null;
                const h = y(v);
                acc += h;
                return <motion.rect key={s.key} x={x} width={bw} rx={2.5} className="bar" data-tone={s.tone} initial={{ y: H - pad.b, height: 0 }} animate={{ y: H - pad.b - acc, height: Math.max(h - 1.5, 1) }} transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }} />;
              })}
              {(i % 7 === 0 && i < data.length - 4) || i === data.length - 1 ? (
                <text x={x + bw / 2} y={H - 6} textAnchor="middle">
                  {label(d.date, { day: "numeric", month: "short" })}
                </text>
              ) : null}
            </g>
          );
        })}
      </svg>
      {hd && hover !== null && (
        <div className="chart-tip" style={{ left: `${((pad.l + hover * step + step / 2) / W) * 100}%` }}>
          <strong>{label(hd.date, { weekday: "short", day: "numeric", month: "short" })}</strong>
          <span>{hd.malicious} phishing</span>
          <span>{hd.suspicious} suspicious</span>
          <span>{hd.safe} safe</span>
        </div>
      )}
    </div>
  );
}

/** Verdict share as one segmented bar. */
export function ShareBar({ counts }: { counts: Record<"safe" | "suspicious" | "malicious", number> }) {
  const total = counts.safe + counts.suspicious + counts.malicious || 1;
  return (
    <div>
      <div className="share-bar" role="img" aria-label={`${counts.malicious} phishing, ${counts.suspicious} suspicious, ${counts.safe} safe`}>
        {SERIES.map((s) => (counts[s.key] ? <motion.span key={s.key} data-tone={s.tone} initial={{ flexGrow: 0 }} animate={{ flexGrow: counts[s.key] / total }} transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }} /> : null))}
      </div>
      <ul className="share-list">
        {SERIES.map((s) => (
          <li key={s.key} data-tone={s.tone}>
            <i aria-hidden="true" />
            <span>{s.label}</span>
            <b>{Math.round((counts[s.key] / total) * 100)}%</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function BarList({ items, max }: { items: { key: string; label: string; value: number; display?: string }[]; max?: number }) {
  const m = max ?? Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="barlist">
      {items.map((it) => (
        <li key={it.key}>
          <span className="bl-label">{it.label}</span>
          <span className="bl-track" aria-hidden="true">
            <motion.span initial={{ width: 0 }} animate={{ width: `${(it.value / m) * 100}%` }} transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }} />
          </span>
          <span className="bl-val">{it.display ?? it.value}</span>
        </li>
      ))}
    </ul>
  );
}
