import type { Verdict } from "../lib/api";
import { VERDICT_TONE } from "../lib/format";
import { useCountUp } from "../lib/useCountUp";

const TICKS = 60;

/** Risk as a ruler of ticks, filled up to the score, with the verdict thresholds marked. */
export default function Gauge({ score, verdict, thresholds }: { score: number; verdict: Verdict; thresholds: { suspicious: number; malicious: number } }) {
  const shown = useCountUp(score, { duration: 0.9 });
  return (
    <div className="gauge" data-tone={VERDICT_TONE[verdict]} role="img" aria-label={`Risk score ${score} out of 100`}>
      <div className="gauge-num">
        {Math.round(shown)}
        <span>/100</span>
      </div>
      <div className="gauge-ticks" aria-hidden="true">
        {Array.from({ length: TICKS }, (_, i) => {
          const on = ((i + 0.5) / TICKS) * 100 <= score;
          return <i key={i} data-on={on} style={on ? { animationDelay: `${i * 12}ms` } : undefined} />;
        })}
      </div>
      <div className="gauge-labels" aria-hidden="true">
        <span style={{ left: `${thresholds.suspicious}%` }}>Suspicious</span>
        <span style={{ left: `${thresholds.malicious}%` }}>Phishing</span>
      </div>
    </div>
  );
}
