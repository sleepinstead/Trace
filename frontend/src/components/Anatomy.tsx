import { useState } from "react";
import { MoveRight } from "lucide-react";
import type { Finding } from "../lib/api";
import { evidenceTerms, urlParts, type ParsedUrl, type Part } from "../lib/anatomy";
import { Breakable, Highlight } from "./Highlight";
import { SeverityIcon } from "./ui";

const KEYWORD_IDS = (id: string) => ["url.keywords", "url.brand_path", "url.brand_subdomain"].includes(id);

/** The link as a specimen, with a row explaining each part. Hovering a row lights its part of the address, and vice versa. */
export default function Anatomy({ parsed, findings, hostOnly = false, finalUrl }: { parsed: ParsedUrl; findings: Finding[]; hostOnly?: boolean; finalUrl?: string | null }) {
  const parts = urlParts(parsed, findings, { hostOnly });
  const terms = evidenceTerms(findings, KEYWORD_IDS);
  const [hot, setHot] = useState<number | null>(null);
  const site = parts.find((p) => p.role === "site")!;

  return (
    <div className="anatomy">
      <div className="specimen" onMouseLeave={() => setHot(null)}>
        <p className="specimen-text">
          {parts.map((p, i) => (
            <span key={p.role}>
              {p.before ? <span className="sp-sep">{p.before}</span> : null}
              <span className={`sp sp-${p.role}`} data-tone={p.tone} data-hot={hot === i ? "true" : undefined} onMouseEnter={() => setHot(i)}>
                <Breakable text={p.text} />
              </span>
              {p.after ? (
                <span className="sp-sep">
                  {p.after}
                  <wbr />
                </span>
              ) : null}
            </span>
          ))}
        </p>
        <div className="destination">
          <span className="dest-label">{parsed.is_ip ? "Connects straight to" : "Actually opens"}</span>
          <span className="dest-value">
            <Breakable text={site.text} />
          </span>
          {finalUrl ? (
            <span className="dest-final">
              <MoveRight size={14} aria-hidden="true" />
              lands on{" "}
              <span className="mono">
                <Breakable text={finalUrl} />
              </span>
            </span>
          ) : null}
        </div>
      </div>

      <ol className="parts" onMouseLeave={() => setHot(null)}>
        {parts.map((p, i) => (
          <PartRow key={p.role} part={p} hot={hot === i} onHover={() => setHot(i)} terms={terms} />
        ))}
      </ol>
    </div>
  );
}

function PartRow({ part, hot, onHover, terms }: { part: Part; hot: boolean; onHover: () => void; terms: ReturnType<typeof evidenceTerms> }) {
  const notes = [...part.findings.filter((f) => f.kind === "risk"), ...part.findings.filter((f) => f.kind === "trust")];
  return (
    <li className="part" data-hot={hot ? "true" : undefined} onMouseEnter={onHover} onFocus={onHover} tabIndex={0}>
      <div className="part-label">{part.label}</div>
      <div className="part-text">
        {part.before}
        {part.role === "site" ? <Breakable text={part.text} /> : <Highlight text={part.text} terms={part.role === "scheme" ? [] : terms} breakable />}
      </div>
      <div className="part-notes">
        {notes.length === 0 ? <p className="part-hint">{part.hint}</p> : null}
        {notes.slice(0, 4).map((f, i) => (
          <p key={`${f.id}-${i}`} className="part-note">
            <SeverityIcon finding={f} size={15} />
            {f.title}
          </p>
        ))}
        {notes.length > 4 ? <p className="part-hint">and {notes.length - 4} more below</p> : null}
      </div>
    </li>
  );
}
