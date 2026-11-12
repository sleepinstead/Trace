import { Fragment } from "react";
import type { Term } from "../lib/anatomy";

/** Text with line-break opportunities after URL separators, so long links wrap at "/" or "." and not mid-word. */
export function Breakable({ text }: { text: string }) {
  const parts = text.split(/(?<=[/.?&=_-])/);
  return (
    <>
      {parts.map((p, i) => (
        <Fragment key={i}>
          {p}
          {/[/.?&=_-]$/.test(p) ? <wbr /> : null}
        </Fragment>
      ))}
    </>
  );
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Mark every occurrence of the given terms inside `text` (case-insensitive). */
export function Highlight({
  text,
  terms,
  breakable = false,
  dimOthers,
}: {
  text: string;
  terms: Term[];
  breakable?: boolean;
  /** When set, only terms whose title matches stay emphasised. */
  dimOthers?: string | null;
}) {
  const usable = terms.filter((t) => t.term && t.term.length > 1).sort((a, b) => b.term.length - a.term.length);
  const plain = (t: string) => (breakable ? <Breakable text={t} /> : t);
  if (!usable.length || !text) return <>{plain(text)}</>;
  const lookup = new Map(usable.map((t) => [t.term.toLowerCase(), t]));
  const re = new RegExp(`(${usable.map((t) => escape(t.term)).join("|")})`, "gi");
  return (
    <>
      {text.split(re).map((part, i) => {
        const hit = lookup.get(part.toLowerCase());
        if (!hit) return <Fragment key={i}>{plain(part)}</Fragment>;
        const dim = dimOthers && dimOthers !== hit.title;
        return (
          <mark key={i} className="hl" data-tone={hit.tone} data-dim={dim ? "true" : undefined} title={hit.title}>
            {part}
          </mark>
        );
      })}
    </>
  );
}
