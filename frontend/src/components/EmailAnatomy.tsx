import { useState } from "react";
import { CircleCheck, CircleDashed, CircleX } from "lucide-react";
import type { Finding, ScanResult } from "../lib/api";
import { strongestTone, toneOf } from "../lib/format";
import type { Term } from "../lib/anatomy";
import { Highlight } from "./Highlight";
import { SeverityIcon } from "./ui";

const AUTH_INFO: Record<string, { name: string; what: string }> = {
  SPF: { name: "SPF", what: "Is the sending server allowed to send for this domain?" },
  DKIM: { name: "DKIM", what: "Is the message signed and unaltered?" },
  DMARC: { name: "DMARC", what: "Does the visible From domain pass the domain's own policy?" },
};

function AuthTile({ label, value }: { label: keyof typeof AUTH_INFO; value?: string | null }) {
  const v = (value ?? "").toLowerCase();
  const pass = v === "pass";
  const fail = ["fail", "softfail", "permerror", "temperror"].includes(v);
  const tone = pass ? "trust" : fail ? "danger" : "neutral";
  const Icon = pass ? CircleCheck : fail ? CircleX : CircleDashed;
  return (
    <div className="auth-tile" data-tone={tone}>
      <Icon size={22} aria-hidden="true" />
      <div>
        <div className="auth-name">
          {AUTH_INFO[label].name} <span className="auth-val">{v || "not reported"}</span>
        </div>
        <div className="auth-what">{AUTH_INFO[label].what}</div>
      </div>
    </div>
  );
}

const has = (findings: Finding[], ids: string[]) => findings.filter((f) => ids.includes(f.id));

const CATEGORY_NAMES: Record<string, string> = {
  "content.urgency": "Urgency",
  "content.threat": "Account threats",
  "content.credentials": "Asks for credentials",
  "content.lure": "Rewards and money",
  "content.generic_greeting": "Generic greeting",
  "content.bec": "Business email compromise",
  "link.text_mismatch": "Disguised link",
};

export default function EmailAnatomy({ result }: { result: ScanResult }) {
  const { details: d, findings } = result;
  const s = d.sender ?? {};
  const auth = d.authentication ?? {};
  const [focus, setFocus] = useState<string | null>(null);

  const rows = [
    {
      key: "from",
      label: "From",
      value: (
        <>
          {s.display_name ? <span className="env-display">{s.display_name}</span> : null}
          <span className="mono">{s.address ? `<${s.address}>` : "not provided"}</span>
        </>
      ),
      findings: has(findings, ["email.display_name_spoof", "email.display_address_mismatch", "email.free_provider_org", "email.lookalike_domain", "email.brand_domain", "auth.sender_nxdomain", "sender.domain.age_new", "sender.domain.age_young", "intel.local"]),
    },
    ...(s.reply_to?.length
      ? [{ key: "reply", label: "Reply-To", value: <span className="mono">{s.reply_to.join(", ")}</span>, findings: has(findings, ["email.reply_to_mismatch"]) }]
      : []),
    ...(s.return_path ? [{ key: "rp", label: "Return-Path", value: <span className="mono">{s.return_path}</span>, findings: has(findings, ["email.return_path_mismatch"]) }] : []),
    { key: "subject", label: "Subject", value: <span>{s.subject || "none"}</span>, findings: [] as Finding[] },
  ];

  const phraseFindings = findings.filter((f) => (f.id.startsWith("content.") || f.id === "link.text_mismatch") && f.evidence?.length);
  const terms: Term[] = phraseFindings.flatMap((f) => f.evidence.map((term) => ({ term, tone: toneOf(f), title: f.title })));

  return (
    <div className="email-anatomy">
      <div className="envelope">
        {rows.map((r) => (
          <div key={r.key} className="env-row" data-tone={strongestTone(r.findings)}>
            <span className="env-label">{r.label}</span>
            <div className="env-value">
              <div className="env-main">{r.key === "subject" ? <Highlight text={s.subject || "none"} terms={terms} dimOthers={focus} /> : r.value}</div>
              {r.findings.length > 0 && (
                <div className="env-notes">
                  {r.findings.map((f) => (
                    <span key={f.id} className="part-note">
                      <SeverityIcon finding={f} size={15} />
                      {f.title}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="auth-tiles">
        <AuthTile label="SPF" value={auth.spf} />
        <AuthTile label="DKIM" value={auth.dkim} />
        <AuthTile label="DMARC" value={auth.dmarc} />
      </div>

      {d.body_preview ? (
        <div className="body-card">
          <div className="body-head">
            <span className="body-title">Message body</span>
            {phraseFindings.length > 0 && (
              <div className="body-cats" role="group" aria-label="Highlight a tactic" onMouseLeave={() => setFocus(null)}>
                {phraseFindings.map((f) => (
                  <button
                    key={f.id}
                    type="button"
                    className="cat"
                    data-tone={toneOf(f)}
                    aria-pressed={focus === f.title}
                    onMouseEnter={() => setFocus(f.title)}
                    onFocus={() => setFocus(f.title)}
                    onBlur={() => setFocus(null)}
                    onClick={() => setFocus(focus === f.title ? null : f.title)}
                  >
                    <i aria-hidden="true" />
                    {CATEGORY_NAMES[f.id] ?? f.title}
                    <span className="n">{f.evidence.length}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          <p className="body-text">
            <Highlight text={d.body_preview} terms={terms} dimOthers={focus} />
          </p>
          {d.body_preview.length >= 1500 ? <p className="faint small">Showing the first 1,500 characters.</p> : null}
        </div>
      ) : null}
    </div>
  );
}
