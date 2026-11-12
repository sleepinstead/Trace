import type { Finding, ScanType, Severity, Verdict } from "./api";

export type Tone = "danger" | "warn" | "trust" | "neutral";

export const VERDICT_LABEL: Record<Verdict, string> = {
  safe: "Looks safe",
  suspicious: "Suspicious",
  malicious: "Likely phishing",
};

export const VERDICT_TONE: Record<Verdict, Tone> = { safe: "trust", suspicious: "warn", malicious: "danger" };

export const TYPE_LABEL: Record<ScanType, string> = { url: "Link", domain: "Domain", email: "Email" };

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Note",
};

export function toneOf(f: Pick<Finding, "kind" | "severity">): Tone {
  if (f.kind === "trust") return "trust";
  if (f.kind === "info") return "neutral";
  return f.severity === "critical" || f.severity === "high" ? "danger" : "warn";
}

const RANK: Record<Tone, number> = { danger: 3, warn: 2, trust: 1, neutral: 0 };

export function strongestTone(findings: Pick<Finding, "kind" | "severity">[]): Tone {
  return findings.reduce<Tone>((best, f) => (RANK[toneOf(f)] > RANK[best] ? toneOf(f) : best), "neutral");
}

export function relativeTime(iso: string): string {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 45) return "just now";
  if (diff < 3600) return `${Math.max(1, Math.round(diff / 60))} min ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)} h ago`;
  if (diff < 86400 * 7) return `${Math.round(diff / 86400)} d ago`;
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

export function formatDate(iso?: string | null): string {
  if (!iso) return "Unknown";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  return `${d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })}, ${d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}`;
}

export function formatAge(days?: number | null): string {
  if (days === undefined || days === null) return "Unknown";
  if (days < 1) return "Under a day";
  if (days < 60) return `${days} day${days === 1 ? "" : "s"}`;
  if (days < 730) return `${Math.round(days / 30.4)} months`;
  return `${Math.floor(days / 365)} years`;
}

export function pct(n: number | null | undefined, digits = 0): string {
  if (n === null || n === undefined) return "n/a";
  return `${(n * 100).toFixed(digits)}%`;
}

/** Guess what was pasted: a full email, a URL or a bare domain. */
export function detectInputType(value: string): ScanType | null {
  const v = value.trim();
  if (!v) return null;
  if (/\n/.test(v) && /^(from|received|return-path|subject|to|date|delivered-to|mime-version|authentication-results|message-id):/im.test(v)) return "email";
  if (/\n.*\n/.test(v)) return "email";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v) || /[/?#@]/.test(v)) return "url";
  if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}\.?$/i.test(v)) return "domain";
  return null;
}

export function shorten(text: string, max = 60): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
