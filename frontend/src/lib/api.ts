export type Verdict = "safe" | "suspicious" | "malicious";
export type ScanType = "url" | "domain" | "email";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  id: string;
  category: string;
  kind: "risk" | "trust" | "info";
  severity: Severity;
  title: string;
  detail: string;
  weight: number;
  evidence: string[];
}

export interface ScoreBreakdown {
  rule_score: number;
  ml_probability: number | null;
  ml_weight: number;
  blended: number;
  trust_multiplier: number;
  intel_floor: number;
  final: number;
  thresholds: { suspicious: number; malicious: number };
}

export interface MlExplanation {
  feature: string;
  label: string;
  value: number;
  contribution: number;
  direction: "phishing" | "legitimate";
}

export interface MlResult {
  probability: number;
  label: string;
  models: Record<string, number>;
  explanations: MlExplanation[];
  features: Record<string, number>;
}

export interface IntelSource {
  source: string;
  name: string;
  status: "malicious" | "suspicious" | "clean" | "unknown" | "error" | "disabled";
  detail: string;
  reference: string | null;
  cached: boolean;
}

export interface IntelSummary {
  malicious: number;
  suspicious: number;
  checked: number;
  sources: IntelSource[];
}

export interface RedirectHop {
  url: string;
  status: number | null;
  location?: string;
  via?: string;
  content_type?: string;
  error?: string;
}

export interface PageInfo {
  title?: string;
  forms?: number;
  password_fields?: number;
  sensitive_fields?: string[];
  external_form_actions?: string[];
  js_redirect?: boolean;
  obfuscated_js?: boolean;
  title_brands?: string[];
  brand_assets?: Record<string, number>;
}

export interface Registration {
  found?: boolean | null;
  source?: string;
  created?: string | null;
  expires?: string | null;
  updated?: string | null;
  registrar?: string | null;
  status?: string[];
  nameservers?: string[];
  age_days?: number;
  error?: string;
}

export interface DnsInfo {
  nxdomain: boolean;
  a: string[];
  aaaa: string[];
  cname: string[];
  mx: string[];
  ns: string[];
  spf: string | null;
  dmarc: string | null;
  dmarc_policy: string | null;
  errors: Record<string, string>;
}

export interface TlsInfo {
  available: boolean;
  verified?: boolean;
  skipped?: boolean;
  error?: string | null;
  subject_cn?: string;
  issuer_cn?: string;
  issuer_org?: string;
  self_signed?: boolean;
  not_before?: string;
  not_after?: string;
  age_days?: number;
  days_remaining?: number;
  san?: string[];
  san_count?: number;
}

export interface ScanResult {
  id: string;
  scan_type: ScanType;
  target: string;
  verdict: Verdict;
  risk_score: number;
  summary: string;
  findings: Finding[];
  score_breakdown: ScoreBreakdown;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  details: Record<string, any>;
  created_at: string;
  duration_ms: number;
}

export interface ScanListItem {
  id: string;
  scan_type: ScanType;
  target: string;
  verdict: Verdict;
  risk_score: number;
  summary: string;
  created_at: string;
}

export interface Stats {
  total_scans: number;
  by_verdict: Record<Verdict, number>;
  by_type: Record<ScanType, number>;
  average_risk: number;
  threat_records: number;
  timeline: { date: string; safe: number; suspicious: number; malicious: number }[];
  top_techniques: { id: string; title: string; count: number }[];
}

export interface ThreatRecord {
  id: number;
  indicator: string;
  indicator_type: "url" | "domain" | "ip" | "email";
  threat_type: string;
  source: string;
  description: string;
  created_at: string;
}

export interface ProviderStatus {
  source: string;
  name: string;
  enabled: boolean;
  env: string | null;
}

export interface ModelInfo {
  trained_at: string;
  dataset: string;
  n_samples: number;
  n_phishing: number;
  n_legitimate: number;
  test_size: number;
  n_features: number;
  ensemble_weights: Record<string, number>;
  metrics: Record<string, Record<string, number>>;
  top_features: { feature: string; label: string; importance: number }[];
  training_seconds: number;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const OFFLINE = "The scanner isn't running. Start Trace with npm run dev from the project folder, then try again.";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError(0, OFFLINE);
  }
  if (res.status >= 502 && res.status <= 504) throw new ApiError(res.status, OFFLINE); // the dev proxy's answer when the API is down
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const detail = body?.detail;
    const message = Array.isArray(detail)
      ? detail.map((d: { msg: string }) => d.msg).join("; ")
      : typeof detail === "string"
        ? detail
        : `Request failed (${res.status})`;
    throw new ApiError(res.status, message);
  }
  return body as T;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  scanUrl: (url: string, deep: boolean, use_intel: boolean) =>
    request<ScanResult>("/api/scan/url", json({ url, deep, use_intel })),
  scanDomain: (domain: string, use_intel: boolean) =>
    request<ScanResult>("/api/scan/domain", json({ domain, use_intel })),
  scanEmail: (raw: string, deep: boolean, use_intel: boolean) =>
    request<ScanResult>("/api/scan/email", json({ raw, deep, use_intel })),
  scanEmailFile: (file: File, deep: boolean, use_intel: boolean) => {
    const form = new FormData();
    form.append("file", file);
    form.append("deep", String(deep));
    form.append("use_intel", String(use_intel));
    return request<ScanResult>("/api/scan/email/upload", { method: "POST", body: form });
  },
  scan: (id: string) => request<ScanResult>(`/api/scans/${id}`),
  deleteScan: (id: string) => request<void>(`/api/scans/${id}`, { method: "DELETE" }),
  scans: (params: { scan_type?: string; verdict?: string; q?: string; limit?: number; offset?: number }) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => v !== undefined && v !== "" && qs.set(k, String(v)));
    return request<{ items: ScanListItem[]; total: number }>(`/api/scans?${qs}`);
  },
  stats: () => request<Stats>("/api/stats"),
  threats: (q?: string) =>
    request<{ items: ThreatRecord[]; total: number }>(`/api/threats${q ? `?q=${encodeURIComponent(q)}` : ""}`),
  addThreat: (rec: { indicator: string; indicator_type: string; threat_type: string; description: string }) =>
    request<ThreatRecord>("/api/threats", json(rec)),
  deleteThreat: (id: number) => request<void>(`/api/threats/${id}`, { method: "DELETE" }),
  providers: () => request<ProviderStatus[]>("/api/intel/status"),
  model: () => request<ModelInfo>("/api/model"),
  health: () => request<{ status: string; model_loaded: boolean }>("/api/health"),
};
