import { api, type ScanResult, type ScanType } from "./api";

export interface ScanRequest {
  kind: ScanType;
  value: string;
  file?: File | null;
  deep: boolean;
  useIntel: boolean;
}

export function runScan(r: ScanRequest): Promise<ScanResult> {
  if (r.kind === "url") return api.scanUrl(r.value.trim(), r.deep, r.useIntel);
  if (r.kind === "domain") return api.scanDomain(r.value.trim(), r.useIntel);
  if (r.file && !r.value.trim()) return api.scanEmailFile(r.file, r.deep, r.useIntel);
  return api.scanEmail(r.value, r.deep, r.useIntel);
}

export interface Step {
  id: string;
  label: string;
  /** Local steps finish almost instantly; network steps run in parallel until the server answers. */
  local?: boolean;
}

export function stepsFor(kind: ScanType, deep: boolean, useIntel: boolean): Step[] {
  if (kind === "url") {
    return [
      { id: "parse", label: "Reading the address", local: true },
      { id: "rules", label: "Checking 25 lure patterns", local: true },
      { id: "ml", label: "Asking the model for a second opinion", local: true },
      ...(deep
        ? [
            { id: "redirects", label: "Following redirects" },
            { id: "page", label: "Inspecting the landing page" },
            { id: "whois", label: "Looking up registration and DNS" },
            { id: "tls", label: "Checking the certificate" },
          ]
        : []),
      { id: "intel", label: useIntel ? "Querying threat feeds and your blocklist" : "Checking your blocklist" },
    ];
  }
  if (kind === "domain") {
    return [
      { id: "parse", label: "Reading the name", local: true },
      { id: "whois", label: "Looking up registration" },
      { id: "dns", label: "Resolving DNS records" },
      { id: "tls", label: "Checking the certificate" },
      { id: "home", label: "Visiting the homepage" },
      { id: "intel", label: useIntel ? "Querying threat feeds" : "Checking your blocklist" },
    ];
  }
  return [
    { id: "parse", label: "Parsing headers", local: true },
    { id: "auth", label: "Reading SPF, DKIM and DMARC results", local: true },
    { id: "content", label: "Reading the message for pressure tactics", local: true },
    { id: "links", label: "Scoring every link" },
    { id: "attachments", label: "Inspecting attachments", local: true },
    ...(deep ? [{ id: "sender", label: "Looking up the sender's domain" }] : []),
  ];
}
