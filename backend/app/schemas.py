"""Pydantic models shared by the analyzers and the API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
FindingKind = Literal["risk", "trust", "info"]
Verdict = Literal["safe", "suspicious", "malicious"]
ScanType = Literal["url", "domain", "email"]


class Finding(BaseModel):
    """A single explainable observation that contributed to (or reduced) the risk score."""

    id: str
    category: str
    kind: FindingKind = "risk"
    severity: Severity = "low"
    title: str
    detail: str = ""
    # Risk findings: probability-like contribution in [0, 1].
    # Trust findings: fraction by which the score is reduced, in [0, 1].
    weight: float = 0.0
    # Exact substrings (keywords, brand names, phrases) that triggered the finding, for highlighting.
    evidence: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    id: str
    scan_type: ScanType
    target: str
    verdict: Verdict
    risk_score: int
    summary: str
    findings: list[Finding]
    score_breakdown: dict[str, Any]
    details: dict[str, Any]
    created_at: str
    duration_ms: int


class ScanListItem(BaseModel):
    id: str
    scan_type: ScanType
    target: str
    verdict: Verdict
    risk_score: int
    summary: str
    created_at: str


class ScanList(BaseModel):
    items: list[ScanListItem]
    total: int


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    deep: bool = Field(True, description="Follow redirects, inspect the page and look up domain intelligence")
    use_intel: bool = Field(True, description="Query configured external threat-intelligence providers")


class DomainScanRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=512)
    use_intel: bool = True


class EmailScanRequest(BaseModel):
    raw: str | None = Field(None, max_length=5_000_000, description="Full RFC 822 message including headers")
    sender: str | None = Field(None, max_length=512)
    subject: str | None = Field(None, max_length=2048)
    body: str | None = Field(None, max_length=2_000_000)
    deep: bool = Field(True, description="Check sender-domain DNS (SPF/DMARC) and registration age")
    use_intel: bool = True


class ThreatRecordIn(BaseModel):
    indicator: str = Field(min_length=1, max_length=4096)
    indicator_type: Literal["url", "domain", "ip", "email"]
    threat_type: str = Field("phishing", max_length=64)
    description: str = Field("", max_length=2000)


class ThreatRecord(ThreatRecordIn):
    id: int
    source: str
    created_at: str


class ThreatList(BaseModel):
    items: list[ThreatRecord]
    total: int
