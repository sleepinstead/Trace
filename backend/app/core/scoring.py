"""Combine findings, ML probability and threat-intel hits into a 0-100 risk score and verdict.

Model (kept deliberately simple so every number on screen can be explained):

* rule score  = noisy-OR of risk-finding weights:  1 - prod(1 - w_i)
* blended     = rule_weight * rule score + ml_weight * ML probability   (ML optional)
* trust       = prod(1 - t_j * (1 - rule score)) over trust findings (popular domain, aged
                registration, ...); trust is discounted when the rule evidence is strong
* adjusted    = blended * trust
* intel floor = a confirmed malicious hit from a threat feed forces the score to >= 90
"""

from __future__ import annotations

from typing import Any

from ..schemas import Finding

SAFE_MAX = 35  # score < 35  -> safe
SUSPICIOUS_MAX = 65  # 35 <= score < 65 -> suspicious, >= 65 -> malicious
INTEL_FLOOR = 0.9
INTEL_SUSPICIOUS_FLOOR = 0.5


def noisy_or(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1.0 - max(0.0, min(w, 0.99))
    return 1.0 - p


def verdict_for(score: int) -> str:
    if score >= SUSPICIOUS_MAX:
        return "malicious"
    if score >= SAFE_MAX:
        return "suspicious"
    return "safe"


def combine(
    findings: list[Finding],
    *,
    ml_probability: float | None = None,
    ml_weight: float = 0.45,
    intel_malicious: int = 0,
    intel_suspicious: int = 0,
    extra_risk: list[float] | None = None,
) -> dict[str, Any]:
    risk_w = [f.weight for f in findings if f.kind == "risk" and f.weight > 0]
    risk_w += extra_risk or []
    trust_w = [f.weight for f in findings if f.kind == "trust" and f.weight > 0]

    rule_score = noisy_or(risk_w)
    if ml_probability is None:
        blended = rule_score
        ml_weight = 0.0
    else:
        blended = (1 - ml_weight) * rule_score + ml_weight * ml_probability
        # Strong agreement should not be diluted by averaging.
        blended = max(blended, min(rule_score, ml_probability))

    # Trust counts for less when the rule evidence against is strong: an aged domain or a valid
    # certificate should not cancel out brand impersonation on that same domain.
    trust = 1.0
    for t in trust_w:
        trust *= 1.0 - max(0.0, min(t, 0.95)) * (1.0 - rule_score)
    adjusted = blended * trust

    floor = 0.0
    if intel_malicious:
        floor = INTEL_FLOOR
    elif intel_suspicious:
        floor = INTEL_SUSPICIOUS_FLOOR
    final = max(adjusted, floor)

    score = int(round(final * 100))
    return {
        "risk_score": score,
        "verdict": verdict_for(score),
        "breakdown": {
            "rule_score": round(rule_score, 4),
            "ml_probability": None if ml_probability is None else round(ml_probability, 4),
            "ml_weight": ml_weight,
            "blended": round(blended, 4),
            "trust_multiplier": round(trust, 4),
            "intel_floor": floor,
            "final": round(final, 4),
            "thresholds": {"suspicious": SAFE_MAX, "malicious": SUSPICIOUS_MAX},
        },
    }


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    kind_order = {"risk": 0, "trust": 1, "info": 2}
    return sorted(findings, key=lambda f: (kind_order[f.kind], SEVERITY_ORDER[f.severity], -f.weight))


def _lower_first(text: str) -> str:
    # Keep acronyms and brand names intact ("ML model", "PayPal", "DMARC").
    word = text.split(" ", 1)[0]
    if len(word) > 1 and (word.isupper() or any(c.isupper() for c in word[1:])):
        return text
    return text[:1].lower() + text[1:]


def summarize(verdict: str, findings: list[Finding], subject: str) -> str:
    risks = [f for f in sort_findings(findings) if f.kind == "risk"]
    if verdict == "safe":
        if risks:
            return f"{subject} looks safe; {len(risks)} minor signal{'s' if len(risks) != 1 else ''} noted."
        return f"{subject} looks safe; no phishing indicators found."
    top = ", ".join(_lower_first(f.title) for f in risks[:3])
    label = "likely phishing" if verdict == "malicious" else "suspicious"
    return f"{subject} is {label}: {top}." if top else f"{subject} is {label}."
