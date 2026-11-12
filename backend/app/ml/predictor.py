"""Runtime inference for the URL classifier ensemble, with per-feature explanations."""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

import joblib
import numpy as np
import xgboost as xgb

from ..config import get_settings
from .features import FEATURE_NAMES, extract_features

log = logging.getLogger(__name__)

FEATURE_LABELS = {
    "url_length": "URL length",
    "host_length": "Hostname length",
    "path_length": "Path length",
    "query_length": "Query string length",
    "num_dots_host": "Dots in hostname",
    "num_hyphens_host": "Hyphens in hostname",
    "num_hyphens_url": "Hyphens in URL",
    "num_underscores": "Underscores",
    "num_slashes": "Path depth (slashes)",
    "num_query_params": "Query parameters",
    "num_at": "'@' characters",
    "num_percent": "Percent-encoding",
    "num_tilde": "'~' characters",
    "num_digits_url": "Digits in URL",
    "digit_ratio_host": "Digit ratio in hostname",
    "num_subdomain_levels": "Subdomain levels",
    "is_ip_host": "IP address as host",
    "has_port": "Non-standard port",
    "is_https": "Uses HTTPS",
    "has_punycode": "Punycode hostname",
    "tld_high_risk": "High-abuse TLD",
    "tld_medium_risk": "Elevated-abuse TLD",
    "tld_length": "TLD length",
    "is_shortener": "URL shortener",
    "is_free_hosting": "Free hosting platform",
    "is_popular_domain": "Well-known domain",
    "host_entropy": "Hostname randomness",
    "path_entropy": "Path randomness",
    "num_suspicious_keywords": "Phishing keywords",
    "brand_in_subdomain": "Brand in subdomain",
    "brand_in_path": "Brand in path",
    "brand_typosquat": "Brand typosquat",
    "brand_combosquat": "Brand + keyword domain",
    "brand_not_owned": "Brand on unowned domain",
    "https_token_in_host": "'https' inside hostname",
    "double_slash_in_path": "'//' inside path",
    "longest_host_token": "Longest hostname token",
    "longest_path_token": "Longest path token",
    "num_path_segments": "Path segments",
    "has_php_or_html": "Script/page file in path",
    "has_exe_ext": "Executable/archive download",
    "has_email_in_url": "Email address in URL",
    "has_hex_run": "Long hex string",
    "domain_label_length": "Domain label length",
    "domain_label_digits": "Digits in domain label",
    "vowel_ratio_domain": "Vowel ratio of domain",
}


class URLClassifier:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.rf = None
        self.xgb: xgb.XGBClassifier | None = None
        self.booster: xgb.Booster | None = None
        self.metadata: dict[str, Any] = {}

    @property
    def ready(self) -> bool:
        return self.rf is not None and self.xgb is not None

    def load(self, train_if_missing: bool = True) -> None:
        with self._lock:
            model_dir = get_settings().model_dir
            rf_path, xgb_path, meta_path = (
                model_dir / "random_forest.joblib",
                model_dir / "xgboost.json",
                model_dir / "metadata.json",
            )
            if not (rf_path.exists() and xgb_path.exists() and meta_path.exists()):
                if not train_if_missing:
                    return
                log.warning("No trained model found; training on the synthetic bootstrap corpus...")
                from .train import train_default

                train_default()
            metadata = json.loads(meta_path.read_text())
            if metadata.get("features") != FEATURE_NAMES:
                log.warning("Model features are out of date; retraining.")
                from .train import train_default

                train_default()
                metadata = json.loads(meta_path.read_text())
            self.rf = joblib.load(rf_path)
            model = xgb.XGBClassifier()
            model.load_model(xgb_path)
            self.xgb = model
            self.booster = model.get_booster()
            self.metadata = metadata

    def predict(self, url: str) -> dict[str, Any]:
        if not self.ready:
            self.load()
        feats = extract_features(url)
        X = np.array([[feats[n] for n in FEATURE_NAMES]], dtype=np.float32)
        p_rf = float(self.rf.predict_proba(X)[0, 1])
        p_xgb = float(self.xgb.predict_proba(X)[0, 1])
        weights = self.metadata.get("ensemble_weights", {"xgboost": 0.6, "random_forest": 0.4})
        p = weights["xgboost"] * p_xgb + weights["random_forest"] * p_rf

        # SHAP-style per-feature contributions (log-odds) from the XGBoost booster.
        contribs = self.booster.predict(xgb.DMatrix(X, feature_names=None), pred_contribs=True)[0]
        ranked = sorted(
            ((FEATURE_NAMES[i], float(contribs[i])) for i in range(len(FEATURE_NAMES))),
            key=lambda kv: abs(kv[1]),
            reverse=True,
        )
        explanations = [
            {
                "feature": name,
                "label": FEATURE_LABELS.get(name, name),
                "value": round(feats[name], 3),
                "contribution": round(c, 3),
                "direction": "phishing" if c > 0 else "legitimate",
            }
            for name, c in ranked[:6]
            if abs(c) >= 0.05
        ]
        return {
            "probability": round(p, 4),
            "label": "phishing" if p >= 0.5 else "legitimate",
            "models": {"xgboost": round(p_xgb, 4), "random_forest": round(p_rf, 4)},
            "explanations": explanations,
            "features": {k: round(v, 3) for k, v in feats.items()},
        }

    def info(self) -> dict[str, Any]:
        if not self.ready:
            self.load()
        info = {k: v for k, v in self.metadata.items() if k != "features"} | {"n_features": len(FEATURE_NAMES)}
        info["top_features"] = [f | {"label": FEATURE_LABELS.get(f["feature"], f["feature"])} for f in info.get("top_features", [])]
        return info


classifier = URLClassifier()
