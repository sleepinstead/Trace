"""Train the URL classifiers (scikit-learn Random Forest + XGBoost) and save the artifacts.

Usage:
    python -m app.ml.train                      # synthetic bootstrap corpus
    python -m app.ml.train --csv urls.csv       # your own data: columns url,label (1 = phishing)
    python -m app.ml.train --csv urls.csv --mix # your data plus the synthetic corpus
"""

from __future__ import annotations

import argparse
import csv
import json
import time
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from ..config import get_settings
from . import dataset
from .features import FEATURE_NAMES, feature_vector

ENSEMBLE_WEIGHTS = {"xgboost": 0.6, "random_forest": 0.4}

_LABEL_MAP = {"1": 1, "0": 0, "phishing": 1, "malicious": 1, "bad": 1, "phish": 1, "benign": 0, "legitimate": 0, "good": 0, "safe": 0}


def load_csv(path: Path) -> tuple[list[str], list[int]]:
    urls, labels = [], []
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        fields = {f.lower(): f for f in reader.fieldnames or []}
        url_col = fields.get("url")
        label_col = fields.get("label") or fields.get("type") or fields.get("status")
        if not url_col or not label_col:
            raise SystemExit(f"{path}: expected 'url' and 'label' columns, got {reader.fieldnames}")
        for row in reader:
            label = _LABEL_MAP.get(str(row[label_col]).strip().lower())
            if label is None or not row[url_col]:
                continue
            urls.append(row[url_col].strip())
            labels.append(label)
    return urls, labels


def _metrics(y_true, prob) -> dict[str, float]:
    pred = (prob >= 0.5).astype(int)
    return {
        "accuracy": round(float(accuracy_score(y_true, pred)), 4),
        "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, prob)), 4),
    }


def train(urls: list[str], labels: list[int], source: str, out_dir: Path | None = None, quiet: bool = False) -> dict:
    out_dir = out_dir or get_settings().model_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()

    X = np.array([feature_vector(u) for u in urls], dtype=np.float32)
    y = np.array(labels, dtype=np.int32)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    rf = RandomForestClassifier(n_estimators=250, max_depth=None, min_samples_leaf=2, n_jobs=-1, random_state=42, class_weight="balanced")
    rf.fit(X_train, y_train)

    xgb = XGBClassifier(
        n_estimators=350, max_depth=6, learning_rate=0.08, subsample=0.9, colsample_bytree=0.8,
        eval_metric="logloss", n_jobs=-1, random_state=42,
    )
    xgb.fit(X_train, y_train)

    p_rf = rf.predict_proba(X_test)[:, 1]
    p_xgb = xgb.predict_proba(X_test)[:, 1]
    p_ens = ENSEMBLE_WEIGHTS["xgboost"] * p_xgb + ENSEMBLE_WEIGHTS["random_forest"] * p_rf

    importances = sorted(
        zip(FEATURE_NAMES, xgb.feature_importances_.tolist(), strict=True), key=lambda kv: kv[1], reverse=True
    )
    metadata = {
        "trained_at": datetime.now(UTC).isoformat(),
        "dataset": source,
        "n_samples": int(len(y)),
        "n_phishing": int(y.sum()),
        "n_legitimate": int(len(y) - y.sum()),
        "test_size": int(len(y_test)),
        "features": FEATURE_NAMES,
        "ensemble_weights": ENSEMBLE_WEIGHTS,
        "metrics": {
            "random_forest": _metrics(y_test, p_rf),
            "xgboost": _metrics(y_test, p_xgb),
            "ensemble": _metrics(y_test, p_ens),
        },
        "top_features": [{"feature": k, "importance": round(v, 4)} for k, v in importances[:15]],
        "training_seconds": round(time.perf_counter() - started, 2),
    }

    joblib.dump(rf, out_dir / "random_forest.joblib")
    xgb.save_model(out_dir / "xgboost.json")
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
    if not quiet:
        print(json.dumps({k: metadata[k] for k in ("dataset", "n_samples", "metrics", "training_seconds")}, indent=2))
    return metadata


def train_default(quiet: bool = True) -> dict:
    urls, labels = dataset.generate()
    return train(urls, labels, source="synthetic bootstrap corpus (app/ml/dataset.py)", quiet=quiet)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", type=Path, help="CSV with url,label columns (label 1/phishing, 0/benign)")
    parser.add_argument("--mix", action="store_true", help="Also include the synthetic corpus")
    parser.add_argument("--per-class", type=int, default=12_000, help="Synthetic samples per class")
    args = parser.parse_args()

    if args.csv:
        urls, labels = load_csv(args.csv)
        source = f"csv:{args.csv.name}"
        if args.mix:
            su, sl = dataset.generate(args.per_class)
            urls, labels, source = urls + su, labels + sl, source + " + synthetic"
    else:
        urls, labels = dataset.generate(args.per_class)
        source = "synthetic bootstrap corpus (app/ml/dataset.py)"
    print(f"Training on {len(urls)} URLs ({sum(labels)} phishing) from {source}")
    train(urls, labels, source)


if __name__ == "__main__":
    main()
