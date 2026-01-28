from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd

# Allow running as: py scripts\cross_dataset_evaluation.py (adds repo root to sys.path)
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.phase1.preprocessing import build_preprocessor, prepare_xy
from src.phase1.models import build_model
from src.phase1.metrics import classification_metrics
from src.phase1.resampling import smote_resample


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Cross-dataset evaluation (train on UNSW-NB15, test on CICIDS2017)")
    p.add_argument("--unsw", required=True, help="Path to UNSW-NB15 CSV")
    p.add_argument("--cicids", required=True, help="Path to CICIDS2017 CSV")
    p.add_argument(
        "--label-col",
        default=None,
        help="Legacy: label column name used for BOTH datasets. Prefer --unsw-label-col and --cicids-label-col.",
    )
    p.add_argument("--unsw-label-col", default="label", help="UNSW-NB15 label column (default: label)")
    p.add_argument("--cicids-label-col", default="Label", help="CICIDS2017 label column (default: Label)")
    p.add_argument("--binary", action="store_true", default=True, help="Use binary labels BENIGN vs ATTACK")
    p.add_argument("--no-binary", dest="binary", action="store_false", help="Use multiclass labels")
    p.add_argument("--models", default="random_forest,svm", help="Comma-separated model names")
    p.add_argument("--results-path", default=str(Path("results") / "cross_dataset_metrics.csv"))
    return p.parse_args()


def main() -> None:
    args = parse_args()

    # Backward compatibility: if user provides --label-col, apply it to both datasets.
    if args.label_col:
        args.unsw_label_col = args.label_col
        args.cicids_label_col = args.label_col

    unsw_df = pd.read_csv(args.unsw)
    cicids_df = pd.read_csv(args.cicids)

    unsw = prepare_xy(unsw_df, label_col=args.unsw_label_col, binary=args.binary)
    cicids = prepare_xy(cicids_df, label_col=args.cicids_label_col, binary=args.binary)

    # Use intersection of columns for compatibility
    common_cols = sorted(set(unsw.feature_columns).intersection(set(cicids.feature_columns)))
    if not common_cols:
        raise ValueError("No overlapping feature columns between datasets. Ensure both CSVs have similar schemas.")

    X_train = unsw.X[common_cols]
    y_train = unsw.y
    X_test = cicids.X[common_cols]
    y_test = cicids.y

    # Convert to binary numeric labels for metrics/AUC (BENIGN=0, ATTACK=1)
    y_train_bin = (y_train != "BENIGN").astype(int).to_numpy()
    y_test_bin = (y_test != "BENIGN").astype(int).to_numpy()

    model_names = [m.strip() for m in args.models.split(",") if m.strip()]
    rows: List[Dict[str, object]] = []

    for model_name in model_names:
        preprocessor = build_preprocessor(X_train)
        model = build_model(model_name)

        # Fit preprocessor then apply SMOTE in transformed space (simple academic choice)
        X_train_t = preprocessor.fit_transform(X_train)
        X_train_bal, y_train_bal = smote_resample(X_train_t, y_train_bin, random_state=42)

        model.fit(X_train_bal, y_train_bal)

        X_test_t = preprocessor.transform(X_test)
        y_pred = model.predict(X_test_t)

        y_score = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(X_test_t)
            if proba.shape[1] >= 2:
                y_score = proba[:, 1]

        m = classification_metrics(y_test_bin, y_pred, y_score=y_score, average="binary")

        rows.append(
            {
                "model": model_name,
                "train_dataset": "UNSW-NB15",
                "test_dataset": "CICIDS2017",
                "n_train": int(X_train.shape[0]),
                "n_test": int(X_test.shape[0]),
                **m,
            }
        )

    out_path = Path(args.results_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(out_path, index=False)
    print(f"Saved cross-dataset metrics to: {out_path}")


if __name__ == "__main__":
    main()
