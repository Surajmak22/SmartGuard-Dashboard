#!/usr/bin/env python
"""Standalone training script for SmartGuard AI.

Usage:
    python scripts/train_on_dataset.py --csv <path-to-csv> [--label-col Label] [--model random_forest]

Example with CIC-IDS2017:
    python scripts/train_on_dataset.py --csv datasets/cicids2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv --label-col Label
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Add repo root to sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import joblib
import numpy as np
import pandas as pd

from src.phase1.training import train_binary_classifier
from src.phase1.metrics import classification_metrics
from sklearn.metrics import confusion_matrix, classification_report


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train SmartGuard AI model on a CSV dataset")
    p.add_argument("--csv", required=True, help="Path to CSV dataset file")
    p.add_argument("--label-col", default="Label", help="Name of the label column (default: Label)")
    p.add_argument("--model", default="random_forest", choices=["random_forest", "svm"],
                   help="Model type (default: random_forest)")
    p.add_argument("--max-rows", type=int, default=50000,
                   help="Max rows to use for training (default: 50000, 0 = all)")
    p.add_argument("--test-size", type=float, default=0.2,
                   help="Test split size (default: 0.2)")
    p.add_argument("--no-smote", action="store_true",
                   help="Disable SMOTE resampling")
    p.add_argument("--save-model", default="models/smartguard_model.joblib",
                   help="Path to save trained model (default: models/smartguard_model.joblib)")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        print(f"ERROR: CSV file not found: {csv_path}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  SmartGuard AI - Model Training")
    print(f"{'='*60}")
    print(f"  Dataset:    {csv_path.name}")
    print(f"  Model:      {args.model}")
    print(f"  Label col:  {args.label_col}")
    print(f"  Test split: {args.test_size}")
    print(f"  SMOTE:      {'Yes' if not args.no_smote else 'No'}")
    print(f"{'='*60}\n")

    # ── Load CSV ──────────────────────────────
    print("[1/5] Loading dataset...")
    t0 = time.time()
    df = pd.read_csv(csv_path)

    # Clean common CSV issues (BOM, whitespace in headers)
    cleaned_cols = [str(c).replace("\ufeff", "").strip() for c in df.columns]
    if len(set(cleaned_cols)) == len(cleaned_cols):
        df.columns = cleaned_cols

    print(f"       Loaded {len(df):,} rows x {df.shape[1]} columns in {time.time()-t0:.1f}s")

    # Verify label column exists
    if args.label_col not in df.columns:
        print(f"\nERROR: Label column '{args.label_col}' not found.")
        print(f"Available columns: {list(df.columns)[:20]}")
        sys.exit(1)

    # Show label distribution
    label_counts = df[args.label_col].value_counts()
    print(f"\n[2/5] Label distribution:")
    for label, count in label_counts.items():
        print(f"       {label:<30s} {count:>8,}")

    # ── Subsample if needed ──────────────────
    if args.max_rows > 0 and len(df) > args.max_rows:
        print(f"\n[3/5] Subsampling to {args.max_rows:,} rows...")
        df = df.sample(n=args.max_rows, random_state=42)
    else:
        print(f"\n[3/5] Using all {len(df):,} rows")

    # ── Train ─────────────────────────────────
    print(f"\n[4/5] Training {args.model} model...")
    t0 = time.time()
    bundle, metrics, pred_df = train_binary_classifier(
        df,
        label_col=args.label_col,
        model_name=args.model,
        test_size=args.test_size,
        use_smote=not args.no_smote,
    )
    train_time = time.time() - t0
    print(f"       Training completed in {train_time:.1f}s")

    # ── Evaluate ──────────────────────────────
    print(f"\n[5/5] Evaluation Results:")
    print(f"{'─'*50}")
    print(f"  Accuracy:   {metrics['accuracy']:.4f}")
    print(f"  Precision:  {metrics['precision']:.4f}")
    print(f"  Recall:     {metrics['recall']:.4f}")
    print(f"  F1 Score:   {metrics['f1']:.4f}")
    roc_str = f"{metrics['roc_auc']:.4f}" if metrics['roc_auc'] is not None else "N/A"
    print(f"  ROC-AUC:    {roc_str}")
    print(f"{'─'*50}")

    # Confusion matrix
    y_true = pred_df["y_true"].astype(int).to_numpy()
    y_pred = pred_df["y_pred"].astype(int).to_numpy()
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]
    print(f"\n  Confusion Matrix:")
    print(f"                Pred BENIGN   Pred ATTACK")
    print(f"  True BENIGN   {tn:>10,}    {fp:>10,}")
    print(f"  True ATTACK   {fn:>10,}    {tp:>10,}")

    print(f"\n  Classification Report:")
    print(classification_report(y_true, y_pred, target_names=["BENIGN", "ATTACK"]))

    # ── Save model ────────────────────────────
    save_path = Path(args.save_model)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "bundle_model_name": bundle.model_name,
        "preprocessor": bundle.preprocessor,
        "model": bundle.model,
        "feature_names": bundle.feature_names,
        "metrics": metrics,
    }, save_path)
    print(f"\n  ✅ Model saved to: {save_path}")
    print(f"\n{'='*60}")
    print(f"  Training complete! You can now use the Streamlit dashboard")
    print(f"  or load the model with: joblib.load('{save_path}')")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
