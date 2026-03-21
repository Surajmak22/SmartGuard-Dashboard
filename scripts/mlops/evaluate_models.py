"""
SmartGuard AI — MLOps Model Evaluator
=====================================
Stand-alone script that loads Parquet test sets and active models,
computes precision, recall, f1, and generates classification reports.
"""

import os
import sys
import logging
import joblib
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, recall_score, precision_score

REPO_ROOT = Path(__file__).resolve().parents[2]
FEATURES_DIR = REPO_ROOT / "data" / "features"
MODELS_DIR = REPO_ROOT / "models"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def evaluate(format_type: str):
    logging.info(f"--- Evaluating {format_type.upper()} Model ---")
    
    model_path = MODELS_DIR / f"{format_type}_classifier.joblib"
    parquet_path = FEATURES_DIR / f"{format_type}_features.parquet"
    
    if not model_path.exists():
        logging.warning(f"No active model for {format_type}. Skipping.")
        return
        
    if not parquet_path.exists():
        logging.warning(f"No parquet dataset found for {format_type}. Skipping.")
        return
        
    model = joblib.load(model_path)
    df = pd.read_parquet(parquet_path)
    
    X = df.drop(columns=["label", "filepath"])
    y = df["label"]
    
    # Use the same random seed for consistent test sets
    try:
        _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    except:
        _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
    preds = model.predict(X_test)
    
    logging.info(f"\nClassification Report for {format_type.upper()}:\n" + classification_report(y_test, preds, zero_division=0))
    logging.info(f"Accuracy : {accuracy_score(y_test, preds):.3f}")
    logging.info(f"Precision: {precision_score(y_test, preds, zero_division=0):.3f}")
    logging.info(f"Recall   : {recall_score(y_test, preds, zero_division=0):.3f}")
    print("-" * 50)

if __name__ == "__main__":
    for fmt in ["pdf", "image", "docx", "zip", "exe"]:
        evaluate(fmt)
    logging.info("Evaluation sweep complete.")
