"""
SmartGuard AI — MLOps Model Trainer
===================================
Orchestrates ensemble training for all formats.
Consumes fast .parquet datasets.
Tracks metrics, hyperparameters, and artifacts securely via MLflow.
Optimizes rigorously for Recall.
"""

import os
import sys
import logging
import joblib
from pathlib import Path

import pandas as pd
import numpy as np
import mlflow
import mlflow.sklearn
import mlflow.xgboost

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

REPO_ROOT = Path(__file__).resolve().parents[2]
FEATURES_DIR = REPO_ROOT / "data" / "features"
MODELS_DIR = REPO_ROOT / "models"
MLRUNS_DIR = REPO_ROOT / "mlruns"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Set up MLflow tracking
mlflow.set_tracking_uri(f"file:///{MLRUNS_DIR.resolve().as_posix()}")

def train_format(format_type: str, weight_malicious=1.0) -> dict:
    """Trains XGBoost and RandomForest models for a specific format, logging to MLflow."""
    parquet_path = FEATURES_DIR / f"{format_type}_features.parquet"
    if not parquet_path.exists():
        logging.warning(f"No parquet dataset found for {format_type}. Skipping.")
        return None
        
    df = pd.read_parquet(parquet_path)
    if "label" not in df.columns or len(df) < 20:
        logging.warning(f"Insufficient data in {format_type}_features.parquet.")
        return None
        
    X = df.drop(columns=["label", "filepath"])
    y = df["label"]
    
    # Stratified Split
    try:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    except ValueError:
        # Fallback if only 1 class is present
        logging.warning(f"[{format_type}] Only 1 class present. Cannot stratify.")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    if len(np.unique(y_train)) < 2:
        logging.warning(f"[{format_type}] Training data must contain both classes. Skipping.")
        return None

    # Calculate class weights for imbalance
    counts = np.bincount(y_train)
    spw = (counts[0] / max(counts[1], 1)) * weight_malicious

    mlflow.set_experiment(f"SmartGuard_{format_type.upper()}")
    
    with mlflow.start_run(run_name=f"{format_type}_xgboost_rf_ensemble"):
        mlflow.log_param("format", format_type)
        mlflow.log_param("training_samples", len(X_train))
        mlflow.log_param("malicious_weight_multiplier", weight_malicious)
        
        # 1. XGBoost Training
        logging.info(f"[{format_type}] Training XGBoost...")
        xgb_clf = XGBClassifier(
            n_estimators=150,
            max_depth=5,
            learning_rate=0.1,
            scale_pos_weight=spw,
            random_state=42,
            eval_metric="logloss"
        )
        xgb_clf.fit(X_train, y_train)
        y_pred_xgb = xgb_clf.predict(X_test)
        
        # 2. RandomForest Training (Fallback/Ensemble checks)
        logging.info(f"[{format_type}] Training Random Forest...")
        rf_clf = RandomForestClassifier(
            n_estimators=100, 
            max_depth=8, 
            class_weight={0: 1.0, 1: weight_malicious},
            random_state=42
        )
        rf_clf.fit(X_train, y_train)
        y_pred_rf = rf_clf.predict(X_test)
        
        # 3. Evaluate & Select Best (Prioritize Recall)
        xgb_recall = recall_score(y_test, y_pred_xgb, zero_division=0)
        rf_recall = recall_score(y_test, y_pred_rf, zero_division=0)
        
        xgb_f1 = f1_score(y_test, y_pred_xgb, zero_division=0)
        rf_f1 = f1_score(y_test, y_pred_rf, zero_division=0)
        
        # We heavily prioritize Recall. Tie-break with F1.
        best_model_name = "XGBoost"
        best_model = xgb_clf
        best_preds = y_pred_xgb
        
        if (rf_recall > xgb_recall) or (rf_recall == xgb_recall and rf_f1 > xgb_f1):
            best_model_name = "RandomForest"
            best_model = rf_clf
            best_preds = y_pred_rf
            
        mlflow.log_param("selected_model", best_model_name)
        
        # Log Best Metrics
        metrics = {
            "accuracy": accuracy_score(y_test, best_preds),
            "precision": precision_score(y_test, best_preds, zero_division=0),
            "recall": recall_score(y_test, best_preds, zero_division=0),
            "f1_score": f1_score(y_test, best_preds, zero_division=0),
        }
        
        try:
            y_proba = best_model.predict_proba(X_test)[:, 1]
            metrics["roc_auc"] = roc_auc_score(y_test, y_proba)
        except:
            pass
            
        mlflow.log_metrics(metrics)
        
        # Exporting Best Model to production directory
        out_path = MODELS_DIR / f"{format_type}_classifier.joblib"
        joblib.dump(best_model, out_path)
        logging.info(f"[{format_type}] Saved {best_model_name} to {out_path.name} | Recall: {metrics['recall']:.3f} | F1: {metrics['f1_score']:.3f}")
        
        return metrics

if __name__ == "__main__":
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    MLRUNS_DIR.mkdir(parents=True, exist_ok=True)
    
    results = {}
    for fmt in ["pdf", "image", "docx", "zip", "exe"]:
        metrics = train_format(fmt)
        if metrics:
            results[fmt] = metrics
            
    logging.info("====================================")
    logging.info("MLOps Training Run Complete.")
    for fmt, mets in results.items():
        logging.info(f"{fmt.upper():<6} | Recall: {mets['recall']:.3f} | F1: {mets['f1_score']:.3f} | AUC: {mets.get('roc_auc',0):.3f}")
    logging.info("====================================")
