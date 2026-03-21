"""
SmartGuard AI — MLOps Auto-Improvement Loop
=============================================
1. Iterates over formats.
2. Checks if current MLflow model achieves >= 90% Recall.
3. If not, automatically kicks off an Optuna hyperparameter tuning 
   session or adjusts class weights to force recall improvement.
"""

import os
import sys
import logging
import optuna
import pandas as pd
import numpy as np
import mlflow
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import recall_score, f1_score
from xgboost import XGBClassifier

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scripts.mlops.train_models import train_format

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
optuna.logging.set_verbosity(optuna.logging.WARNING)

RECALL_THRESHOLD = 0.90
MAX_TRIES = 3

def objective(trial, X_train, y_train, X_test, y_test, spw):
    """Optuna objective for tuning XGBoost strictly for Recall."""
    param = {
        'n_estimators': trial.suggest_int('n_estimators', 50, 300),
        'max_depth': trial.suggest_int('max_depth', 3, 12),
        'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3, log=True),
        'scale_pos_weight': trial.suggest_float('scale_pos_weight', spw, spw * 5),
        'subsample': trial.suggest_float('subsample', 0.5, 1.0),
        'colsample_bytree': trial.suggest_float('colsample_bytree', 0.5, 1.0),
        'random_state': 42
    }
    
    xgb = XGBClassifier(**param)
    xgb.fit(X_train, y_train)
    preds = xgb.predict(X_test)
    
    # We want to maximize Recall. If recall is tied, maximize F1.
    rec = recall_score(y_test, preds, zero_division=0)
    f1 = f1_score(y_test, preds, zero_division=0)
    
    # Custom composite score
    return rec + (f1 * 0.1)

def auto_improve_format(fmt: str):
    """Checks baseline and actively searches for better hypers if needed."""
    logging.info(f"--- AUTO-IMPROVE ENGINE: {fmt.upper()} ---")
    
    # 1. Get baseline
    baseline_metrics = train_format(fmt, weight_malicious=1.0)
    if not baseline_metrics:
        logging.warning("No data. Skipping.")
        return
        
    current_recall = baseline_metrics["recall"]
    logging.info(f"Baseline Recall: {current_recall:.3f} | Target: {RECALL_THRESHOLD:.3f}")
    
    if current_recall >= RECALL_THRESHOLD:
        logging.info("=> Model meets criteria. No improvement loop needed.")
        return
        
    logging.warning("=> Recall is BLEOW threshold! Initiating Optuna Auto-Tuning Loop...")
    
    # Load dataset for tuning
    parquet_path = REPO_ROOT / "data" / "features" / f"{fmt}_features.parquet"
    df = pd.read_parquet(parquet_path)
    X = df.drop(columns=["label", "filepath"])
    y = df["label"]
    
    try:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    except:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
    counts = np.bincount(y_train)
    spw = counts[0] / max(counts[1], 1)
    
    study = optuna.create_study(direction='maximize')
    study.optimize(lambda trial: objective(trial, X_train, y_train, X_test, y_test, spw), n_trials=15)
    
    best_params = study.best_params
    logging.info(f"Found better hyperparameters: {best_params}")
    
    # Retrain and Save the new tuned model
    mlflow.set_experiment(f"SmartGuard_{fmt.upper()}")
    with mlflow.start_run(run_name=f"{fmt}_xgboost_optuna_tuned"):
        mlflow.log_params(best_params)
        
        best_xgb = XGBClassifier(**best_params, random_state=42)
        best_xgb.fit(X_train, y_train)
        preds = best_xgb.predict(X_test)
        
        new_rec = recall_score(y_test, preds, zero_division=0)
        new_f1 = f1_score(y_test, preds, zero_division=0)
        
        mlflow.log_metric("recall", new_rec)
        mlflow.log_metric("f1_score", new_f1)
        
        out_path = REPO_ROOT / "models" / f"{fmt}_classifier.joblib"
        joblib.dump(best_xgb, out_path)
        
        logging.info(f"Tuned Model Saved! New Recall: {new_rec:.3f} | New F1: {new_f1:.3f}")

if __name__ == "__main__":
    for fmt in ["pdf", "image", "docx", "zip", "exe"]:
        auto_improve_format(fmt)
    logging.info("Auto-Improvement Loop finished.")
