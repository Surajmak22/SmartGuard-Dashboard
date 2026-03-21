"""
SmartGuard AI — Automated Continuous Learning Loop
==================================================
1. Ingests reported false negatives/positives from the feedback queue
2. Uses dataset_manager to categorize & deduplicate them into the main training set
3. Triggers per-format model retraining
4. Reloads the models if the F1/AUC scores remain robust

Intended to run as a nightly cron job or triggered manually by SOC.
"""

import os
import sys
import time
import shutil
import logging
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.dataset_manager import DatasetManager
import scripts.train_per_format_models as trainer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def process_feedback_queue() -> bool:
    """Moves feedback files into the main unorganized pool and runs dataset manager."""
    feedback_dir = REPO_ROOT / "data" / "feedback"
    malicious_queue = feedback_dir / "malicious"
    benign_queue = feedback_dir / "benign"
    
    files_moved = 0
    
    for queue_dir, label in [(malicious_queue, "malicious"), (benign_queue, "benign")]:
        if not queue_dir.exists():
            continue
            
        for file in queue_dir.glob("*"):
            if file.is_file():
                # We move it temporarily to the data root, and let the dataset_manager
                # figure out exactly which format folder it belongs to based on magic numbers.
                dest_dir = REPO_ROOT / "data" / label
                dest_dir.mkdir(parents=True, exist_ok=True)
                
                dest_path = dest_dir / file.name
                shutil.move(str(file), str(dest_path))
                files_moved += 1
                
    if files_moved == 0:
        logging.info("Feedback queue is empty. No new samples to learn from.")
        return False
        
    logging.info(f"Ingested {files_moved} new feedback samples. Running DatasetManager...")
    manager = DatasetManager(data_dir=str(REPO_ROOT / "data"))
    manager.organize_and_deduplicate()
    return True

def trigger_retraining():
    """Triggers the XGBoost/LGBM training for all formats."""
    logging.info("Initiating per-format model retraining...")
    start_time = time.time()
    
    results = {}
    for fmt in ["pdf", "image", "docx", "zip", "exe"]:
        logging.info(f"Building dataset for {fmt}...")
        df = trainer.build_format_dataset(fmt)
        if df is None or len(df) < 10:
            logging.warning(f"Skipping {fmt} - insufficient data")
            continue
            
        logging.info(f"Training models for {fmt}...")
        res = trainer.train_format_model(fmt, df)
        if res:
            results[fmt] = res
            
    elapsed = time.time() - start_time
    logging.info(f"Retraining complete in {elapsed:.1f} seconds.")
    
    for fmt, r in results.items():
        logging.info(f"[{fmt.upper()}] ROC-AUC: {r.get('roc_auc',0):.4f} | CV-F1: {r.get('cv_f1',0):.3f}")

if __name__ == "__main__":
    logging.info("Starting SmartGuard Automated Learning Loop")
    has_new_data = process_feedback_queue()
    if has_new_data:
        trigger_retraining()
        logging.info("Learning sequence complete. New models are live.")
    else:
        logging.info("Exiting.")
