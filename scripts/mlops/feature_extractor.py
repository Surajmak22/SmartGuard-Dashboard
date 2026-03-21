"""
SmartGuard AI — MLOps Parquet Feature Extractor
================================================
A highly parallelized feature extraction pipeline.
Reads raw binaries, extracts domain-specific features,
and writes highly optimized .parquet datasets for MLflow.
"""

import os
import sys
import logging
import pandas as pd
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

# Import the existing feature extractors we built in Phase 3
from scripts.train_per_format_models import (
    extract_pdf_features,
    extract_image_features,
    extract_docx_features,
    extract_zip_features,
    extract_exe_features
)
from src.scanner.ml_scanner import FeatureExtractor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

FORMAT_EXTRACTORS = {
    "pdf":   extract_pdf_features,
    "image": extract_image_features,
    "docx":  extract_docx_features,
    "zip":   extract_zip_features,
    "exe":   extract_exe_features,
}

def process_file_worker(filepath: Path, format_type: str, label_num: int):
    """Worker function to read data and extract numerical features."""
    try:
        data = filepath.read_bytes()
        extractor_func = FORMAT_EXTRACTORS.get(format_type, FeatureExtractor().extract)
        features = extractor_func(data)
        
        # Convert numpy array to list for dict serialization
        # Format is f0, f1, ..., fN, label, filepath
        row = {f"f{i}": float(v) for i, v in enumerate(features)}
        row["label"] = label_num
        row["filepath"] = str(filepath.name)
        return row
    except Exception as e:
        return None

class BatchFeatureExtractor:
    def __init__(self, data_dir: Path, output_dir: Path):
        self.data_dir = data_dir
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def extract_format_to_parquet(self, format_type: str):
        """Processes an entire format folder and drops a .parquet file."""
        format_dir = self.data_dir / format_type
        if not format_dir.exists():
            return
            
        logging.info(f"Extracting features for {format_type.upper()}...")
        
        tasks = []
        for label_name, label_num in [("benign", 0), ("malicious", 1)]:
            label_dir = format_dir / label_name
            if not label_dir.exists(): continue
            for file in label_dir.glob("*"):
                if file.is_file():
                    tasks.append((file, label_num))
                    
        if not tasks:
            logging.warning(f"No files found for {format_type}")
            return
            
        results = []
        with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
            futures = {executor.submit(process_file_worker, fpath, format_type, lnum): fpath for fpath, lnum in tasks}
            
            for future in tqdm(as_completed(futures), total=len(futures), desc=f"{format_type.upper()} Extraction"):
                res = future.result()
                if res:
                    results.append(res)
                    
        if results:
            df = pd.DataFrame(results)
            # Parquet requires string column names, which we already have
            out_file = self.output_dir / f"{format_type}_features.parquet"
            df.to_parquet(out_file, engine='pyarrow', index=False)
            logging.info(f"Saved {len(df)} samples to {out_file.name} ({out_file.stat().st_size / 1024:.1f} KB)")
        else:
            logging.warning(f"Extraction yielded no valid features for {format_type}")

if __name__ == "__main__":
    DATA_DIR = REPO_ROOT / "data"
    OUTPUT_DIR = REPO_ROOT / "data" / "features"
    
    extractor = BatchFeatureExtractor(DATA_DIR, OUTPUT_DIR)
    
    for fmt in ["pdf", "image", "docx", "zip", "exe"]:
        extractor.extract_format_to_parquet(fmt)
        
    logging.info("All feature datasets generated as Parquet files.")
