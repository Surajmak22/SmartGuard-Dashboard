#!/usr/bin/env python
"""Download the CIC-IDS2017 dataset (MachineLearningCSV files).

This script downloads one of the CIC-IDS2017 CSV files for training.
The full dataset is ~2.2 GB; we download a single day's file for quick testing.

Usage:
    python scripts/download_dataset.py
"""
from __future__ import annotations

import os
import sys
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASETS_DIR = REPO_ROOT / "datasets" / "cicids2017"


def progress_hook(count, block_size, total_size):
    pct = count * block_size * 100.0 / total_size if total_size > 0 else 0
    mb = count * block_size / (1024 * 1024)
    total_mb = total_size / (1024 * 1024)
    sys.stdout.write(f"\r  Downloading: {mb:.1f} / {total_mb:.1f} MB ({pct:.0f}%)")
    sys.stdout.flush()


def main() -> None:
    DATASETS_DIR.mkdir(parents=True, exist_ok=True)

    # CIC-IDS2017 MachineLearningCSV.zip from UNB mirror
    # This contains all 8 CSV files for the CIC-IDS2017 dataset
    url = "https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/GeneratedCSVs/MachineLearningCVE.zip"
    zip_path = DATASETS_DIR / "MachineLearningCVE.zip"

    if zip_path.exists():
        print(f"  ZIP already downloaded: {zip_path}")
    else:
        print(f"  Downloading CIC-IDS2017 dataset from UNB...")
        print(f"  URL: {url}")
        print(f"  This may take several minutes (~600 MB compressed)...\n")
        try:
            urlretrieve(url, zip_path, progress_hook)
            print("\n  Download complete!")
        except Exception as e:
            print(f"\n\n  ERROR: Download failed: {e}")
            print(f"\n  Alternative: Download manually from:")
            print(f"    https://www.unb.ca/cic/datasets/ids-2017.html")
            print(f"  Or from Kaggle:")
            print(f"    https://www.kaggle.com/datasets/cicdataset/cicids2017")
            print(f"\n  Place CSV files in: {DATASETS_DIR}")
            sys.exit(1)

    # Extract
    csv_files = list(DATASETS_DIR.glob("*.csv"))
    if csv_files:
        print(f"\n  CSV files already extracted ({len(csv_files)} files found)")
    else:
        print(f"\n  Extracting ZIP file...")
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(DATASETS_DIR)
        
        # Move files from nested directories if needed
        for root, dirs, files in os.walk(DATASETS_DIR):
            for f in files:
                if f.endswith(".csv"):
                    src = Path(root) / f
                    dst = DATASETS_DIR / f
                    if src != dst and not dst.exists():
                        src.rename(dst)
        
        csv_files = list(DATASETS_DIR.glob("*.csv"))
        print(f"  Extracted {len(csv_files)} CSV files")

    print(f"\n  Available CSV files in {DATASETS_DIR}:")
    for f in sorted(csv_files):
        size_mb = f.stat().st_size / (1024 * 1024)
        print(f"    - {f.name} ({size_mb:.1f} MB)")

    print(f"\n  ✅ Dataset ready! Train with:")
    if csv_files:
        example = sorted(csv_files)[0].name
        print(f"     python scripts/train_on_dataset.py --csv datasets/cicids2017/{example} --label-col Label")


if __name__ == "__main__":
    main()
