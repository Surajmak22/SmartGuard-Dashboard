"""
SmartGuard AI — MLOps Data Cleaner / Preprocessor
==================================================
Uses high-performance multiprocessing to rapidly organize,
validate, and deduplicate files in the dataset before feature extraction.
"""

import os
import hashlib
import shutil
import logging
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    
REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class DataCleaner:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.seen_hashes = set()
        
    @staticmethod
    def _compute_hash(filepath: Path) -> str:
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return ""

    @staticmethod
    def _determine_format(filepath: Path) -> str:
        """Determines format via magic bytes or extension."""
        ext = filepath.suffix.lower().lstrip('.')
        if ext in ['pdf', 'png', 'jpg', 'jpeg', 'docx', 'zip', 'exe', 'txt']:
            # Normalization
            if ext == 'jpg': ext = 'jpeg'
            return ext
            
        if MAGIC_AVAILABLE:
            try:
                m = magic.from_file(str(filepath), mime=True)
                if 'pdf' in m: return 'pdf'
                if 'image' in m: return 'image'
                if 'zip' in m: return 'zip'
                if 'x-dosexec' in m or 'x-executable' in m: return 'exe'
                if 'wordprocessingml' in m: return 'docx'
            except:
                pass
        return "other"

    @staticmethod
    def worker_process(file_path: Path):
        """Worker that processes a single file (used in ProcessPool)."""
        if not file_path.is_file():
            return None
            
        size = file_path.stat().st_size
        if size == 0:
            file_path.unlink()
            return {"action": "deleted_empty", "path": str(file_path)}
            
        file_hash = DataCleaner._compute_hash(file_path)
        fmt = DataCleaner._determine_format(file_path)
        
        return {
            "path": file_path,
            "hash": file_hash,
            "format": fmt,
            "size": size
        }

    def clean_and_deduplicate(self):
        """Runs the validation across all data directories using multiprocessing."""
        all_files = []
        for root, _, files in os.walk(self.data_dir):
            root_path = Path(root)
            if "features" in root_path.parts: continue # Skip the pre-extracted features dir
                
            for file in files:
                all_files.append(root_path / file)
                
        if not all_files:
            logging.info("No files found to clean.")
            return

        logging.info(f"Scanning {len(all_files)} files across {os.cpu_count()} cores...")
        
        results = []
        with ProcessPoolExecutor() as executor:
            futures = {executor.submit(self.worker_process, f): f for f in all_files}
            
            for future in tqdm(as_completed(futures), total=len(futures), desc="Validating"):
                try:
                    res = future.result()
                    if res and "hash" in res:
                        results.append(res)
                except Exception as e:
                    logging.error(f"Error processing a file: {e}")

        # Post-processing deduplication thread
        duplicates_removed = 0
        formats_moved = 0
        
        for res in results:
            fpath = res["path"]
            fhash = res["hash"]
            fmt = res["format"]
            
            if not fpath.exists(): continue
            
            # 1. Deduplication
            if fhash in self.seen_hashes:
                fpath.unlink()
                duplicates_removed += 1
                continue
            self.seen_hashes.add(fhash)
            
            # 2. Reorganization
            # Ensure it's in the correct format directory
            label = "benign"
            if "malicious" in fpath.parts or fpath.parent.name == "malicious":
                label = "malicious"
                
            expected_dir = self.data_dir / label / "manga" # Wait, format not manga
            expected_dir = self.data_dir / fmt / label
            
            if fpath.parent != expected_dir:
                expected_dir.mkdir(parents=True, exist_ok=True)
                new_path = expected_dir / f"{label}_{fhash[:12]}.{fmt}"
                shutil.move(str(fpath), str(new_path))
                formats_moved += 1

        logging.info("=" * 40)
        logging.info("Data Cleaner Results:")
        logging.info(f"Total Unique Files : {len(self.seen_hashes)}")
        logging.info(f"Duplicates Removed: {duplicates_removed}")
        logging.info(f"Files Reorganized : {formats_moved}")
        logging.info("=" * 40)

if __name__ == "__main__":
    cleaner = DataCleaner(DATA_DIR)
    cleaner.clean_and_deduplicate()
