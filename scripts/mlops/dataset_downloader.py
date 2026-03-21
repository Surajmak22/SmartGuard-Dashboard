"""
SmartGuard AI — MLOps Dataset Downloader
==========================================
Automated dataset collection script. 
Fetches benign datasets and pre-extracted malware features (EMBER).

SECURITY NOTICE: 
To protect the host system, this script is intentionally restricted from downloading 
raw, weaponized malware binaries from live sources (e.g., MalShare, VirusShare).
It only downloads safe, benign files and vectorized JSONL/CSV feature sets.
"""

import os
import time
import logging
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"

# Example Safe Sources
SOURCES = {
    # EMBER provides vectorized PE features safely (no actual executables)
    "ember_2018_features": {
        "url": "https://ember.elastic.co/ember_dataset_2018_2.tar.bz2",
        "dest": DATA_DIR / "features" / "ember",
        "type": "archive"
    },
    # Tiny sample of benign PDFs for demonstration (W3C or similar public docs)
    "benign_pdfs": {
        "urls": [
            "https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf",
            "https://unec.edu.az/application/uploads/2014/12/pdf-sample.pdf"
        ],
        "dest": DATA_DIR / "benign" / "pdf",
        "type": "files"
    }
}

class DatasetDownloader:
    def __init__(self, max_retries=3, timeout=15):
        self.max_retries = max_retries
        self.timeout = timeout
        
    def download_file(self, url: str, dest_path: Path) -> bool:
        """Downloads a single file with retries and timeout."""
        if dest_path.exists() and dest_path.stat().st_size > 0:
            logging.info(f"Skipping {dest_path.name} (already exists).")
            return True
            
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        
        for attempt in range(self.max_retries):
            try:
                with requests.get(url, stream=True, timeout=self.timeout) as r:
                    r.raise_for_status()
                    total_size = int(r.headers.get('content-length', 0))
                    
                    with open(dest_path, 'wb') as f, tqdm(
                        desc=dest_path.name,
                        total=total_size,
                        unit='iB',
                        unit_scale=True,
                        unit_divisor=1024,
                        leave=False
                    ) as bar:
                        for chunk in r.iter_content(chunk_size=8192):
                            size = f.write(chunk)
                            bar.update(size)
                return True
                
            except requests.exceptions.RequestException as e:
                logging.warning(f"Attempt {attempt+1} failed for {url}: {e}")
                time.sleep(2 ** attempt)  # Exponential backoff
                
        logging.error(f"Failed to download {url} after {self.max_retries} attempts.")
        return False

    def fetch_all(self):
        """Orchestrates concurrent downloads."""
        logging.info("Starting safe dataset acquisition...")
        tasks = []
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            for name, config in SOURCES.items():
                if config["type"] == "archive":
                    dest_file = config["dest"] / Path(config["url"]).name
                    tasks.append(executor.submit(self.download_file, config["url"], dest_file))
                elif config["type"] == "files":
                    for i, url in enumerate(config["urls"]):
                        dest_file = config["dest"] / f"{name}_{i}.pdf"
                        tasks.append(executor.submit(self.download_file, url, dest_file))
                        
            for future in as_completed(tasks):
                future.result() # Wait for completion
                
        logging.info("Safe dataset acquisition complete.")
        
    def setup_malshare_stub(self):
        """
        Creates stub directories and READMEs for user-provided real malware.
        Prevents automated downloading of live malicious payloads.
        """
        malware_dirs = [
            DATA_DIR / "malicious" / "exe",
            DATA_DIR / "malicious" / "pdf",
            DATA_DIR / "malicious" / "docx",
            DATA_DIR / "malicious" / "image",
            DATA_DIR / "malicious" / "zip"
        ]
        
        readme_content = (
            "SAFETY NOTICE\n"
            "=============\n"
            "To prevent accidental infection, the automated MLOps pipeline does NOT download "
            "raw malware from MalShare or VirusShare automatically.\n\n"
            "If you have an API key and are operating in a strictly isolated sandbox environment, "
            "you may manually place your raw malicious payload files in this directory.\n"
            "The data_cleaner.py and feature_extractor.py scripts will automatically pick them up "
            "and ingest them safely into the .parquet feature datasets for MLflow training."
        )
        
        for d in malware_dirs:
            d.mkdir(parents=True, exist_ok=True)
            readme_path = d / "READ_ME_MALWARE_INGESTION.txt"
            if not readme_path.exists():
                readme_path.write_text(readme_content)
                
        logging.info("Created isolated ingestion folders for user-provided malware.")

if __name__ == "__main__":
    downloader = DatasetDownloader()
    downloader.setup_malshare_stub()
    # Note: downloader.fetch_all() is omitted from auto-run to avoid sitting 
    #       for 20 minutes downloading the 1.5GB EMBER tarball during testing.
    #       You can uncomment it or call it programmatically.
    logging.info("Downloader setup complete. Ready for manual or scheduled execution.")
