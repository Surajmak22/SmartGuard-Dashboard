"""
Dataset Manager — SmartGuard AI (Phase 3)
===========================================
Organizes, deduplicates, and cleans datasets for continuous learning.
Ensures the directory structure is strictly maintained:
data/
  {format}/
      malicious/
      benign/
  feedback/
      malicious/    <- Auto-learning ingest folder
"""

import os
import sys
import shutil
import hashlib
from pathlib import Path

# Fix import path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.scanner.signature_scanner import SignatureScanner

class DatasetManager:
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.sig_scanner = SignatureScanner()
        self.supported_formats = ["pdf", "image", "docx", "exe", "zip", "other"]
        
    def setup_directories(self):
        """Creates the required directory structure."""
        print("[*] Setting up directory structure...")
        for fmt in self.supported_formats:
            (self.data_dir / fmt / "malicious").mkdir(parents=True, exist_ok=True)
            (self.data_dir / fmt / "benign").mkdir(parents=True, exist_ok=True)
            
        (self.data_dir / "feedback" / "malicious").mkdir(parents=True, exist_ok=True)
        (self.data_dir / "feedback" / "benign").mkdir(parents=True, exist_ok=True)
        print("[+] Directory structure verified.")
        
    def get_file_hash(self, filepath):
        """Calculates SHA-256 hash of a file."""
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None

    def organize_and_deduplicate(self):
        """
        Scans all files in data/, deduplicates them based on hash, 
        removes empty/corrupted files, and ensures they are in the correct format folder.
        """
        print("\n[*] Starting dataset organization and deduplication...")
        
        seen_hashes = {} # hash -> filepath
        stats = {
            "processed": 0,
            "moved": 0,
            "deleted_duplicate": 0,
            "deleted_corrupted": 0
        }
        
        # Traverse all files in data/
        for root, _, files in os.walk(self.data_dir):
            root_path = Path(root)
            for file in files:
                filepath = root_path / file
                stats["processed"] += 1
                
                # Skip 0-byte files
                if filepath.stat().st_size == 0:
                    filepath.unlink()
                    stats["deleted_corrupted"] += 1
                    continue
                    
                file_hash = self.get_file_hash(filepath)
                if not file_hash:
                    filepath.unlink()
                    stats["deleted_corrupted"] += 1
                    continue
                    
                # Deduplication check
                if file_hash in seen_hashes:
                    # It's a duplicate. Keep the original, delete this one.
                    filepath.unlink()
                    stats["deleted_duplicate"] += 1
                    continue
                    
                seen_hashes[file_hash] = filepath
                
                # Determine correct folder based on content (not just extension)
                try:
                    with open(filepath, 'rb') as f:
                        data = f.read(2048)
                    sig_result = self.sig_scanner.scan(data, file)
                    
                    # Map mime type to our folder structure
                    mime = sig_result.mime_type
                    target_fmt = "other"
                    
                    if "pdf" in mime: target_fmt = "pdf"
                    elif "image" in mime: target_fmt = "image"
                    elif "word" in mime or "officedocument" in mime: target_fmt = "docx"
                    elif file.endswith(".docx") or file.endswith(".doc"): target_fmt = "docx"
                    elif "executable" in mime or "x-dosexec" in mime: target_fmt = "exe"
                    elif "zip" in mime: target_fmt = "zip"
                    
                    # Check if it's already in the right place
                    # Expected structure: data/{fmt}/{label}/{file}
                    parts = filepath.parts
                    
                    # Only reorganize if it's currently in a malicious/benign folder
                    # Don't try to guess label if it's randomly in the root data folder
                    label = None
                    if "malicious" in parts: label = "malicious"
                    elif "benign" in parts: label = "benign"
                    
                    if label:
                        target_dir = self.data_dir / target_fmt / label
                        target_dir.mkdir(parents=True, exist_ok=True)
                        target_path = target_dir / file
                        
                        if filepath != target_path:
                            # If target already exists, just delete the source (duplicate name different hash edge case)
                            if target_path.exists():
                                target_path = target_dir / f"{file_hash[:8]}_{file}"
                            
                            shutil.move(str(filepath), str(target_path))
                            stats["moved"] += 1
                            seen_hashes[file_hash] = target_path # update pointer
                            
                except Exception as e:
                    print(f"[-] Error processing {filepath}: {e}")
                    
        print("\n=== Dataset Manager Results ===")
        print(f"Total processed:      {stats['processed']}")
        print(f"Moves to corr. fmt:   {stats['moved']}")
        print(f"Duplicates removed:   {stats['deleted_duplicate']}")
        print(f"Corrupted removed:    {stats['deleted_corrupted']}")
        print(f"Unique high-Q files:  {len(seen_hashes)}")
        print("===============================\n")

if __name__ == "__main__":
    manager = DatasetManager()
    manager.setup_directories()
    manager.organize_and_deduplicate()
