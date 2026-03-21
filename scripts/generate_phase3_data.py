"""
Phase 3 Dataset Generator — SmartGuard AI
===========================================
Generates synthetic benign/malicious ZIP and EXE files for training Phase 3 models.
"""

import os
import struct
import zipfile
import io
from pathlib import Path
import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]

# ─── Synthetic Generator ─────────────────────────────────────────────────────

def generate_samples(fmt: str, is_malicious: bool, count: int):
    out_dir = REPO_ROOT / "data" / ("malicious" if is_malicious else "benign") / fmt
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(42)
    
    for i in range(count):
        filepath = out_dir / f"{'malicious' if is_malicious else 'benign'}_{fmt}_{i:04d}.{fmt}"
        
        if fmt == "zip":
            # Generate synthetic ZIP
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                if is_malicious:
                    # Malicious traits: deep nesting, scripts, executables, path traversal
                    zf.writestr(f"payload_{i}.exe", b"MZ" + bytes(rng.integers(0, 256, 1024, dtype=np.uint8)))
                    zf.writestr(f"script_{i}.vbs", b"CreateObject(\"WScript.Shell\").Run \"cmd.exe /c calc.exe\"")
                    if i % 5 == 0:
                        zf.writestr(f"../../../etc/passwd", b"root:x:0:0:")
                else:
                    # Benign traits: text files, images, code
                    zf.writestr(f"document_{i}.txt", b"Hello World " * 50)
                    zf.writestr(f"image_{i}.png", b"\x89PNG\r\n\x1a\n" + bytes(rng.integers(0, 256, 100, dtype=np.uint8)))
            
            filepath.write_bytes(buf.getvalue())
            
        elif fmt == "exe":
            # Generate synthetic EXE (PE Header simulation)
            # PE format starts with MZ, followed by a DOS stub, then PE\0\0
            dos_stub = b"MZ" + bytes(rng.integers(0, 256, 58, dtype=np.uint8)) + struct.pack("<I", 64)
            pe_header = b"PE\0\0"
            
            if is_malicious:
                # Malicious logic: High entropy sections, suspicious names (.upx), low printable
                sections = b".text\0\0\0" + bytes(rng.integers(0, 256, 4000, dtype=np.uint8))
                sections += b".upx\0\0\0\0" + bytes(rng.integers(0, 256, 2000, dtype=np.uint8))
                payload = dos_stub + pe_header + sections
            else:
                # Benign logic: normal sections (.text, .rdata, .data), normal entropy
                sections = b".text\0\0\0" + bytes(rng.integers(32, 127, 2000, dtype=np.uint8))  # Ascii-ish code
                sections += b".rdata\0\0" + b"ImportTable..." * 50
                payload = dos_stub + pe_header + sections
                
            filepath.write_bytes(payload)

if __name__ == "__main__":
    print("[*] Generating Phase 3 synthetic data...")
    generate_samples("zip", is_malicious=True, count=250)
    generate_samples("zip", is_malicious=False, count=250)
    generate_samples("exe", is_malicious=True, count=250)
    generate_samples("exe", is_malicious=False, count=250)
    print("[+] Complete. Generated 1000 samples across ZIP and EXE formats.")
