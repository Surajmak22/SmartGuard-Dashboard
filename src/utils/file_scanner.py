from __future__ import annotations

import hashlib
import math
import os
from dataclasses import dataclass
from typing import Dict, List, Optional


try:
    from PIL import Image
    import io
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

@dataclass
class ScanResult:
    filename: str
    file_type: str
    is_safe: bool
    risk_score: float  # 0 to 100
    entropy: float
    threats: List[str]
    file_hash: str
    details: Dict[str, any]


class FileScanner:
    """
    Heuristic-based file analysis engine for Multimedia files.
    """

    # Common "Magic Numbers" for multimedia files
    MAGIC_NUMBERS = {
        b"\xff\xd8": "JPEG Image",  # Standard JPEG start
        b"\x89PNG\r\n\x1a\n": "PNG Image",
        b"ID3": "MP3 Audio",
        b"\x00\x00\x00\x18ftyp": "MP4 Video",
        b"\x00\x00\x00\x20ftyp": "MP4 Video",
        b"fLaC": "FLAC Audio",
        b"RIFF": "WAV/AVI Container",
    }

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of the file data."""
        if not data:
            return 0.0
        
        counts = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
            
        entropy = 0.0
        for count in counts.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def analyze_file(self, filename: str, file_data: bytes) -> ScanResult:
        threats = []
        risk_score = 0
        
        # 1. Basic Metadata
        file_hash = hashlib.sha256(file_data).hexdigest()
        entropy = self.calculate_entropy(file_data)
        
        # 2. Signature Validation (Magic Numbers)
        detected_type = "Unknown / Binary"
        matched_sig = False
        for sig, label in self.MAGIC_NUMBERS.items():
            if file_data.startswith(sig):
                detected_type = label
                matched_sig = True
                break
        
        # 3. Deep Content Validation (The "Training" Improvement)
        valid_media = False
        if HAS_PILLOW and ("Image" in detected_type or filename.lower().endswith(('.jpg', '.jpeg', '.png'))):
            try:
                img = Image.open(io.BytesIO(file_data))
                img.verify()  # Verify image integrity
                valid_media = True
            except Exception:
                valid_media = False

        # 4. Heuristic Scoring Logic
        if not matched_sig:
            threats.append("Unexpected File Signature (Potential Obfuscation)")
            risk_score += 30

        # Entropy Analysis
        # Compressed multimedia is naturally high entropy. 
        # Only flag it as "packed" if it's NOT a valid media file.
        if entropy > 7.98 and not valid_media:
            threats.append("Extremely High Entropy (Potential Malicious Payload)")
            risk_score += 45
        elif entropy < 0.3:
            threats.append("Suspiciously Low Entropy (Potential Shellcode)")
            risk_score += 25

        # Heuristic: Extension vs Content
        _, ext = os.path.splitext(filename.lower())
        is_media_ext = ext in [".jpg", ".jpeg", ".png", ".mp3", ".wav", ".mp4", ".flac"]
        
        if is_media_ext and not matched_sig and not valid_media:
            threats.append(f"Content-Extension Mismatch (File type signature not found)")
            risk_score += 50
        
        # FINAL SAFETY OVERRIDE: 
        # If the file successfully decoded as a media object (Image/Audio/etc), 
        # we treat it as safe unless there are extreme risks.
        if valid_media:
            risk_score = 10  # Low baseline risk for valid media
            threats = [t for t in threats if "Extremely High Entropy" not in t] # Remove entropy warning for valid images
            
        # Final decision: threshold is 40
        is_safe = risk_score < 40
        
        return ScanResult(
            filename=filename,
            file_type=detected_type,
            is_safe=is_safe,
            risk_score=min(risk_score, 100),
            entropy=round(entropy, 4),
            threats=threats,
            file_hash=file_hash,
            details={
                "size_bytes": len(file_data),
                "extension": ext,
                "deep_validated": valid_media
            }
        )
