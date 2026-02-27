import hashlib
import os
from typing import Dict, List, Tuple

class SignatureScanner:
    """
    Layer 1: Signature-based scan.
    Handles hashing, extension validation, and known threat lookups.
    """
    # Mock database of "known malware" hashes for demonstration
    KNOWN_THREATS = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test Malware Sample A",
        "44d88612fea8a8f36de82e1278abb02f": "Old Virus Hash (MD5 Mock)",
        "0000000000000000000000000000000000000000000000000000000000000000": "Null Payload"
    }

    # Common Magic Numbers
    MAGIC_MAP = {
        b"\xff\xd8": "image/jpeg",
        b"\x89PNG\r\n\x1a\n": "image/png",
        b"ID3": "audio/mpeg",
        b"\x00\x00\x00\x18ftyp": "video/mp4",
        b"%PDF": "application/pdf",
        b"PK\x03\x04": "application/zip/docx",
        b"MZ": "application/x-msdos-program (EXE)"
    }

    def scan(self, file_data: bytes, filename: str) -> Dict[str, any]:
        threats = []
        risk_score = 0
        
        # 1. Hashing
        sha256 = hashlib.sha256(file_data).hexdigest()
        
        # 1.5 EICAR Standard Test String Check
        eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        if eicar_string in file_data:
            threats.append("EICAR Standard Anti-Malware Test File Detected (Safe for testing)")
            risk_score += 100
        
        # 2. Known Hash Lookup
        if sha256 in self.KNOWN_THREATS:
            threats.append(f"Known Malware Signature Match: {self.KNOWN_THREATS[sha256]}")
            risk_score += 100 # Immediate Critical
        
        # 3. Extension vs Content Validation
        _, ext = os.path.splitext(filename.lower())
        detected_mime = "unknown"
        for sig, mime in self.MAGIC_MAP.items():
            if file_data.startswith(sig):
                detected_mime = mime
                break
        
        # Check suspicious extensions
        suspicious_exts = [".exe", ".bat", ".sh", ".py", ".js", ".vbs"]
        if ext in suspicious_exts:
            threats.append(f"Suspicious file extension detected: {ext}")
            risk_score += 30

        # Mismatch check
        if detected_mime == "application/x-msdos-program (EXE)" and ext not in [".exe", ".scr", ".com"]:
            threats.append("Executable content hidden in non-executable extension (Stealth Technique)")
            risk_score += 60

        return {
            "sha256": sha256,
            "detected_mime": detected_mime,
            "threats": threats,
            "risk_score": min(risk_score, 100),
            "layer": "Signature"
        }
