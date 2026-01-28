import re
from typing import Dict, List

class HeuristicScanner:
    """
    Layer 3: Heuristic analysis.
    Checks for embedded scripts, obfuscation, and structural anomalies.
    """
    SUSPICIOUS_PATTERNS = {
        "JavaScript / Scripting": [r"<script", r"javascript:", r"eval\(", r"setTimeout\(", r"document\.location"],
        "Shell / OS Access": [r"cmd\.exe", r"/bin/sh", r"/bin/bash", r"powershell", r"shell_exec", r"system\("],
        "Obfuscation Indicators": [r"base64", r"char\(", r"str_replace", r"\\u[0-9a-fA-F]{4}", r"0x[0-9a-fA-F]{2,}"],
        "Web Communication": [r"http://", r"https://", r"ftp://", r"socket\("]
    }

    def scan(self, file_data: bytes) -> Dict[str, any]:
        threats = []
        risk_score = 0
        
        # Convert to string for regex (careful with binary, we decoded with errors ignored)
        content_str = file_data.decode('utf-8', errors='ignore')
        
        for category, patterns in self.SUSPICIOUS_PATTERNS.items():
            category_matches = 0
            for pattern in patterns:
                if re.search(pattern, content_str, re.IGNORECASE):
                    category_matches += 1
            
            if category_matches > 0:
                threats.append(f"Heuristic Match: Found {category_matches} {category} signals")
                risk_score += (20 * category_matches)

        return {
            "threats": threats,
            "risk_score": min(risk_score, 100),
            "layer": "Heuristic"
        }
