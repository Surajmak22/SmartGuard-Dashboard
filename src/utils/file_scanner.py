"""
Upgraded FileScanner utility — SmartGuard AI
=============================================
Routes to the proper engine instead of the old heuristic-only approach.
Fixes the critical bug: valid images were being set to risk=10 regardless of content.
"""
from __future__ import annotations

import hashlib
import math
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ScanResult:
    filename: str
    file_type: str
    is_safe: bool
    risk_score: float        # 0 to 100
    entropy: float
    threats: List[str]
    file_hash: str
    details: Dict


class FileScanner:
    """
    Heuristic-based file analysis engine — now delegates to MalwareEngine
    for proper multi-layer analysis instead of doing entropy-only checks.

    The original "valid image → risk=10" override has been REMOVED.
    A malicious JPEG that passes PIL.verify() is STILL malicious.
    """

    def calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts: Dict[int, int] = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def analyze_file(self, filename: str, file_data: bytes) -> ScanResult:
        """
        Full multi-layer analysis via MalwareEngine.
        Falls back to basic heuristics if engine fails to import.
        """
        try:
            from src.scanner.engine import MalwareEngine
            engine = MalwareEngine()
            result = engine.scan_file(file_data, filename)

            return ScanResult(
                filename=filename,
                file_type=result["metadata"].get("format", "Unknown"),
                is_safe=not result["is_malicious"] and result["risk_score"] < 40,
                risk_score=result["risk_score"],
                entropy=result["metadata"].get("entropy", 0.0),
                threats=result.get("threats", []),
                file_hash=result["sha256"],
                details={
                    "size_bytes":    result["file_size_kb"] * 1024,
                    "extension":     os.path.splitext(filename.lower())[1],
                    "classification": result["detection"],
                    "severity":       result["severity"],
                    "layer_scores":   result.get("layer_results", {}),
                    "sanitizable":    result["metadata"].get("sanitizable", False),
                },
            )
        except Exception as e:
            # Fallback: basic entropy + hash only (should not normally reach here)
            return self._fallback_scan(filename, file_data, str(e))

    def _fallback_scan(self, filename: str, file_data: bytes, error: str) -> ScanResult:
        file_hash = hashlib.sha256(file_data).hexdigest()
        entropy   = self.calculate_entropy(file_data)
        threats   = [f"Engine error (fallback mode): {error}"]
        risk_score = 0.0

        if entropy > 7.9:
            threats.append("Extremely high entropy — possible encrypted payload")
            risk_score += 40
        if entropy < 0.3:
            threats.append("Very low entropy — possible null-padded shellcode")
            risk_score += 25

        _, ext = os.path.splitext(filename.lower())
        return ScanResult(
            filename=filename,
            file_type="Unknown (fallback mode)",
            is_safe=risk_score < 40,
            risk_score=min(risk_score, 100),
            entropy=round(entropy, 4),
            threats=threats,
            file_hash=file_hash,
            details={"size_bytes": len(file_data), "extension": ext},
        )
