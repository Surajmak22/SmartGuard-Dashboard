"""
Upgraded MalwareEngine Orchestrator — SmartGuard AI
====================================================
Wires 4 detection layers:
  1. Signature  (hash DB, magic bytes, extension mismatch)
  2. Format     (PDF/Image/DOCX/EXE deep structural analysis)  ← NEW
  3. Heuristic  (100+ regex patterns across 10 categories)
  4. ML         (60 byte-level features → Random Forest)

Key fix: removed the "valid image → risk=10" override that caused
every malicious image to be misclassified as safe.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

import numpy as np

from .signature_scanner import SignatureScanner
from .ml_scanner import MLScanner
from .heuristic_scanner import HeuristicScanner
from .format_scanner import FormatScanner


class MalwareEngine:
    """
    4-layer malware detection orchestrator.
    Each layer contributes a weighted risk score to the final verdict.
    """

    # Layer weights — format scanner gets the biggest share because it's
    # the most format-specific and hardest to evade.
    WEIGHTS = {
        "signature":  0.25,
        "format":     0.40,   # NEW — format-specific deep analysis
        "heuristic":  0.20,
        "ml":         0.15,
    }

    # Thresholds for final classification
    THRESHOLDS = {
        "MALICIOUS":   70,
        "SUSPICIOUS":  40,
    }

    def __init__(self, ensemble=None):
        self.signature_layer = SignatureScanner()
        self.format_layer    = FormatScanner()
        self.heuristic_layer = HeuristicScanner()
        self.ml_layer        = MLScanner(ensemble=ensemble)

    # ── Public API ────────────────────────────────────────────────────────────

    def scan_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        start_time = time.time()

        # ── Run all 4 layers ─────────────────────────────────────────────────
        sig_result = self.signature_layer.scan(file_data, filename)
        fmt_result = self.format_layer.scan(file_data, filename)
        heu_result = self.heuristic_layer.scan(file_data, filename)
        ml_result  = self.ml_layer.scan(file_data)

        sig_score = sig_result["risk_score"]
        fmt_score = fmt_result.risk_score
        heu_score = heu_result["risk_score"]
        ml_score  = ml_result["ml_risk_score"]

        # ── Weighted combination ─────────────────────────────────────────────
        weighted = (
            sig_score * self.WEIGHTS["signature"]  +
            fmt_score * self.WEIGHTS["format"]      +
            heu_score * self.WEIGHTS["heuristic"]   +
            ml_score  * self.WEIGHTS["ml"]
        )

        # ── Max-impact boost ─────────────────────────────────────────────────
        # If any single layer is extremely confident we boost the final score.
        # This prevents a high-confidence format detect from being diluted.
        max_single = max(sig_score, fmt_score, heu_score)

        final_score = weighted
        if max_single >= 90:
            final_score = max(final_score, max_single * 0.95)
        elif max_single >= 75:
            final_score = max(final_score, 70.0)  # floor at MALICIOUS threshold

        # ── Signature hard-overrides ─────────────────────────────────────────
        if sig_score == 100:       # EICAR or known hash → always MALICIOUS
            final_score = 100.0

        final_score = min(round(final_score, 1), 100.0)

        # ── Build evidence trail ─────────────────────────────────────────────
        explanations: List[str] = []

        if sig_score > 0:
            explanations.append(
                f"[Signature] Score {sig_score}/100 — "
                + "; ".join(sig_result["threats"][:2])
            )
        if fmt_score > 0:
            explanations.append(
                f"[Format ({fmt_result.format_type})] Score {fmt_score}/100 — "
                + "; ".join(fmt_result.threats[:3])
            )
        if heu_score > 0:
            explanations.append(
                f"[Heuristic] Score {heu_score}/100 — "
                + "; ".join(heu_result["threats"][:2])
            )
        if ml_score > 30:
            explanations.append(
                f"[ML] Risk {ml_score:.0f}/100 — entropy {ml_result['entropy']:.2f}; "
                + "; ".join(ml_result.get("notes", [])[:2])
            )

        if not explanations:
            explanations.append("No significant risk indicators detected across all 4 layers.")

        # ── Classification ───────────────────────────────────────────────────
        if final_score >= self.THRESHOLDS["MALICIOUS"] or sig_score == 100:
            classification = "MALICIOUS"
            is_malicious   = True
            severity       = "Critical" if final_score >= 90 else "High"
        elif final_score >= self.THRESHOLDS["SUSPICIOUS"]:
            classification = "SUSPICIOUS"
            is_malicious   = False
            severity       = "Medium"
        else:
            classification = "CLEAN"
            is_malicious   = False
            severity       = "Low"

        # ── Collect all threat strings ────────────────────────────────────────
        all_threats: List[str] = (
            sig_result.get("threats", [])   +
            fmt_result.threats              +
            heu_result.get("threats", [])
        )

        scan_duration = time.time() - start_time

        return {
            # Core result
            "filename":       filename,
            "file_size_kb":   round(len(file_data) / 1024, 2),
            "sha256":         sig_result["sha256"],
            "is_malicious":   is_malicious,
            "detection":      classification,
            "severity":       severity,
            "risk_score":     final_score,
            "confidence":     round(ml_result.get("confidence", 0.5) * 100, 1),
            "scan_time_ms":   round(scan_duration * 1000, 2),
            "timestamp":      time.strftime("%Y-%m-%d %H:%M:%S"),
            # Detailed layer breakdown
            "layer_results": {
                "Signature Scanner":      {"score": sig_score},
                f"Format ({fmt_result.format_type})": {"score": fmt_score},
                "Heuristic Analysis":     {"score": heu_score},
                "ML Classifier":          {"score": round(ml_score, 1)},
            },
            "metadata": {
                "size":    len(file_data),
                "type":    sig_result.get("detected_label", "Unknown"),
                "entropy": ml_result.get("entropy", 0.0),
                "format":  fmt_result.format_type,
                "sanitizable": fmt_result.sanitizable,
            },
            # Threats + explanations
            "threats":        all_threats[:20],  # cap at 20 items for UI
            "risk_breakdown": explanations,
            "format_evidence": fmt_result.evidence,
        }
