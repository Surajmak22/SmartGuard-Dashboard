"""
Upgraded ML Scanner — SmartGuard AI
=====================================
Extracts 60 real byte-level features from file content.
Trains a Random Forest on synthetic malware/benign samples.
Falls back to heuristic scoring if model not loaded.
"""
from __future__ import annotations

import math
import os
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "file_classifier.joblib"


class FeatureExtractor:
    """
    Extracts 60 byte-level features that distinguish malicious from benign files.
    These features work across all file formats without needing format-specific parsing.
    """

    N_FEATURES = 60

    def extract(self, data: bytes) -> np.ndarray:
        features = np.zeros(self.N_FEATURES, dtype=np.float32)
        if not data:
            return features

        arr = np.frombuffer(data, dtype=np.uint8)
        n = len(arr)

        # ── 1–8: Global entropy & size ────────────────────────────────
        features[0] = self._entropy(arr)
        features[1] = math.log1p(n)
        features[2] = float(n < 128)      # tiny file
        features[3] = float(n > 10_000_000)  # very large file

        # ── 4–7: Printable / null / high-byte ratios ─────────────────
        printable_mask = (arr >= 32) & (arr < 127)
        features[4] = printable_mask.mean()
        features[5] = (arr == 0).mean()          # null byte density
        features[6] = (arr > 127).mean()         # high-byte density
        features[7] = ((arr >= 9) & (arr <= 13)).mean()  # whitespace density

        # ── 8–17: Byte-histogram (8 buckets of 32 bytes each) ────────
        for i in range(8):
            lo, hi = i * 32, (i + 1) * 32
            features[8 + i] = np.mean((arr >= lo) & (arr < hi))

        # ── 16–25: Entropy per chunk (10 chunks) ─────────────────────
        chunk_size = max(n // 10, 1)
        for i in range(10):
            chunk = arr[i * chunk_size: (i + 1) * chunk_size]
            features[16 + i] = self._entropy(chunk) if len(chunk) > 0 else 0.0

        # ── 26: Entropy variance across chunks ───────────────────────
        chunk_entropies = features[16:26]
        features[26] = float(np.var(chunk_entropies))

        # ── 27–28: Max entropy run / Min entropy run ─────────────────
        features[27] = float(np.max(chunk_entropies))
        features[28] = float(np.min(chunk_entropies))

        # ── 29–33: Common byte frequencies (individual) ──────────────
        for idx, byte_val in enumerate([0x00, 0xFF, 0x90, 0x4D, 0x5A]):  # null, FF, NOP, MZ
            features[29 + idx] = float(np.sum(arr == byte_val)) / n

        # ── 34–37: Longest run of repeated bytes ──────────────────────
        features[34] = self._longest_run(arr, 0x00) / n   # null run
        features[35] = self._longest_run(arr, 0x90) / n   # NOP sled run
        features[36] = self._longest_run(arr, 0xFF) / n   # FF run
        features[37] = self._longest_run(arr, 0xCC) / n   # INT3 (debugger breakpoint)

        # ── 38–42: Header magic bytes (first 8 bytes as floats) ──────
        header = arr[:8]
        for i, b in enumerate(header[:5]):
            features[38 + i] = b / 255.0

        # ── 43–47: Tail bytes (last 8) ───────────────────────────────
        tail = arr[-8:]
        for i, b in enumerate(tail[:5]):
            features[43 + i] = b / 255.0

        # ── 48–52: String density indicators ─────────────────────────
        data_str = bytes(data)
        features[48] = self._count_pattern(data_str, b"http") / max(n, 1)
        features[49] = self._count_pattern(data_str, b"eval") / max(n, 1)
        features[50] = self._count_pattern(data_str, b"exec") / max(n, 1)
        features[51] = self._count_pattern(data_str, b"cmd.exe") / max(n, 1)
        features[52] = self._count_pattern(data_str, b"base64") / max(n, 1)

        # ── 53–56: File structure indicators ─────────────────────────
        features[53] = float(data[:2] == b"MZ")         # PE header
        features[54] = float(data[:4] == b"%PDF")       # PDF header
        features[55] = float(data[:4] == b"PK\x03\x04") # ZIP/DOCX
        features[56] = float(data[:2] == b"\xff\xd8")   # JPEG header

        # ── 57–59: Byte distribution stats ───────────────────────────
        counts = np.bincount(arr, minlength=256).astype(np.float32)
        counts /= n
        features[57] = float(np.std(counts))         # uniformity of byte distribution
        features[58] = float(np.max(counts))         # dominance of single byte
        features[59] = float((counts > 0.01).sum() / 256)  # byte diversity

        return features

    @staticmethod
    def _entropy(arr: np.ndarray) -> float:
        if len(arr) == 0:
            return 0.0
        counts = np.bincount(arr, minlength=256).astype(np.float64)
        probs = counts[counts > 0] / len(arr)
        return float(-np.sum(probs * np.log2(probs)))

    @staticmethod
    def _longest_run(arr: np.ndarray, byte_val: int) -> int:
        """Find the longest consecutive run of a specific byte value."""
        mask = (arr == byte_val).astype(np.int8)
        best = current = 0
        for v in mask:
            if v:
                current += 1
                best = max(best, current)
            else:
                current = 0
        return best

    @staticmethod
    def _count_pattern(data: bytes, pattern: bytes) -> int:
        count = 0
        start = 0
        while True:
            pos = data.lower().find(pattern, start)
            if pos == -1:
                break
            count += 1
            start = pos + 1
        return count


class MLScanner:
    """
    Layer 2: ML-based detection.
    Extracts 60 real byte-level features → Random Forest classifier.
    """

    def __init__(self, ensemble=None):
        self.ensemble = ensemble
        self._extractor = FeatureExtractor()
        self._model = None
        self._load_model()

    def _load_model(self) -> None:
        """Load the trained file classifier if available."""
        try:
            if MODEL_PATH.exists():
                import joblib
                pkg = joblib.load(MODEL_PATH)
                self._model = pkg.get("model")
        except Exception:
            self._model = None

    def calculate_entropy(self, data: bytes) -> float:
        arr = np.frombuffer(data, dtype=np.uint8) if data else np.array([], dtype=np.uint8)
        return FeatureExtractor._entropy(arr)

    def extract_byte_distribution(self, data: bytes) -> np.ndarray:
        if not data:
            return np.zeros(256)
        arr = np.frombuffer(data, dtype=np.uint8)
        counts = np.bincount(arr, minlength=256).astype(np.float64)
        return counts / len(data)

    def scan(self, file_data: bytes) -> Dict:
        entropy = self.calculate_entropy(file_data)
        features = self._extractor.extract(file_data)

        # ── A: Use the trained RF model if available ──────────────────
        if self._model is not None:
            try:
                pred_proba = self._model.predict_proba(features.reshape(1, -1))[0]
                # class 1 = malicious
                malicious_prob = float(pred_proba[1]) if len(pred_proba) > 1 else float(pred_proba[0])
                ml_risk = malicious_prob * 100
                confidence = max(pred_proba)

                return {
                    "entropy": round(entropy, 4),
                    "ml_risk_score": round(ml_risk, 1),
                    "confidence": round(float(confidence), 3),
                    "layer": "Machine Learning (File Classifier RF)",
                    "features_used": FeatureExtractor.N_FEATURES,
                }
            except Exception:
                pass  # Fall through to heuristic baseline

        # ── B: Network-traffic ensemble (legacy) ─────────────────────
        if self.ensemble is not None:
            try:
                top_features = features[:20].reshape(1, -1)
                result = self.ensemble.predict(top_features)
                return {
                    "entropy": round(entropy, 4),
                    "ml_risk_score": round(result["final_score"][0] * 100, 1),
                    "confidence": round(float(result["confidence"][0]), 3),
                    "layer": "Machine Learning (Hybrid Ensemble)",
                }
            except Exception:
                pass

        # ── C: Heuristic fallback (no model loaded) ───────────────────
        ml_risk = 0.0
        notes = []

        if entropy > 7.8:
            ml_risk += 35
            notes.append("Very high entropy — likely packed/encrypted")
        elif entropy > 7.2:
            ml_risk += 15
            notes.append("High entropy — compressed content")

        if entropy < 0.5 and len(file_data) > 256:
            ml_risk += 25
            notes.append("Abnormally low entropy — null-padded shellcode stub")

        # Byte diversity score
        byte_diversity = float(features[59])
        if byte_diversity < 0.15 and len(file_data) > 1024:
            ml_risk += 15
            notes.append("Low byte diversity — repetitive content (possible encoded payload)")

        # Printable ratio
        printable_ratio = float(features[4])
        if printable_ratio < 0.05 and len(file_data) > 512:
            ml_risk += 10
            notes.append("Very few printable characters — binary blob")

        return {
            "entropy": round(entropy, 4),
            "ml_risk_score": round(ml_risk, 1),
            "confidence": 0.5,
            "layer": "Machine Learning (Heuristic Baseline — no model loaded)",
            "notes": notes,
        }
