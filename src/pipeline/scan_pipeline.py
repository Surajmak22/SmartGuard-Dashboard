"""
Production Scan Pipeline Orchestrator — SmartGuard AI
======================================================
Implements the complete defense-in-depth pipeline:

  STEP 1 → File Validation    (MIME + extension sanity check)
  STEP 2 → Antivirus Scan     (ClamAV — reject if infected)
  STEP 3 → Format Analysis    (PDF / Image / DOCX / EXE deep structural parse)
  STEP 4 → Heuristic + ML     (4-layer engine risk scoring)
  STEP 5 → Sanitization       (CDR — neutralize threats where possible)
  STEP 6 → Final Decision     (STORE / SANITIZE / QUARANTINE / REJECT)
  STEP 7 → Audit Logging      (full record to NDJSON log)

Architecture principle: Defense in depth.
No single layer is trusted exclusively.
"""
from __future__ import annotations

import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Decision(Enum):
    STORE      = "STORE"       # File is clean — safe to store and use
    SANITIZE   = "SANITIZE"    # File was risky but neutralized — provide sanitized version
    QUARANTINE = "QUARANTINE"  # File is suspicious — hold for manual review
    REJECT     = "REJECT"      # File is malicious or AV-flagged — block


@dataclass
class PipelineResult:
    """Full result of the defense-in-depth scan pipeline."""
    scan_id: str
    filename: str
    sha256: str
    file_size_bytes: int

    # Per-stage results
    validation: Dict      = field(default_factory=dict)
    av_result: Dict       = field(default_factory=dict)
    engine_result: Dict   = field(default_factory=dict)
    sanitize_result: Dict = field(default_factory=dict)

    # Aggregated
    risk_score: float    = 0.0
    ml_score: float      = 0.0
    decision: Decision   = Decision.STORE
    threats: List[str]   = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)
    sanitized_bytes: Optional[bytes] = None
    scan_time_ms: float  = 0.0

    @property
    def is_safe(self) -> bool:
        return self.decision in (Decision.STORE, Decision.SANITIZE)

    def to_api_dict(self) -> Dict[str, Any]:
        """Clean dict for JSON API response."""
        return {
            "scan_id":        self.scan_id,
            "filename":       self.filename,
            "sha256":         self.sha256,
            "file_size_kb":   round(self.file_size_bytes / 1024, 2),
            "decision":       self.decision.value,
            "risk_score":     self.risk_score,
            "ml_score":       self.ml_score,
            "is_safe":        self.is_safe,
            "is_malicious":   not self.is_safe,
            "sanitized":      self.sanitized_bytes is not None,
            "threats":        self.threats[:15],
            "actions_taken":  self.actions_taken,
            "scan_time_ms":   self.scan_time_ms,
            "antivirus": {
                "status":     self.av_result.get("status", "UNAVAILABLE"),
                "engine":     self.av_result.get("engine", "none"),
                "detections": self.av_result.get("detections", []),
            },
            "layer_scores":   self.engine_result.get("layer_results", {}),
            "metadata":       self.engine_result.get("metadata", {}),
            "risk_breakdown": self.engine_result.get("risk_breakdown", []),
        }


# ─── Validation ───────────────────────────────────────────────────────────────

class FileValidator:
    """
    Step 1: Quick sanity checks before any expensive analysis.
    Rejects obviously invalid submissions immediately.
    """

    MAX_FILE_SIZE_MB = 50
    MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

    ALLOWED_EXTENSIONS = {
        ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
        ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm",
        ".txt", ".csv", ".json", ".xml", ".zip", ".exe", ".dll",
        ".bin", ".dat", ".mp3", ".mp4", ".wav",
    }

    def validate(self, data: bytes, filename: str) -> Dict:
        errors = []
        warnings = []

        # Size check
        if len(data) == 0:
            errors.append("Empty file — nothing to scan")
        elif len(data) > self.MAX_FILE_SIZE_BYTES:
            errors.append(
                f"File too large ({len(data) // (1024*1024)}MB > {self.MAX_FILE_SIZE_MB}MB limit)"
            )

        # Extension check (informational — not a hard block)
        _, ext = os.path.splitext(filename.lower())
        if ext and ext not in self.ALLOWED_EXTENSIONS:
            warnings.append(f"Unusual file extension: {ext}")

        # Filename sanity
        if not filename or filename.strip() == "":
            errors.append("Filename is empty")
        if ".." in filename or "/" in filename or "\\" in filename:
            errors.append("Suspicious filename path traversal characters")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "extension": ext,
        }


# ─── Main Pipeline ────────────────────────────────────────────────────────────

class ScanPipeline:
    """
    Orchestrates the complete defense-in-depth detection pipeline.
    """

    # Risk thresholds — tuned for high recall (strict)
    REJECT_THRESHOLD      = 70     # Risk >= 70 → REJECT
    QUARANTINE_THRESHOLD  = 45     # Risk >= 45 → QUARANTINE
    SANITIZE_THRESHOLD    = 20     # Risk >= 20 → SANITIZE (clean and return)

    def __init__(self):
        from src.antivirus.clam_wrapper import ClamAVWrapper
        from src.sanitizer.sanitizers import FileSanitizer
        from src.scanner.engine import MalwareEngine
        from src.logging.audit_logger import get_logger

        self._validator = FileValidator()
        self._av        = ClamAVWrapper()
        self._engine    = MalwareEngine()
        self._sanitizer = FileSanitizer()
        self._logger    = get_logger()

    def scan(
        self,
        file_data: bytes,
        filename: str,
        session_id: Optional[str] = None,
        sanitize_if_clean: bool = True,
    ) -> PipelineResult:
        """
        Run the full pipeline. Returns a PipelineResult regardless of errors.
        Never raises exceptions — all errors are captured in the result.
        """
        start = time.time()
        scan_id = str(uuid.uuid4())[:8]
        sid = session_id or scan_id

        result = PipelineResult(
            scan_id    = scan_id,
            filename   = filename,
            sha256     = hashlib.sha256(file_data).hexdigest(),
            file_size_bytes = len(file_data),
        )

        try:
            # ── STEP 1: Validation ────────────────────────────────────
            val = self._validator.validate(file_data, filename)
            result.validation = val

            if not val["valid"]:
                result.decision = Decision.REJECT
                result.threats  = val["errors"]
                result.actions_taken.append("Rejected at validation: " + "; ".join(val["errors"]))
                self._finalize(result, start, sid)
                return result

            if val["warnings"]:
                result.threats.extend(val["warnings"])

            # ── STEP 2: Antivirus ────────────────────────────────────
            av = self._av.scan(file_data, filename)
            result.av_result = {
                "status":     av.status.value,
                "engine":     av.engine,
                "detections": av.detections,
                "available":  av.is_available,
            }

            if av.is_infected:
                result.decision = Decision.REJECT
                result.risk_score = 100.0
                result.threats.extend(
                    [f"AV: {d}" for d in av.detections[:5]] or ["AV: Known malware detected"]
                )
                result.actions_taken.append(f"Blocked by {av.engine}: {av.detections}")
                self._finalize(result, start, sid)
                return result

            if not av.is_available:
                result.actions_taken.append(
                    "⚠️ ClamAV not installed — antivirus layer skipped. "
                    "Install ClamAV for full protection."
                )

            # ── STEP 3 + 4: Format Analysis + ML Scoring ─────────────
            engine_result = self._engine.scan_file(file_data, filename)
            result.engine_result = engine_result
            result.risk_score = engine_result["risk_score"]
            result.ml_score   = engine_result.get("layer_results", {}).get("ML Classifier", {}).get("score", 0.0)
            result.threats.extend(engine_result.get("threats", []))

            # ── STEP 5: Sanitization ─────────────────────────────────
            fmt = engine_result.get("metadata", {}).get("format", "Unknown")
            sanitizable = engine_result.get("metadata", {}).get("sanitizable", False)

            if sanitize_if_clean and sanitizable and result.risk_score >= self.SANITIZE_THRESHOLD:
                san = self._sanitizer.sanitize(file_data, filename)
                result.sanitize_result = {
                    "success":        san.success,
                    "actions":        san.actions_taken,
                    "size_reduction": san.size_reduction_pct,
                }
                if san.success and san.sanitized_bytes:
                    result.sanitized_bytes = san.sanitized_bytes
                    result.actions_taken.extend(san.actions_taken)

            # ── STEP 6: Final Decision ────────────────────────────────
            score = result.risk_score

            if score >= self.REJECT_THRESHOLD or engine_result.get("detection") == "MALICIOUS":
                if sanitizable and result.sanitized_bytes is not None:
                    # We sanitized a high-risk file — return clean version
                    result.decision = Decision.SANITIZE
                    result.actions_taken.append(
                        f"High-risk file ({score:.0f}/100) sanitized — "
                        "malicious elements removed, clean version available"
                    )
                else:
                    result.decision = Decision.REJECT
                    result.actions_taken.append(f"Rejected — risk score {score:.0f}/100 exceeds threshold")

            elif score >= self.QUARANTINE_THRESHOLD:
                result.decision = Decision.QUARANTINE
                result.actions_taken.append(
                    f"Quarantined — suspicious score {score:.0f}/100 (manual review recommended)"
                )

            elif score >= self.SANITIZE_THRESHOLD and result.sanitized_bytes is not None:
                result.decision = Decision.SANITIZE
                result.actions_taken.append(
                    f"Sanitized — low-risk file ({score:.0f}/100) returned with threats neutralized"
                )

            else:
                result.decision = Decision.STORE
                result.actions_taken.append(f"File clean — risk score {score:.0f}/100")

        except Exception as e:
            result.decision = Decision.QUARANTINE
            result.threats.append(f"Pipeline error (quarantined for safety): {e}")
            self._logger.log_error("Pipeline exception", e)

        self._finalize(result, start, sid)
        return result

    def _finalize(self, result: PipelineResult, start: float, sid: str) -> None:
        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        fmt = result.engine_result.get("metadata", {}).get("format", "Unknown")
        av_r = result.av_result

        self._logger.log_scan(
            filename        = result.filename,
            file_size_bytes = result.file_size_bytes,
            sha256          = result.sha256,
            av_status       = av_r.get("status", "UNAVAILABLE"),
            av_engine       = av_r.get("engine", "none"),
            av_detections   = av_r.get("detections", []),
            format_type     = fmt,
            risk_score      = result.risk_score,
            ml_score        = result.ml_score,
            decision        = result.decision.value,
            threats         = result.threats[:10],
            sanitized       = result.sanitized_bytes is not None,
            session_id      = sid,
            scan_time_ms    = result.scan_time_ms,
        )
