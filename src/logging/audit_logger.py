"""
Structured Audit Logger — SmartGuard AI
=========================================
Logs every scan decision to both JSON file and console.
Each log entry is a self-contained JSON object (NDJSON format).
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


LOGS_DIR = Path(__file__).resolve().parents[2] / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)

SCAN_LOG_PATH = LOGS_DIR / "scan_audit.ndjson"
ERROR_LOG_PATH = LOGS_DIR / "errors.log"


class AuditLogger:
    """
    Writes one JSON record per scan to the audit log.
    Thread-safe for single-process use (file-level locking via append mode).
    """

    # Standard console logger for human-readable output
    _console = logging.getLogger("smartguard")

    def __init__(self):
        if not self._console.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            ))
            self._console.addHandler(handler)
            self._console.setLevel(logging.INFO)

        # File handler for errors
        err_handler = logging.FileHandler(ERROR_LOG_PATH)
        err_handler.setLevel(logging.ERROR)
        self._console.addHandler(err_handler)

    def log_scan(
        self,
        *,
        filename: str,
        file_size_bytes: int,
        sha256: str,
        av_status: str,
        av_engine: str,
        av_detections: list,
        format_type: str,
        risk_score: float,
        ml_score: float,
        decision: str,           # STORE / REJECT / QUARANTINE / SANITIZE
        threats: list,
        sanitized: bool = False,
        session_id: Optional[str] = None,
        scan_time_ms: float = 0.0,
    ) -> None:
        record = {
            "timestamp":     datetime.utcnow().isoformat() + "Z",
            "session_id":    session_id or "unknown",
            "filename":      filename,
            "sha256":        sha256,
            "file_size_kb":  round(file_size_bytes / 1024, 2),
            "format":        format_type,
            "av": {
                "status":     av_status,
                "engine":     av_engine,
                "detections": av_detections[:5],
            },
            "risk_score":    risk_score,
            "ml_score":      ml_score,
            "decision":      decision,
            "sanitized":     sanitized,
            "threat_count":  len(threats),
            "threats":       threats[:5],   # first 5 for log compactness
            "scan_time_ms":  scan_time_ms,
        }

        # Write JSON record
        try:
            with open(SCAN_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError as e:
            self._console.error(f"Failed to write audit log: {e}")

        # Console summary
        icon = {"REJECT": "[!]", "QUARANTINE": "[?]", "STORE": "[OK]", "SANITIZE": "[*]"}.get(decision, "[I]")
        self._console.info(
            f"{icon} [{decision}] {filename} | score={risk_score:.0f}/100 | "
            f"AV={av_status} | {format_type} | {round(file_size_bytes/1024,1)}KB"
        )

    def log_error(self, message: str, exc: Optional[Exception] = None) -> None:
        self._console.error(f"ERROR: {message}" + (f" — {exc}" if exc else ""))

    def get_recent_scans(self, n: int = 100) -> list:
        """Read last N scan records from the audit log."""
        records = []
        try:
            if SCAN_LOG_PATH.exists():
                lines = SCAN_LOG_PATH.read_text(encoding="utf-8").strip().splitlines()
                for line in lines[-n:]:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except OSError:
            pass
        return records


# Singleton instance
_logger: Optional[AuditLogger] = None

def get_logger() -> AuditLogger:
    global _logger
    if _logger is None:
        _logger = AuditLogger()
    return _logger
