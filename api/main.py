"""
SmartGuard AI — Production FastAPI Backend
==========================================
Defense-in-depth file scanning API.

Endpoints:
  POST /api/v1/scan          — Scan a single uploaded file
  POST /api/v1/scan/batch    — Scan multiple files
  POST /api/v1/feedback/report— Submit false negatives/positives for ML retraining
  GET  /api/v1/history       — Scan history (last N records)
  GET  /api/v1/health        — System health + engine status
  GET  /api/v1/stats         — Aggregated scan statistics
  GET  /api/v1/download/{id} — Download sanitized file

Architecture:
  Every file goes through: Validate → ClamAV → 4-Layer Engine → Sanitize → Decide → Log

Usage:
  uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
"""
from __future__ import annotations

import hashlib
import io
import os
import sys
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI(
    title="SmartGuard AI — Malware Detection API",
    description=(
        "Production-grade defense-in-depth file malware detection.\n\n"
        "**Architecture:** Validation → ClamAV → Format Analysis → Heuristic+ML → Sanitization → Decision"
    ),
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Lazy-init pipeline (avoids slow startup for health checks) ────────────────
_pipeline = None
_av_wrapper = None

def get_pipeline():
    global _pipeline
    if _pipeline is None:
        from src.pipeline.scan_pipeline import ScanPipeline
        _pipeline = ScanPipeline()
    return _pipeline

def get_av():
    global _av_wrapper
    if _av_wrapper is None:
        from src.antivirus.clam_wrapper import ClamAVWrapper
        _av_wrapper = ClamAVWrapper()
    return _av_wrapper

# ── In-memory sanitized file cache (session-scoped) ──────────────────────────
# In production, replace with Redis or file storage
_sanitized_cache: Dict[str, bytes] = {}


# ─── Health ──────────────────────────────────────────────────────────────────

@app.get("/api/v1/health", tags=["System"])
def health_check() -> Dict:
    """Returns system health, engine status, and ClamAV availability."""
    av = get_av()
    av_info = av.get_engine_info()

    return {
        "status": "operational",
        "version": "2.0.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "antivirus": {
            "mode":      av_info["mode"],
            "available": av_info["available"],
            "note":      av_info["note"],
        },
        "detection_layers": [
            "Layer 1: Signature (SHA-256, magic bytes, mismatch detection)",
            "Layer 2: Format-Specific Deep Analysis (PDF/Image/DOCX/EXE parsers)",
            "Layer 3: Heuristic (100+ patterns across 10 categories)",
            "Layer 4: ML Classifier (60 byte features — Random Forest + XGBoost per-format)",
        ],
        "sanitization": ["PDF CDR", "Image re-encode", "DOCX macro removal"],
        "thresholds": {
            "reject":      70,
            "quarantine":  45,
            "sanitize":    20,
        },
    }


# ─── Single File Scan ─────────────────────────────────────────────────────────

@app.post("/api/v1/scan", tags=["Scanning"])
async def scan_file(
    file: UploadFile = File(..., description="File to scan"),
    x_session_id: Optional[str] = Form(None, description="Optional session ID for tracking"),
    sanitize: bool = Form(True, description="Apply CDR sanitization to risky-but-sanitizable files"),
) -> Dict[str, Any]:
    """
    **Full defense-in-depth file scan.**

    Returns risk score, decision, detailed threats, and layer breakdown.
    If the file is sanitizable, the sanitized version is cached for download.

    **Decisions:**
    - `STORE` — File is clean
    - `SANITIZE` — File was risky but neutralized (download clean version via /download/{scan_id})
    - `QUARANTINE` — File is suspicious (manual review recommended)
    - `REJECT` — File is malicious (blocked)
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    file_bytes = await file.read()

    pipeline = get_pipeline()
    session_id = x_session_id or str(uuid.uuid4())[:8]

    result = pipeline.scan(
        file_data=file_bytes,
        filename=file.filename,
        session_id=session_id,
        sanitize_if_clean=sanitize,
    )

    # Cache sanitized version if available
    if result.sanitized_bytes:
        _sanitized_cache[result.scan_id] = result.sanitized_bytes
        # Limit cache size (simple LRU approximation)
        if len(_sanitized_cache) > 100:
            oldest_key = next(iter(_sanitized_cache))
            del _sanitized_cache[oldest_key]

    response = result.to_api_dict()

    # Add download link if sanitized
    if result.sanitized_bytes:
        response["sanitized_download_url"] = f"/api/v1/download/{result.scan_id}"

    return response


@app.post("/api/v1/scan/batch", tags=["Scanning"])
async def scan_batch(
    files: List[UploadFile] = File(..., description="Files to scan (max 10)"),
    x_session_id: Optional[str] = Form(None),
) -> Dict:
    """
    **Batch scan up to 10 files.**
    Each file is scanned independently. Returns summary + per-file results.
    """
    if len(files) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 files per batch")

    pipeline = get_pipeline()
    session_id = x_session_id or str(uuid.uuid4())[:8]

    results = []
    malicious_count = 0
    total_start = time.time()

    for f in files:
        data = await f.read()
        r = pipeline.scan(data, f.filename or "unknown", session_id=session_id)
        item = r.to_api_dict()
        if not r.is_safe:
            malicious_count += 1
        results.append(item)

    total_ms = round((time.time() - total_start) * 1000, 2)

    return {
        "total_files":     len(results),
        "malicious_count": malicious_count,
        "clean_count":     len(results) - malicious_count,
        "total_scan_ms":   total_ms,
        "results":         results,
    }


# ─── Download Sanitized File ──────────────────────────────────────────────────

@app.get("/api/v1/download/{scan_id}", tags=["Scanning"])
def download_sanitized(scan_id: str):
    """
    **Download the sanitized (threat-neutralized) version of a scanned file.**
    Only available for files with decision=SANITIZE.
    """
    data = _sanitized_cache.get(scan_id)
    if not data:
        raise HTTPException(
            status_code=404,
            detail="Sanitized file not found. It may have expired or this file was not sanitizable."
        )

    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=sanitized_{scan_id}.bin"},
    )


# ─── History & Stats ──────────────────────────────────────────────────────────

@app.get("/api/v1/history", tags=["Analytics"])
def get_scan_history(limit: int = 50) -> Dict:
    """Returns last N scan records from the audit log."""
    from src.logging.audit_logger import get_logger
    logger = get_logger()
    records = logger.get_recent_scans(n=min(limit, 500))
    return {
        "total": len(records),
        "records": records,
    }


@app.get("/api/v1/stats", tags=["Analytics"])
def get_stats() -> Dict:
    """Returns aggregated scan statistics."""
    from src.logging.audit_logger import get_logger
    logger = get_logger()
    records = logger.get_recent_scans(n=1000)

    if not records:
        return {"message": "No scan history yet", "total_scans": 0}

    decisions = Counter(r.get("decision", "UNKNOWN") for r in records)
    formats   = Counter(r.get("format", "Unknown") for r in records)
    av_statuses = Counter(r.get("av", {}).get("status", "?") for r in records)

    risk_scores = [r.get("risk_score", 0) for r in records]
    scan_times  = [r.get("scan_time_ms", 0) for r in records]

    return {
        "total_scans":       len(records),
        "decisions":         dict(decisions),
        "formats":           dict(formats.most_common(10)),
        "antivirus_results": dict(av_statuses),
        "risk_score_stats": {
            "mean":   round(sum(risk_scores) / len(risk_scores), 1),
            "max":    round(max(risk_scores), 1),
            "min":    round(min(risk_scores), 1),
        },
        "scan_time_stats": {
            "mean_ms": round(sum(scan_times) / len(scan_times), 1),
            "max_ms":  round(max(scan_times), 1),
        },
        "detection_rate": round(
            decisions.get("REJECT", 0) / max(len(records), 1) * 100, 1
        ),
    }


# ─── Malware Portal Compat ────────────────────────────────────────────────────

@app.post("/malware/scan", tags=["Legacy"])
async def malware_scan_compat(
    file: UploadFile = File(...),
    filename: Optional[str] = Form(None),
    x_user_id: Optional[str] = Form(None),
) -> Dict:
    """Legacy endpoint for compatibility with the Streamlit malware portal."""
    data = await file.read()
    fname = filename or file.filename or "unknown"
    pipeline = get_pipeline()
    result = pipeline.scan(data, fname, session_id=x_user_id)
    r = result.to_api_dict()

    # Add legacy field names expected by malware_portal.py
    r["is_malicious"] = not result.is_safe
    r["layer_results"] = r.get("layer_scores", {})
    return r


@app.get("/malware/history", tags=["Legacy"])
def malware_history_compat(x_user_id: Optional[str] = None):
    """Legacy history endpoint for Streamlit portal."""
    from src.logging.audit_logger import get_logger
    records = get_logger().get_recent_scans(100)
    if x_user_id:
        records = [r for r in records if r.get("session_id") == x_user_id]
    return records


# ─── Continuous Learning Feedback ──────────────────────────────────────────

@app.post("/api/v1/feedback/report", tags=["Continuous Learning"])
async def report_missed_threat(
    file: UploadFile = File(..., description="The raw file that was misclassified"),
    expected_decision: str = Form(..., description="What the system SHOULD have decided: 'REJECT' (missed malware) or 'STORE' (false alarm)"),
    notes: Optional[str] = Form(None, description="Optional analyst notes"),
) -> Dict[str, Any]:
    """
    **Continuous Learning Ingest Endpoint**
    
    Submit files that the system incorrectly classified (False Negatives or False Positives).
    These files are queued continuously and ingested during the automatic 
    retraining loop (auto_retrain.py) to improve the ML models dynamically.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
        
    decision = expected_decision.upper()
    if decision not in ("REJECT", "STORE", "QUARANTINE"):
        raise HTTPException(status_code=400, detail="expected_decision must be REJECT or STORE")
        
    # Translate decision to data folder
    folder = "malicious" if decision in ("REJECT", "QUARANTINE") else "benign"
    
    # We use path relative to the REPO_ROOT
    repo_root = Path(__file__).resolve().parents[1]
    feedback_dir = repo_root / "data" / "feedback" / folder
    feedback_dir.mkdir(parents=True, exist_ok=True)
    
    file_bytes = await file.read()
    
    # Hash for deduplication
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    ext = os.path.splitext(file.filename)[1]
    save_path = feedback_dir / f"reported_{file_hash[:12]}{ext}"
    
    is_new = not save_path.exists()
    if is_new:
        save_path.write_bytes(file_bytes)
        
    return {
        "status": "queued_for_retraining",
        "file_hash": file_hash,
        "is_new_sample": is_new,
        "queue": folder,
        "message": "Sample successfully queued. It will be incorporated into the next ML retraining cycle."
    }


# ─── Root ────────────────────────────────────────────────────────────────────

@app.get("/", tags=["System"])
def root():
    return {
        "service": "SmartGuard AI — Malicious File Detection API",
        "version": "2.0.0",
        "docs":    "/api/docs",
        "health":  "/api/v1/health",
    }
