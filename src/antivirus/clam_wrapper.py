"""
ClamAV Antivirus Wrapper — SmartGuard AI
=========================================
Provides a unified interface for ClamAV scanning with graceful fallback.

Priority order:
1. clamd Unix socket (fastest, production)
2. clamdscan subprocess (common CLI install)
3. clamscan subprocess (standalone, slower)
4. Signature-only fallback (development mode)

On Windows, ClamAV can be installed via:
    winget install ClamAV.ClamAV
or downloaded from: https://www.clamav.net/downloads
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional


class AVStatus(Enum):
    CLEAN     = "CLEAN"
    INFECTED  = "INFECTED"
    ERROR     = "ERROR"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class AVResult:
    status: AVStatus
    engine: str                           # which scanner provided the result
    scan_time_ms: float = 0.0
    detections: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def is_infected(self) -> bool:
        return self.status == AVStatus.INFECTED

    @property
    def is_available(self) -> bool:
        return self.status != AVStatus.UNAVAILABLE


class ClamAVWrapper:
    """
    Resilient ClamAV interface with multi-backend support.
    Always returns an AVResult — never raises exceptions.
    """

    # Known dangerous signatures for built-in fallback (EICAR + common patterns)
    BUILTIN_SIGNATURES: List[bytes] = [
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
    ]

    def __init__(self, socket_path: Optional[str] = None, host: str = "127.0.0.1", port: int = 3310):
        self._socket = socket_path or "/var/run/clamav/clamd.ctl"
        self._host  = host
        self._port  = port
        self._mode  = self._detect_mode()

    def _detect_mode(self) -> str:
        """Auto-detect available ClamAV backend."""
        # 1. Try clamd Python library via TCP
        try:
            import clamd
            cd = clamd.ClamdNetworkSocket(host=self._host, port=self._port)
            cd.ping()
            return "clamd_tcp"
        except Exception:
            pass

        # 2. Try clamd via Unix socket
        try:
            import clamd
            if os.path.exists(self._socket):
                cd = clamd.ClamdUnixSocket(self._socket)
                cd.ping()
                return "clamd_unix"
        except Exception:
            pass

        # 3. Try clamdscan CLI
        if shutil.which("clamdscan"):
            return "clamdscan_cli"

        # 4. Try clamscan CLI (standalone, no daemon needed)
        if shutil.which("clamscan"):
            return "clamscan_cli"

        # 5. Built-in signature only (development fallback)
        return "builtin_fallback"

    def scan(self, file_data: bytes, filename: str = "upload") -> AVResult:
        """Scan file bytes. Automatically chooses the best available backend."""
        start = time.time()

        # Always run builtin EICAR check first (instant)
        builtin = self._builtin_check(file_data)
        if builtin.is_infected:
            return builtin

        if self._mode == "clamd_tcp":
            result = self._scan_clamd_tcp(file_data)
        elif self._mode == "clamd_unix":
            result = self._scan_clamd_unix(file_data)
        elif self._mode in ("clamdscan_cli", "clamscan_cli"):
            result = self._scan_cli(file_data, self._mode)
        else:
            result = AVResult(
                status=AVStatus.UNAVAILABLE,
                engine="builtin_fallback",
                scan_time_ms=round((time.time() - start) * 1000, 2),
                error=(
                    "ClamAV not installed. Install with: winget install ClamAV.ClamAV\n"
                    "Built-in signature check was applied instead."
                ),
            )

        result.scan_time_ms = round((time.time() - start) * 1000, 2)
        return result

    def _builtin_check(self, data: bytes) -> AVResult:
        for sig in self.BUILTIN_SIGNATURES:
            if sig in data:
                return AVResult(
                    status=AVStatus.INFECTED,
                    engine="builtin_signatures",
                    detections=["EICAR-Standard-AntiVirus-Test-File (builtin)"],
                )
        return AVResult(status=AVStatus.CLEAN, engine="builtin_signatures")

    def _scan_clamd_tcp(self, data: bytes) -> AVResult:
        try:
            import clamd
            cd = clamd.ClamdNetworkSocket(host=self._host, port=self._port)
            result = cd.instream(data)
            # result = {'stream': ('FOUND', 'Eicar-Test-Signature') or ('OK', None)}
            stream_result = result.get("stream", ("OK", None))
            status_str, virus_name = stream_result[0], stream_result[1]
            if status_str == "FOUND":
                return AVResult(
                    status=AVStatus.INFECTED,
                    engine="clamd_tcp",
                    detections=[virus_name or "Unknown"]
                )
            return AVResult(status=AVStatus.CLEAN, engine="clamd_tcp")
        except Exception as e:
            return AVResult(status=AVStatus.ERROR, engine="clamd_tcp", error=str(e))

    def _scan_clamd_unix(self, data: bytes) -> AVResult:
        try:
            import clamd
            cd = clamd.ClamdUnixSocket(self._socket)
            result = cd.instream(data)
            stream_result = result.get("stream", ("OK", None))
            status_str, virus_name = stream_result[0], stream_result[1]
            if status_str == "FOUND":
                return AVResult(
                    status=AVStatus.INFECTED,
                    engine="clamd_unix",
                    detections=[virus_name or "Unknown"]
                )
            return AVResult(status=AVStatus.CLEAN, engine="clamd_unix")
        except Exception as e:
            return AVResult(status=AVStatus.ERROR, engine="clamd_unix", error=str(e))

    def _scan_cli(self, data: bytes, mode: str) -> AVResult:
        """Write to temp file and scan with CLI tool."""
        suffix = ".bin"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            cmd = "clamdscan" if mode == "clamdscan_cli" else "clamscan"
            proc = subprocess.run(
                [cmd, "--no-summary", tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            output = proc.stdout + proc.stderr

            if proc.returncode == 1:  # Virus found
                # Parse virus name from output
                match = re.search(r"FOUND\s*$", output, re.MULTILINE)
                lines = [l for l in output.splitlines() if "FOUND" in l]
                detections = [l.strip() for l in lines[:5]]
                return AVResult(
                    status=AVStatus.INFECTED,
                    engine=cmd,
                    detections=detections or ["Unknown threat detected"]
                )
            elif proc.returncode == 0:
                return AVResult(status=AVStatus.CLEAN, engine=cmd)
            else:
                return AVResult(
                    status=AVStatus.ERROR,
                    engine=cmd,
                    error=f"Scanner exit code {proc.returncode}: {output[:200]}"
                )
        except subprocess.TimeoutExpired:
            return AVResult(status=AVStatus.ERROR, engine=cmd, error="Scan timeout (30s)")
        except FileNotFoundError:
            return AVResult(status=AVStatus.UNAVAILABLE, engine=cmd, error="Scanner not found")
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    def get_engine_info(self) -> Dict[str, str]:
        return {
            "mode": self._mode,
            "available": self._mode != "builtin_fallback",
            "note": (
                "ClamAV daemon active" if "clamd" in self._mode
                else "ClamAV CLI available" if "cli" in self._mode
                else "ClamAV not installed — using built-in EICAR signatures only. "
                     "Install ClamAV for full antivirus protection."
            )
        }
