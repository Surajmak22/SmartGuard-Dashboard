"""
Upgraded Signature Scanner — SmartGuard AI
==========================================
Full magic-number map (30+ formats), double-extension & polyglot detection,
EICAR, and an extensible known-hash DB.
"""
import hashlib
import os
import re
from typing import Dict, List, Optional, Tuple


class SignatureScanner:
    """
    Layer 1: Signature-based scan.
    Upgraded with full format detection, mismatch analysis, and threat database.
    """

    # ── Known threat hashes (SHA-256) ────────────────────────────────────────
    KNOWN_THREATS: Dict[str, str] = {
        # EICAR hash (empty file — for test)
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "EICAR Empty-File Test",
        # Null payload
        "0000000000000000000000000000000000000000000000000000000000000000": "Null Payload / Zeroed File",
        # Add real hashes here as your DB grows (e.g., from VirusShare / MalShare)
    }

    # ── Magic-byte → MIME map (30+ formats) ─────────────────────────────────
    # Order matters — longer/more specific magic first
    MAGIC_MAP: List[Tuple[bytes, str, str]] = [
        # Executables (highest priority)
        (b"MZ",                               "application/x-dosexec",      "Windows PE Executable"),
        (b"\x7fELF",                          "application/x-elf",          "Linux ELF Executable"),
        (b"\xca\xfe\xba\xbe",                 "application/x-mach-binary",  "macOS Mach-O Executable"),
        (b"\xfe\xed\xfa\xce",                 "application/x-mach-binary",  "macOS Mach-O (32-bit)"),
        # Archives
        (b"PK\x03\x04",                       "application/zip",            "ZIP / DOCX / XLSX / JAR"),
        (b"Rar!\x1a\x07",                     "application/x-rar",          "RAR Archive"),
        (b"\x1f\x8b",                         "application/gzip",           "GZIP Archive"),
        (b"7z\xbc\xaf'\x1c",                  "application/x-7z-compressed","7-Zip Archive"),
        # Documents
        (b"%PDF",                             "application/pdf",            "PDF Document"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1","application/msword",         "Office 97-2003 (DOC/XLS/PPT) — OLE"),
        # Images
        (b"\xff\xd8\xff",                     "image/jpeg",                 "JPEG Image"),
        (b"\x89PNG\r\n\x1a\n",               "image/png",                  "PNG Image"),
        (b"GIF87a",                           "image/gif",                  "GIF87 Image"),
        (b"GIF89a",                           "image/gif",                  "GIF89 Image"),
        (b"BM",                               "image/bmp",                  "BMP Image"),
        (b"RIFF",                             "image/webp",                 "RIFF Container (WAV/WEBP/AVI)"),
        (b"\x00\x00\x01\x00",                "image/x-icon",               "ICO Icon"),
        # Audio / Video
        (b"ID3",                             "audio/mpeg",                 "MP3 Audio (ID3)"),
        (b"\xff\xfb",                        "audio/mpeg",                 "MP3 Audio"),
        (b"fLaC",                            "audio/flac",                 "FLAC Audio"),
        (b"OggS",                            "audio/ogg",                  "OGG Audio"),
        (b"\x00\x00\x00\x18ftyp",            "video/mp4",                  "MP4 Video"),
        (b"\x00\x00\x00\x20ftyp",            "video/mp4",                  "MP4 Video"),
        # Scripts / Code
        (b"#!/bin/sh",                        "text/x-shellscript",         "Shell Script"),
        (b"#!/bin/bash",                      "text/x-shellscript",         "Bash Script"),
        (b"#!/usr/bin/env python",            "text/x-python",              "Python Script"),
        (b"#!/usr/bin/env node",              "text/x-javascript",          "Node.js Script"),
        # Other
        (b"<!DOCTYPE html",                   "text/html",                  "HTML Document"),
        (b"<html",                            "text/html",                  "HTML Document"),
        (b"<?xml",                            "text/xml",                   "XML Document"),
    ]

    # ── Safe extension → MIME groups ────────────────────────────────────────
    # Mapping: extension → list of acceptable detected MIME prefixes
    SAFE_EXTENSION_MIME: Dict[str, List[str]] = {
        ".jpg":  ["image/jpeg"],
        ".jpeg": ["image/jpeg"],
        ".png":  ["image/png"],
        ".gif":  ["image/gif"],
        ".bmp":  ["image/bmp"],
        ".webp": ["image/webp"],
        ".pdf":  ["application/pdf"],
        ".docx": ["application/zip"],  # DOCX is a ZIP
        ".xlsx": ["application/zip"],
        ".pptx": ["application/zip"],
        ".docm": ["application/zip"],
        ".xlsm": ["application/zip"],
        ".zip":  ["application/zip"],
        ".rar":  ["application/x-rar"],
        ".7z":   ["application/x-7z-compressed"],
        ".gz":   ["application/gzip"],
        ".mp3":  ["audio/mpeg"],
        ".flac": ["audio/flac"],
        ".ogg":  ["audio/ogg"],
        ".mp4":  ["video/mp4"],
        ".exe":  ["application/x-dosexec"],
        ".dll":  ["application/x-dosexec"],
        ".txt":  [],   # plain text has no magic — skip mismatch check
        ".csv":  [],
        ".json": [],
        ".xml":  ["text/xml"],
        ".html": ["text/html"],
        ".htm":  ["text/html"],
    }

    # ── Extensions that are inherently dangerous ────────────────────────────
    DANGEROUS_EXTENSIONS = {
        ".exe", ".dll", ".scr", ".com", ".bat", ".cmd",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".ps1", ".ps1xml", ".ps2", ".ps2xml",
        ".msi", ".msp", ".reg", ".inf", ".lnk",
        ".hta", ".cpl", ".pif",
    }

    # ── Double-extension patterns ────────────────────────────────────────────
    DOUBLE_EXTENSION_PATTERN = re.compile(
        r"\.(jpg|jpeg|png|pdf|doc|txt|mp3|mp4|gif)\.(exe|bat|vbs|ps1|js|scr|cmd|com|dll|lnk)$",
        re.IGNORECASE
    )

    def detect_format(self, data: bytes) -> Tuple[str, str]:
        """Returns (mime_type, human_label) based on magic bytes."""
        for magic, mime, label in self.MAGIC_MAP:
            if data[:len(magic)] == magic:
                return mime, label
        return "application/octet-stream", "Unknown Binary"

    def scan(self, file_data: bytes, filename: str) -> Dict:
        threats: List[str] = []
        risk_score = 0

        # ── 1. Hash ──────────────────────────────────────────────────
        sha256 = hashlib.sha256(file_data).hexdigest()

        # ── 2. EICAR test string ─────────────────────────────────────
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        if eicar in file_data:
            threats.append("EICAR Standard Anti-Malware Test File Detected")
            risk_score = 100

        # ── 3. Known hash lookup ─────────────────────────────────────
        if sha256 in self.KNOWN_THREATS:
            threats.append(f"Known threat hash: {self.KNOWN_THREATS[sha256]}")
            risk_score = max(risk_score, 100)

        # ── 4. Magic-byte format detection ───────────────────────────
        detected_mime, detected_label = self.detect_format(file_data)
        _, ext = os.path.splitext(filename.lower())

        # ── 5. Double-extension check ────────────────────────────────
        if self.DOUBLE_EXTENSION_PATTERN.search(filename):
            threats.append(
                f"Double extension detected: '{filename}' — classic trick to disguise executables as documents"
            )
            risk_score += 75

        # ── 6. Dangerous extension ───────────────────────────────────
        if ext in self.DANGEROUS_EXTENSIONS:
            threats.append(f"Inherently dangerous file type: '{ext}'")
            risk_score += 40

        # ── 7. Extension vs content mismatch ────────────────────────
        expected_mimes = self.SAFE_EXTENSION_MIME.get(ext)
        if expected_mimes is not None and len(expected_mimes) > 0:
            if not any(detected_mime.startswith(m) for m in expected_mimes):
                # Real mismatch — content doesn't match extension at all
                if detected_mime not in ("application/octet-stream",):
                    threats.append(
                        f"CONTENT-EXTENSION MISMATCH: File claims to be '{ext}' but "
                        f"magic bytes say '{detected_label}' ({detected_mime}). "
                        "This is a common masquerading technique used by malware."
                    )
                    risk_score += 70

        # ── 8. Executable disguised as media ─────────────────────────
        if detected_mime == "application/x-dosexec" and ext not in (".exe", ".dll", ".scr", ".com"):
            threats.append(
                f"CRITICAL: Windows executable content inside '{ext}' file — "
                "executable hiding behind a safe-looking extension"
            )
            risk_score = max(risk_score, 90)

        if detected_mime == "application/x-elf" and ext not in (".elf", ".so", ".bin", ""):
            threats.append(
                f"Linux ELF binary inside '{ext}' — executable masquerading as document"
            )
            risk_score += 70

        # ── 9. Legacy OLE check (DOC/XLS/PPT pre-2007) ───────────────
        if len(file_data) >= 8 and file_data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            threats.append(
                "Legacy OLE Compound File (Word 97-2003 / Excel 97-2003). "
                "These formats support embedded VBA macros. Prefer DOCX/XLSX."
            )
            risk_score += 25

        return {
            "sha256": sha256,
            "detected_mime": detected_mime,
            "detected_label": detected_label,
            "threats": threats,
            "risk_score": min(risk_score, 100),
            "layer": "Signature",
        }
