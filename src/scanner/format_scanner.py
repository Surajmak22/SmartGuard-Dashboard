"""
Format-Specific Deep Scanner — SmartGuard AI
=============================================
This is the most critical missing layer in the original scanner.
Each file format requires a completely different analysis strategy.

Why this matters:
- A malicious PDF looks exactly like a benign PDF to entropy analysis
- A polyglot JPEG passes PIL.Image.verify() — yet contains a ZIP payload
- A DOCX with macros shows nothing suspicious in byte distribution

This module performs structural parsing, not just byte/entropy inspection.
"""
from __future__ import annotations

import io
import math
import os
import re
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ─── Return type ─────────────────────────────────────────────────────────────

@dataclass
class FormatScanResult:
    format_type: str           # Detected format label
    risk_score: int            # 0-100
    threats: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    sanitizable: bool = False  # Can we neutralize the threat?


# ─── PDF Scanner ─────────────────────────────────────────────────────────────

class PDFScanner:
    """
    Parses PDF raw bytes to find dangerous objects.
    Does NOT rely on PDF parsing libraries — reads raw byte patterns
    which catches both text-based and binary/stream-encoded payloads.
    """

    # These PDF dictionary keywords are dangerous.
    # Scores are based on how often they appear in real attacks.
    DANGEROUS_KEYS = {
        # Automatic execution
        b"/OpenAction":     (50, "Auto-execute action on open — common in PDF dropper exploits"),
        b"/AA":             (40, "/Additional Actions — can trigger code on page open/close"),
        b"/AcroForm":       (15, "AcroForm present — check for XFA or JS inside"),
        # JavaScript
        b"/JavaScript":     (70, "JavaScript stream found — top exploit vector in PDF malware"),
        b"/JS":              (65, "JS shorthand reference — usually ties to a JavaScript stream"),
        # Embedded files
        b"/EmbeddedFile":   (60, "File embedded in PDF — common dropper technique"),
        b"/EmbeddedFiles":  (60, "Embedded file catalog — may contain dropped executable"),
        b"/Filespec":       (20, "Filespec reference to embedded content"),
        # Execution
        b"/Launch":         (80, "Launch action — directly executes commands or opens files"),
        b"/SubmitForm":     (30, "Form submission to external URL — potential data exfiltration"),
        b"/ImportData":     (30, "Data import from URL — remote content injection"),
        b"/RichMedia":      (35, "RichMedia annotation — exploited in Adobe Flash CVEs"),
        b"/XFA":            (45, "XFA form — complex XML that can embed scripts"),
        # Encryption / obfuscation
        b"/Encrypt":        (25, "PDF is encrypted — hides content from static scanners"),
        b"obj\x0astream":   (10, "Binary stream object — may contain encoded payload"),
    }

    # URI patterns inside PDFs that indicate C2 / payload fetching
    URL_PATTERN = re.compile(
        rb"(https?://[^\s<>\"\')\]]{6,}|ftp://[^\s<>\"\')\]]{6,})",
        re.IGNORECASE
    )

    # detect suspicious JS fragments inside PDF streams (even if base64-encoded partially)
    JS_PATTERNS = [
        (rb"eval\s*\(", 40, "eval() call inside PDF JS — common shellcode execution path"),
        (rb"unescape\s*\(", 35, "unescape() — classic obfuscation to decode hex payloads"),
        (rb"String\.fromCharCode", 30, "String.fromCharCode — character-level obfuscation"),
        (rb"this\.exportDataObject", 50, "exportDataObject — extracts and executes embedded files"),
        (rb"app\.doc\.syncAnnotScan", 40, "syncAnnotScan — used in annotation exploit chains"),
        (rb"getAnnots\(", 35, "getAnnots — used in certain CVE exploit PDFs"),
        (rb"Collab\.collectEmailInfo", 60, "collectEmailInfo — legacy Adobe Reader RCE exploit"),
        (rb"util\.printf\s*\(", 55, "util.printf — buffer overflow vector (CVE-2008-2992)"),
        (rb"app\.openDoc\s*\(", 40, "openDoc — opens/executes other documents or URLs"),
    ]

    def scan(self, data: bytes) -> FormatScanResult:
        result = FormatScanResult(format_type="PDF", risk_score=0)

        if not data.startswith(b"%PDF"):
            result.threats.append("File does not start with %PDF magic — fake PDF extension")
            result.risk_score += 40
            return result

        # ── Version check ──────────────────────────────────────────────
        try:
            ver_line = data[:20].split(b"\n")[0]
            result.evidence.append(f"PDF version: {ver_line.decode(errors='ignore').strip()}")
        except Exception:
            pass

        # ── Dangerous keyword scan ────────────────────────────────────
        for keyword, (score, desc) in self.DANGEROUS_KEYS.items():
            # Count occurrences — multiple is more suspicious
            count = data.count(keyword)
            if count > 0:
                multiplier = min(count, 3)  # cap at 3x to avoid runaway scores
                pts = min(score * multiplier, 90)
                result.risk_score += int(pts * 0.5)  # weighted contribution
                result.threats.append(f"[{keyword.decode(errors='replace')}] x{count}: {desc}")

        # ── JavaScript pattern scan ────────────────────────────────────
        for pattern, score, desc in self.JS_PATTERNS:
            if re.search(pattern, data, re.IGNORECASE):
                result.risk_score += score
                result.threats.append(f"JS exploit pattern: {desc}")

        # ── External URL detection ────────────────────────────────────
        urls = self.URL_PATTERN.findall(data)
        if urls:
            unique_urls = list(set(urls[:10]))  # deduplicate
            result.threats.append(
                f"External URLs found ({len(unique_urls)}): "
                + ", ".join(u.decode(errors="replace")[:60] for u in unique_urls[:3])
            )
            result.risk_score += min(len(unique_urls) * 10, 40)

        # ── Object count anomaly ────────────────────────────────────
        obj_count = len(re.findall(rb"\d+\s+\d+\s+obj\b", data))
        if obj_count > 200:
            result.threats.append(
                f"Extremely high PDF object count ({obj_count}) — possible obfuscation via object fragmentation"
            )
            result.risk_score += 20
        result.evidence.append(f"PDF object count: ~{obj_count}")

        # ── Stream count & entropy ────────────────────────────────────
        stream_matches = list(re.finditer(rb"stream\r?\n", data))
        result.evidence.append(f"Stream segments: {len(stream_matches)}")

        # ── Detect encoding tricks ────────────────────────────────────
        if b"/FlateDecode" in data and (b"/JavaScript" in data or b"/JS" in data):
            result.threats.append(
                "JavaScript inside FlateDecode stream — compressed/hidden from simple text search"
            )
            result.risk_score += 30

        if b"/ASCIIHexDecode" in data:
            result.threats.append("ASCIIHex-encoded stream — obfuscation technique")
            result.risk_score += 15

        if b"/ASCII85Decode" in data:
            result.threats.append("ASCII85-encoded stream — additional obfuscation layer")
            result.risk_score += 15

        result.risk_score = min(result.risk_score, 100)
        result.sanitizable = True  # PDFs can be sanitized (render → rebuild)
        return result


# ─── Image Scanner ──────────────────────────────────────────────────────────

class ImageScanner:
    """
    Deep image analysis that goes beyond PIL.Image.verify().
    Catches: polyglot files, EXIF exploits, appended payloads, LSB stego indicators.

    The KEY insight: malicious images are malicious because of what's AROUND or
    AFTER the image data — not the pixels themselves.
    """

    # Known image end-of-file markers
    EOF_MARKERS = {
        "JPEG": (b"\xff\xd9", b"\xff\xd8\xff"),  # (EOF, SOI)
        "PNG":  (b"\x00\x00\x00\x00IEND\xaeB`\x82", b"\x89PNG"),
        "GIF":  (b"\x3b", b"GIF8"),
    }

    # EXIF tags that can contain exploit payloads (by tag ID hex)
    DANGEROUS_EXIF_TAGS = {
        0x010e: "ImageDescription",
        0x013b: "Artist",
        0x8298: "Copyright",
        0x9c9c: "XPComment",
        0x9c9b: "XPKeywords",
        0x9c9a: "XPSubject",
    }

    def scan(self, data: bytes, filename: str) -> FormatScanResult:
        ext = os.path.splitext(filename.lower())[1]
        fmt = "JPEG" if ext in (".jpg", ".jpeg") else "PNG" if ext == ".png" else "GIF" if ext == ".gif" else "IMAGE"
        result = FormatScanResult(format_type=f"Image ({fmt})", risk_score=0)

        # ── 1. Validate magic number ──────────────────────────────────
        magic_ok, actual_fmt = self._check_magic(data)
        if not magic_ok:
            result.threats.append(
                f"File extension .{ext} but content is actually '{actual_fmt}' — masquerading image"
            )
            result.risk_score += 60

        # ── 2. Appended data check (POLYGLOT detection) ───────────────
        # This is the #1 technique: valid JPEG + ZIP/PE appended after end marker
        appended = self._find_appended_data(data, fmt)
        if appended:
            payload_size, payload_preview, inner_format = appended
            result.threats.append(
                f"POLYGLOT DETECTED: {payload_size} bytes appended AFTER image EOF marker "
                f"({inner_format}). The image contains a hidden file."
            )
            result.risk_score += 80  # Very high — this is almost always malicious

        # ── 3. EXIF analysis ─────────────────────────────────────────
        if fmt in ("JPEG", "PNG"):
            exif_risks = self._scan_exif(data)
            for risk in exif_risks:
                result.threats.append(risk)
                result.risk_score += 25

        # ── 4. Suspicious embedded strings ───────────────────────────
        string_risks = self._scan_embedded_strings(data)
        for risk in string_risks:
            result.threats.append(risk)
            result.risk_score += 20

        # ── 5. Size anomaly check ────────────────────────────────────
        # A 100x100 JPEG should be ~5-50KB. A 10MB "thumbnail" is suspicious.
        size_kb = len(data) / 1024
        if size_kb > 5000 and fmt == "JPEG":
            result.threats.append(
                f"Extremely large image ({size_kb:.0f}KB) — may contain embedded payload"
            )
            result.risk_score += 15

        # ── 6. PNG chunk analysis ────────────────────────────────────
        if fmt == "PNG":
            chunk_risks = self._scan_png_chunks(data)
            for risk in chunk_risks:
                result.threats.append(risk)
                result.risk_score += 20

        # ── 7. Re-encode size delta test ────────────────────────────
        reencode_risk = self._reencode_delta_test(data, fmt)
        if reencode_risk:
            result.threats.append(reencode_risk)
            result.risk_score += 15

        result.risk_score = min(result.risk_score, 100)
        result.sanitizable = True  # Images can be neutralized: decode → re-encode
        result.evidence.append(f"File size: {size_kb:.1f} KB")
        return result

    def _check_magic(self, data: bytes) -> Tuple[bool, str]:
        """Returns (magic_matches, actual_detected_format)."""
        if data[:2] == b"\xff\xd8":
            return True, "JPEG"
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            return True, "PNG"
        if data[:6] in (b"GIF87a", b"GIF89a"):
            return True, "GIF"
        if data[:4] == b"RIFF":
            return True, "RIFF/WEBP"
        if data[:2] == b"MZ":
            return False, "Windows Executable (EXE)"
        if data[:4] == b"PK\x03\x04":
            return False, "ZIP Archive"
        if data[:4] == b"%PDF":
            return False, "PDF Document"
        return False, "Unknown Binary"

    def _find_appended_data(self, data: bytes, fmt: str) -> Optional[Tuple[int, bytes, str]]:
        """Finds data appended after the image's end-of-file marker."""
        eof_marker = None
        if fmt == "JPEG":
            eof_marker = b"\xff\xd9"
        elif fmt == "PNG":
            eof_marker = b"IEND\xaeB`\x82"
        elif fmt == "GIF":
            # GIF trailer is just 0x3B
            last_byte_pos = data.rfind(b"\x3b")
            if last_byte_pos != -1 and last_byte_pos < len(data) - 4:
                payload = data[last_byte_pos + 1:]
                return len(payload), payload[:16], self._identify_format(payload)
            return None

        if eof_marker:
            pos = data.rfind(eof_marker)
            if pos != -1:
                after_pos = pos + len(eof_marker)
                # Allow up to 4 bytes of harmless padding (some encoders add 0x00)
                payload = data[after_pos:].lstrip(b"\x00\xff")
                if len(payload) > 16:
                    return len(payload), payload[:16], self._identify_format(payload)
        return None

    def _identify_format(self, data: bytes) -> str:
        """Quick format identification for appended data."""
        if data[:2] == b"MZ":
            return "Windows PE Executable — CRITICAL"
        if data[:4] == b"PK\x03\x04":
            return "ZIP Archive (may contain malware)"
        if data[:4] == b"%PDF":
            return "PDF Document"
        if data[:4] == b"\x7fELF":
            return "Linux ELF Executable"
        if data[:6] in (b"GIF87a", b"GIF89a"):
            return "GIF Image"
        return f"Unknown binary data (hex: {data[:4].hex()})"

    def _scan_exif(self, data: bytes) -> List[str]:
        """Scans EXIF data for suspicious content: CVE shellcode, URLs, script injections."""
        risks = []
        # Look for the EXIF APP1 marker in JPEG
        exif_pos = data.find(b"Exif\x00\x00")
        if exif_pos == -1:
            return risks

        exif_data = data[exif_pos:exif_pos + 8192]

        # Check for suspicious patterns in EXIF fields
        suspicious = [
            (rb"<script", "Script tag in EXIF — XSS via EXIF exploit"),
            (rb"javascript:", "JavaScript URI in EXIF metadata"),
            (rb"eval\s*\(", "eval() in EXIF — code execution attempt"),
            (rb"http[s]?://\S{20,}", "External URL in EXIF — potential C2 beacon"),
            (rb"cmd\.exe|powershell|/bin/sh", "Shell command in EXIF metadata"),
            (rb"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){5,}", "Hex-encoded shellcode in EXIF"),
        ]

        for pattern, desc in suspicious:
            if re.search(pattern, exif_data, re.IGNORECASE):
                risks.append(f"EXIF exploit: {desc}")

        return risks

    def _scan_embedded_strings(self, data: bytes) -> List[str]:
        """Looks for plaintext indicators of malicious content embedded in image file."""
        risks = []
        # Try to extract printable strings and look for red flags
        printable = bytes(b for b in data if 32 <= b < 127)

        patterns = [
            (rb"cmd\.exe", "cmd.exe reference embedded in image"),
            (rb"powershell\s+-", "PowerShell command embedded in image"),
            (rb"WScript\.Shell", "WScript.Shell object — Windows script host"),
            (rb"http[s]?://\S+\.(exe|bat|ps1|vbs|dll)\b", "Download URL for executable in image"),
            (rb"EICAR", "EICAR test string found in image file"),
            (rb"X5O!P%@AP\[4", "EICAR antivirus test signature"),
        ]

        for pattern, desc in patterns:
            if re.search(pattern, printable, re.IGNORECASE):
                risks.append(f"Suspicious string in image body: {desc}")

        return risks

    def _scan_png_chunks(self, data: bytes) -> List[str]:
        """
        Parses PNG chunk structure.
        Malicious PNGs often use tEXt/zTXt/iTXt chunks to hide payloads.
        """
        risks = []
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return risks

        pos = 8  # Skip PNG signature
        while pos + 12 <= len(data):
            try:
                chunk_len = struct.unpack(">I", data[pos:pos + 4])[0]
                chunk_type = data[pos + 4:pos + 8]

                if chunk_type in (b"tEXt", b"zTXt", b"iTXt"):
                    chunk_data = data[pos + 8:pos + 8 + chunk_len]
                    # Check for suspicious content in text chunks
                    if any(kw in chunk_data.lower() for kw in
                           [b"<script", b"eval(", b"javascript:", b"cmd.exe", b"powershell"]):
                        risks.append(
                            f"Suspicious content in PNG text chunk [{chunk_type.decode()}]: "
                            "may contain injected script payload"
                        )
                    if len(chunk_data) > 50000:
                        risks.append(
                            f"Abnormally large PNG text chunk [{chunk_type.decode()}] "
                            f"({chunk_len // 1024}KB) — possible data hiding"
                        )

                if chunk_type == b"tIME" and chunk_len != 7:
                    risks.append("Malformed tIME chunk — can trigger parser exploits")

                pos += 12 + chunk_len
            except Exception:
                break

        return risks

    def _reencode_delta_test(self, data: bytes, fmt: str) -> Optional[str]:
        """
        Re-encode the image and compare sizes.
        If re-encoded is dramatically smaller → original had hidden data.
        This is a lightweight stego indicator.
        """
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(data))
            buf = io.BytesIO()
            save_fmt = "JPEG" if fmt == "JPEG" else "PNG"
            img.save(buf, format=save_fmt, quality=85 if save_fmt == "JPEG" else None)
            reencoded_size = buf.tell()
            original_size = len(data)

            if original_size > 0:
                ratio = reencoded_size / original_size
                if ratio < 0.40 and original_size > 10000:
                    lost_kb = (original_size - reencoded_size) / 1024
                    return (
                        f"Re-encode test: original {original_size // 1024}KB → "
                        f"{reencoded_size // 1024}KB ({lost_kb:.0f}KB lost). "
                        "Large size reduction suggests hidden non-image data (steganography indicator)."
                    )
        except Exception:
            pass
        return None


# ─── DOCX / ZIP Scanner ─────────────────────────────────────────────────────

class DocxScanner:
    """
    Office document scanner.
    DOCX/XLSX/PPTX are ZIP files — we unzip and scan the XML for macros,
    external URLs, and OLE objects.
    """

    MACRO_INDICATORS = [
        b"vbaProject.bin",       # VBA macro storage
        b"macroEnabled",         # Theme/setting indicating macros are ON
        b"xl/vba",               # Excel VBA directory
        b"word/vba",             # Word VBA directory
        b"MacroEnabled",         # Case variant
    ]

    SUSPICIOUS_REL_TARGETS = re.compile(
        rb'Target="(https?://[^"]{10,}|ftp://[^"]{5,}|\\\\[^"]{5,})',
        re.IGNORECASE
    )

    def scan(self, data: bytes, filename: str) -> FormatScanResult:
        ext = os.path.splitext(filename.lower())[1]
        fmt_label = {
            ".docx": "DOCX", ".docm": "DOCM (Macro-Enabled)",
            ".xlsx": "XLSX", ".xlsm": "XLSM (Macro-Enabled)",
            ".pptx": "PPTX", ".pptm": "PPTM (Macro-Enabled)", ".zip": "ZIP",
        }.get(ext, "ZIP/OOXML")
        result = FormatScanResult(format_type=fmt_label, risk_score=0)

        if not data[:4] == b"PK\x03\x04":
            result.threats.append("Not a valid ZIP/OOXML — file may be corrupted or disguised")
            result.risk_score += 30
            return result

        # Macro-enabled extensions are immediately suspicious
        if ext in (".docm", ".xlsm", ".pptm"):
            result.threats.append(f"Macro-enabled Office format ({ext}) — macros auto-execute on open")
            result.risk_score += 35

        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                names = zf.namelist()
                result.evidence.append(f"ZIP contains {len(names)} entries")

                # ── Check for VBA / macro storage ─────────────────────
                for indicator in self.MACRO_INDICATORS:
                    for name in names:
                        if indicator.lower() in name.lower().encode():
                            result.threats.append(
                                f"Macro storage found: '{name}' — VBA macros present. "
                                "Macros can execute arbitrary commands when document is opened."
                            )
                            result.risk_score += 60
                            break

                # ── Scan XML relationships for external URLs ───────────
                for name in names:
                    if name.endswith(".rels") or name.endswith(".xml"):
                        try:
                            content = zf.read(name)
                            urls = self.SUSPICIOUS_REL_TARGETS.findall(content)
                            if urls:
                                for url in urls[:5]:
                                    result.threats.append(
                                        f"External reference in {name}: "
                                        f"{url.decode(errors='replace')[:80]} "
                                        "— may download malicious payload"
                                    )
                                    result.risk_score += 30
                        except Exception:
                            pass

                # ── Scan document XML for suspicious content ──────────
                for name in names:
                    if name in ("word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"):
                        try:
                            content = zf.read(name)
                            if b"DDEAUTO" in content or b"DDE(" in content:
                                result.threats.append(
                                    "DDE (Dynamic Data Exchange) fields found — "
                                    "can execute shell commands without macros"
                                )
                                result.risk_score += 55
                            if b"w:fldChar" in content and b"HYPERLINK" in content:
                                result.threats.append(
                                    "Field code with HYPERLINK — potential phishing/external execution"
                                )
                                result.risk_score += 20
                        except Exception:
                            pass

                # ── Check for embedded executable inside ZIP ──────────
                for name in names:
                    low = name.lower()
                    if low.endswith((".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".scr")):
                        result.threats.append(
                            f"Executable embedded in archive: '{name}' — "
                            "archive used as dropper container"
                        )
                        result.risk_score += 70

                # ── Check for path traversal in ZIP entries ────────────
                for name in names:
                    if name.startswith("/") or ".." in name:
                        result.threats.append(
                            f"ZIP path traversal entry: '{name}' — "
                            "can escape extraction directory (Zip Slip attack)"
                        )
                        result.risk_score += 65

        except zipfile.BadZipFile:
            result.threats.append("Invalid/corrupted ZIP file — may be a malformed dropper")
            result.risk_score += 25
        except Exception as e:
            result.evidence.append(f"ZIP scan error: {e}")

        result.risk_score = min(result.risk_score, 100)
        return result


# ─── EXE / PE Scanner ───────────────────────────────────────────────────────

class ExecutableScanner:
    """
    Basic PE (Windows Portable Executable) header analysis.
    Detects packers, dangerous imports, and suspicious section names.
    """

    # Sections commonly injected by packers or malware
    SUSPICIOUS_SECTIONS = {
        b"UPX0", b"UPX1", b"UPX2",             # UPX packer
        b".aspack", b"ASPack",                   # ASPack packer
        b".adata", b".pelock",                   # PELock packer
        b"PECompact", b"Themida",                # Themida protector
        b".enigma1", b".enigma2",                # Enigma protector
        b".nsp0", b".nsp1",                      # NsPack packer
        b"MPRESS",                               # MPRESS packer
    }

    # Dangerous API imports — the most suspicious ones
    HIGH_RISK_IMPORTS = {
        b"CreateRemoteThread":   "Process injection API — used in code injection attacks",
        b"VirtualAllocEx":       "Remote memory allocation — used in shellcode injection",
        b"WriteProcessMemory":   "Write to other process memory — classic malware technique",
        b"SetWindowsHookEx":     "System-wide keyboard/mouse hook — used by keyloggers",
        b"OpenProcess":          "Opens another process — precursor to injection",
        b"WinExec":              "Executes a command — direct code execution",
        b"ShellExecute":         "Shell execution — can run files or URLs",
        b"URLDownloadToFile":    "Downloads file from URL — dropper behavior",
        b"HttpSendRequest":      "HTTP request — potential C2 communication",
        b"RegSetValueEx":        "Registry modification — persistence mechanism",
        b"FindWindow":           "Searches for windows — evasion/sandbox detection",
        b"IsDebuggerPresent":    "Anti-debugging check — sandbox evasion technique",
        b"NtQuerySystemInfo":    "System info query — often used for VM/sandbox detection",
    }

    def scan(self, data: bytes, filename: str) -> FormatScanResult:
        result = FormatScanResult(format_type="Windows Executable (PE)", risk_score=40)
        # Executables start at an elevated baseline risk

        if data[:2] != b"MZ":
            result.threats.append("Not a valid PE file — MZ magic missing")
            result.risk_score = 0
            return result

        result.threats.append(
            "Executable file type — should never be uploaded/received as a normal document"
        )
        result.risk_score += 30  # Executables are inherently high risk in file scanning contexts

        # ── PE header parsing ─────────────────────────────────────────
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset < len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                # Read number of sections
                num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
                result.evidence.append(f"PE sections: {num_sections}")

                # Read characteristics
                characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]
                if characteristics & 0x2000:
                    result.evidence.append("DLL file (not standalone EXE)")
                if not (characteristics & 0x0002):
                    result.threats.append("PE has linker errors flag — may be a crafted/corrupted PE")
                    result.risk_score += 15

        except (struct.error, IndexError):
            result.threats.append("Malformed PE header — possibly crafted to exploit parsers")
            result.risk_score += 30

        # ── Packer detection ─────────────────────────────────────────
        for section in self.SUSPICIOUS_SECTIONS:
            if section in data:
                result.threats.append(
                    f"Packer signature found: {section.decode(errors='replace')} — "
                    "packed binaries hide real code from static scanners"
                )
                result.risk_score += 25

        # ── Import scan ─────────────────────────────────────────────
        found_imports = []
        for api, desc in self.HIGH_RISK_IMPORTS.items():
            if api in data:
                found_imports.append(f"{api.decode()}: {desc}")
                result.risk_score += 8

        if found_imports:
            result.threats.append(
                f"High-risk API imports found ({len(found_imports)}): "
                + "; ".join(found_imports[:5])
            )

        # ── Compile timestamp check ──────────────────────────────────
        try:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            timestamp = struct.unpack_from("<I", data, pe_offset + 8)[0]
            if timestamp == 0 or timestamp == 0xFFFFFFFF:
                result.threats.append("Invalid compile timestamp (0 or 0xFFFFFFFF) — timestamp wiped to evade detection")
                result.risk_score += 10
        except Exception:
            pass

        result.risk_score = min(result.risk_score, 100)
        return result


# ─── Generic Binary / Unknown Scanner ───────────────────────────────────────

class GenericScanner:
    """Fallback scanner for unrecognised formats."""

    SHEBANG_PATTERNS = [
        (b"#!/bin/sh",        "Shell script (sh) — can execute system commands"),
        (b"#!/bin/bash",      "Bash script — can execute system commands"),
        (b"#!/usr/bin/env python", "Python script disguised as binary"),
        (b"#!/usr/bin/env node",   "Node.js script"),
    ]

    def scan(self, data: bytes, filename: str) -> FormatScanResult:
        result = FormatScanResult(format_type="Binary/Unknown", risk_score=10)

        for shebang, desc in self.SHEBANG_PATTERNS:
            if data.startswith(shebang):
                result.threats.append(f"Script file: {desc}")
                result.risk_score += 40

        # High entropy = packed / encrypted content
        entropy = self._entropy(data)
        result.evidence.append(f"Shannon entropy: {entropy:.2f}/8.0")
        if entropy > 7.8:
            result.threats.append(
                f"Very high entropy ({entropy:.2f}) — content is likely encrypted or packed"
            )
            result.risk_score += 20
        elif entropy < 0.5 and len(data) > 512:
            result.threats.append(
                f"Abnormally low entropy ({entropy:.2f}) — may be null-padded shellcode stub"
            )
            result.risk_score += 15

        result.risk_score = min(result.risk_score, 100)
        return result

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts: Dict[int, int] = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        e = 0.0
        n = len(data)
        for c in counts.values():
            p = c / n
            e -= p * math.log2(p)
        return e


# ─── Main Router ────────────────────────────────────────────────────────────

class FormatScanner:
    """
    Routes uploaded files to the correct format-specific scanner.
    This is the NEW 4th detection layer in the SmartGuard engine.
    """

    def __init__(self):
        self._pdf = PDFScanner()
        self._img = ImageScanner()
        self._doc = DocxScanner()
        self._exe = ExecutableScanner()
        self._generic = GenericScanner()

    def scan(self, data: bytes, filename: str) -> FormatScanResult:
        """Route to the right scanner based on magic bytes + extension."""
        ext = os.path.splitext(filename.lower())[1]

        # Magic-byte routing takes priority over extension (catches masquerading files)
        if data[:2] == b"MZ":
            return self._exe.scan(data, filename)

        if data[:4] == b"%PDF":
            return self._pdf.scan(data)

        if data[:2] == b"\xff\xd8" or data[:8] == b"\x89PNG\r\n\x1a\n" or data[:6] in (b"GIF87a", b"GIF89a"):
            return self._img.scan(data, filename)

        if data[:4] == b"PK\x03\x04":
            # ZIP — could be DOCX/XLSX/PPTX or plain ZIP
            return self._doc.scan(data, filename)

        if data[:4] == b"\x7fELF":
            r = FormatScanResult(format_type="Linux ELF Executable", risk_score=50)
            r.threats.append("Linux ELF binary — not a document file, high risk")
            return r

        # Fall back to extension-based routing
        if ext == ".pdf":
            return self._pdf.scan(data)
        if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"):
            return self._img.scan(data, filename)
        if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".zip"):
            return self._doc.scan(data, filename)
        if ext in (".exe", ".dll", ".scr", ".com", ".sys"):
            return self._exe.scan(data, filename)

        return self._generic.scan(data, filename)
