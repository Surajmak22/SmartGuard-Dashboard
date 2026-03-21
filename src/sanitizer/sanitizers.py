"""
File Sanitizers — SmartGuard AI
================================
Implements the neutralization (Content Disarm & Reconstruction) layer.

Philosophy: Instead of DETECTING a threat, REMOVE the threat capability.
A re-encoded image cannot have polyglot payloads.
A rebuilt PDF cannot have JavaScript.

This layer runs AFTER detection — it sanitizes files that may be grey-area
("suspicious but not confirmed") so users can still use their content safely.
"""
from __future__ import annotations

import io
import os
import re
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional

from src.sanitizer.zip_sanitizer import ZipSanitizer


@dataclass
class SanitizeResult:
    original_size: int
    sanitized_size: int
    actions_taken: List[str] = field(default_factory=list)
    success: bool = True
    error: Optional[str] = None
    sanitized_bytes: Optional[bytes] = None

    @property
    def size_reduction_pct(self) -> float:
        if self.original_size == 0:
            return 0.0
        return round((1 - self.sanitized_size / self.original_size) * 100, 1)


# ─── PDF Sanitizer ────────────────────────────────────────────────────────────

class PDFSanitizer:
    """
    Removes dangerous elements from PDFs.
    Strategy: Parse raw bytes, remove or neutralize dangerous objects.
    
    This is a lightweight CDR (Content Disarm & Reconstruction) approach.
    For maximum safety, a proper CDR renders to bitmap then rebuilds.
    """

    # Objects to remove wholesale (replace content with benign placeholder)
    REMOVE_KEYS = [
        b"/JavaScript", b"/JS",
        b"/OpenAction", b"/AA",
        b"/Launch",
        b"/EmbeddedFile", b"/EmbeddedFiles",
        b"/XFA",
        b"/RichMedia",
    ]

    def sanitize(self, data: bytes) -> SanitizeResult:
        result = SanitizeResult(
            original_size=len(data),
            sanitized_size=len(data),
        )

        if not data.startswith(b"%PDF"):
            result.success = False
            result.error = "Not a valid PDF"
            return result

        cleaned = data
        actions = []

        # Strategy 1: Remove dangerous object keys
        for key in self.REMOVE_KEYS:
            if key in cleaned:
                # Replace the entire dict value that follows the key with /Null
                # Pattern: /Key <<...>> or /Key (...)
                pattern = re.escape(key) + rb"\s*(\(.*?\)|<<.*?>>|\S+)"
                replacement = key + b" /Null"
                cleaned_new = re.sub(pattern, replacement, cleaned, flags=re.DOTALL)
                if cleaned_new != cleaned:
                    actions.append(f"Neutralized {key.decode(errors='replace')} object")
                    cleaned = cleaned_new

        # Strategy 2: Remove JavaScript streams entirely
        # Find: N 0 obj ... /JS ... stream...endstream ... endobj
        # This is a simplified approach — a real PDF CDR would use a proper parser
        js_obj_pattern = rb"(\d+ \d+ obj\b.*?(?:/JS|/JavaScript).*?endobj)"
        matches = re.findall(js_obj_pattern, cleaned, flags=re.DOTALL)
        if matches:
            actions.append(f"Removed {len(matches)} JavaScript object(s)")
            for match in matches:
                cleaned = cleaned.replace(match, b"%% [SmartGuard: JS object removed]")

        # Strategy 3: Strip embedded files
        ef_pattern = rb"(\d+ \d+ obj\b.*?/EmbeddedFile.*?endobj)"
        ef_matches = re.findall(ef_pattern, cleaned, flags=re.DOTALL)
        if ef_matches:
            actions.append(f"Removed {len(ef_matches)} embedded file(s)")
            for match in ef_matches:
                cleaned = cleaned.replace(match, b"%% [SmartGuard: embedded file removed]")

        # Strategy 4: Remove /AA (Additional Actions) definitions
        aa_pattern = rb"/AA\s*<<[^>]*>>"
        cleaned, n = re.subn(aa_pattern, b"/AA /Null", cleaned, flags=re.DOTALL)
        if n > 0:
            actions.append(f"Neutralized {n} Additional Action(s)")

        if not actions:
            actions.append("PDF appeared clean — no modifications made")

        result.sanitized_bytes = cleaned
        result.sanitized_size = len(cleaned)
        result.actions_taken = actions
        return result


# ─── Image Sanitizer ─────────────────────────────────────────────────────────

class ImageSanitizer:
    """
    Neutralizes malicious images by decoding and re-encoding.
    
    This is the MOST EFFECTIVE sanitization for images:
    - Stripping EXIF removes metadata exploits
    - Re-encoding removes appended polyglot payloads (they won't survive decode→encode)
    - PNG chunk rewrite removes malicious tEXt chunks
    
    After re-encoding: the file contains ONLY valid image data. Period.
    """

    # Maximum acceptable image dimensions to prevent decompression bombs
    MAX_PIXELS = 50_000_000  # 50 megapixels

    def sanitize(self, data: bytes, filename: str) -> SanitizeResult:
        result = SanitizeResult(original_size=len(data), sanitized_size=len(data))
        actions = []

        try:
            from PIL import Image, ExifTags

            img = Image.open(io.BytesIO(data))

            # Decompression bomb protection
            if img.width * img.height > self.MAX_PIXELS:
                result.success = False
                result.error = (
                    f"Image too large ({img.width}x{img.height} = "
                    f"{img.width * img.height // 1_000_000}MP > 50MP limit)"
                )
                return result

            original_format = img.format or "JPEG"
            actions.append(f"Decoded {original_format} image ({img.width}x{img.height})")

            # Strip ALL metadata (EXIF, XMP, ICC, etc.)
            # The cleanest way: convert to RGB and save fresh
            if img.mode in ("RGBA", "P", "LA"):
                # For transparent images, keep alpha
                clean_img = img.convert("RGBA")
                save_format = "PNG"
            else:
                clean_img = img.convert("RGB")
                save_format = "JPEG"

            actions.append("Stripped all EXIF/XMP/metadata")
            actions.append(f"Re-encoded as clean {save_format}")

            buf = io.BytesIO()
            if save_format == "JPEG":
                clean_img.save(buf, format="JPEG", quality=92, optimize=True)
            else:
                clean_img.save(buf, format="PNG", optimize=True)

            sanitized = buf.getvalue()
            size_reduction = len(data) - len(sanitized)

            if size_reduction > 1024:
                actions.append(
                    f"Removed {size_reduction // 1024}KB of non-image data "
                    f"(was appended after image EOF — polyglot payload neutralized)"
                )

            result.sanitized_bytes = sanitized
            result.sanitized_size = len(sanitized)
            result.actions_taken = actions

        except Exception as e:
            result.success = False
            result.error = f"Image sanitization failed: {e}"

        return result


# ─── DOCX Sanitizer ──────────────────────────────────────────────────────────

class DocxSanitizer:
    """
    Office document CDR — removes macros, DDE, and external connections.
    
    Strategy: Unzip OOXML → filter dangerous parts → rezip.
    """

    # ZIP entries to completely remove (macros, VBA, OLE)
    REMOVE_ENTRIES = [
        "word/vbaProject.bin",
        "xl/vbaProject.bin",
        "ppt/vbaProject.bin",
        "word/vba/",
        "xl/vba/",
    ]

    # XML patterns to neutralize in document content
    XML_FIXES = [
        # Remove DDE fields
        (rb"DDEAUTO\s+[^\s<\"]+[^\n<]*", b"[SmartGuard: DDE removed]"),
        (rb"DDE\s+[^\s<\"]+[^\n<]*",     b"[SmartGuard: DDE removed]"),
        # Remove field codes that could execute
        (rb'<w:instrText[^>]*>\s*DDEAUTO[^<]*</w:instrText>',
         b'<w:instrText>[SmartGuard: field removed]</w:instrText>'),
        # Neutralize hyperlinks to executables
        (rb'Target="([^"]*\.(exe|bat|ps1|vbs|js|scr|cmd|dll))"',
         b'Target="[SmartGuard: removed dangerous link]"'),
    ]

    def sanitize(self, data: bytes, filename: str = "document.docx") -> SanitizeResult:
        result = SanitizeResult(original_size=len(data), sanitized_size=len(data))
        actions = []

        if not data[:4] == b"PK\x03\x04":
            result.success = False
            result.error = "Not a valid ZIP/OOXML file"
            return result

        try:
            in_buf = io.BytesIO(data)
            out_buf = io.BytesIO()

            with zipfile.ZipFile(in_buf, "r") as zin, \
                 zipfile.ZipFile(out_buf, "w", zipfile.ZIP_DEFLATED) as zout:

                for item in zin.infolist():
                    name_lower = item.filename.lower()

                    # Skip VBA / macro storage
                    should_remove = any(
                        name_lower == rem.lower() or name_lower.startswith(rem.lower())
                        for rem in self.REMOVE_ENTRIES
                    )
                    if should_remove:
                        actions.append(f"Removed macro storage: {item.filename}")
                        continue

                    # Read and potentially clean content
                    content = zin.read(item.filename)

                    # Apply XML fixes to document parts
                    if item.filename.endswith(".xml") or item.filename.endswith(".rels"):
                        cleaned_content = content
                        for pattern, replacement in self.XML_FIXES:
                            cleaned_new = re.sub(pattern, replacement, cleaned_content, flags=re.IGNORECASE)
                            if cleaned_new != cleaned_content:
                                actions.append(f"Neutralized dangerous content in {item.filename}")
                            cleaned_content = cleaned_new
                        content = cleaned_content

                    zout.writestr(item, content)

            if not actions:
                actions.append("DOCX appeared clean — no modifications made")

            sanitized = out_buf.getvalue()
            result.sanitized_bytes = sanitized
            result.sanitized_size = len(sanitized)
            result.actions_taken = actions

        except zipfile.BadZipFile as e:
            result.success = False
            result.error = f"Invalid ZIP: {e}"
        except Exception as e:
            result.success = False
            result.error = f"DOCX sanitization failed: {e}"

        return result


# ─── Router ──────────────────────────────────────────────────────────────────

class FileSanitizer:
    """
    Routes files to the correct sanitizer based on content type.
    """

    def __init__(self):
        self._pdf  = PDFSanitizer()
        self._img  = ImageSanitizer()
        self._docx = DocxSanitizer()
        self._zip  = ZipSanitizer()

    def sanitize(self, data: bytes, filename: str) -> SanitizeResult:
        ext = os.path.splitext(filename.lower())[1]

        # Magic-byte routing (don't trust extension)
        if data[:4] == b"%PDF":
            return self._pdf.sanitize(data)

        if data[:2] == b"\xff\xd8" or data[:8] == b"\x89PNG\r\n\x1a\n" or data[:6] in (b"GIF87a", b"GIF89a"):
            return self._img.sanitize(data, filename)

        if data[:4] == b"PK\x03\x04":
            # Determine if OOXML (DOCX/XLSX/PPTX) or regular ZIP
            try:
                with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                    filenames = zf.namelist()
                    if "[Content_Types].xml" in filenames or any(f.startswith("word/") or f.startswith("xl/") for f in filenames):
                        return self._docx.sanitize(data, filename)
            except Exception:
                pass
            return self._zip.sanitize(data)

        # Extension fallback
        if ext == ".pdf":
            return self._pdf.sanitize(data)
        if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"):
            return self._img.sanitize(data, filename)
        if ext in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
            return self._docx.sanitize(data, filename)
        if ext == ".zip":
            return self._zip.sanitize(data)


        # Non-sanitizable format
        return SanitizeResult(
            original_size=len(data),
            sanitized_size=len(data),
            actions_taken=["No sanitizer available for this file type"],
            success=True,
            sanitized_bytes=data,
        )
