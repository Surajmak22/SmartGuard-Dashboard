import io
import zipfile
import logging

try:
    from src.sanitizer.sanitizers import SanitizeResult
except ImportError:
    pass  # Will be provided at runtime by the router

logger = logging.getLogger("ZipSanitizer")

class ZipSanitizer:
    """
    Sanitizes ZIP files by unpacking them, filtering out highly dangerous executable 
    and script payloads, mitigating ZipSlip traversal attacks, and repacking the clean items.
    """
    
    # Files with these extensions are completely purged from the archive
    BANNED_EXTENSIONS = {
        ".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".scr", ".pif", 
        ".dll", ".sys", ".sh", ".msi", ".jar", ".wsf", ".hta"
    }

    def sanitize(self, file_data: bytes) -> 'SanitizeResult':
        # Local import to avoid circular dependency
        from src.sanitizer.sanitizers import SanitizeResult
        
        result = SanitizeResult(original_size=len(file_data), sanitized_size=len(file_data))
        actions = []
        clean_zip_buffer = io.BytesIO()
        
        try:
            with zipfile.ZipFile(io.BytesIO(file_data), 'r') as source_zip:
                with zipfile.ZipFile(clean_zip_buffer, 'w', zipfile.ZIP_DEFLATED) as new_zip:
                    
                    for item in source_zip.filelist:
                        # 1. ZipSlip Prevention
                        if ".." in item.filename or item.filename.startswith("/"):
                            actions.append(f"Blocked ZipSlip path traversal attempt: {item.filename}")
                            continue
                            
                        # 2. Banned Payload Removal
                        ext = ""
                        if "." in item.filename:
                            ext = "." + item.filename.split(".")[-1].lower()
                            
                        if ext in self.BANNED_EXTENSIONS:
                            actions.append(f"Purged dangerous payload from archive: {item.filename}")
                            continue

                        # If it's safe, write it to the new zip
                        new_zip.writestr(item, source_zip.read(item.filename))
                        
            if not actions:
                actions.append("No malicious payloads found in ZIP to sanitize.")
                result.sanitized_bytes = file_data
            else:
                sanitized_data = clean_zip_buffer.getvalue()
                result.sanitized_bytes = sanitized_data
                result.sanitized_size = len(sanitized_data)
                
            result.actions_taken = actions
            return result
            
        except zipfile.BadZipFile:
            result.success = False
            result.error = "Failed to sanitize ZIP: Corrupted or invalid archive."
            return result
        except Exception as e:
            logger.error(f"ZIP sanitization error: {e}")
            result.success = False
            result.error = f"Sanitization error: {str(e)}"
            return result
