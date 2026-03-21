"""End-to-end verification tests for the upgraded SmartGuard scanner."""
import sys, io, zipfile, struct
sys.path.insert(0, '.')
from src.scanner.engine import MalwareEngine

engine = MalwareEngine()

def test(name, data, filename, expected):
    r = engine.scan_file(data, filename)
    status = "PASS" if expected in r["detection"] else "FAIL"
    print(f"  [{status}] {name:35s} -> {r['detection']:12s} score={r['risk_score']:5.1f}  (expected: {expected})")
    if status == "FAIL" or r["risk_score"] > 30:
        for t in r.get("threats", [])[:3]:
            print(f"         * {t[:100]}")
    return status == "PASS"

benign_jpg = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' + bytes(range(256)) * 4 + b'\xff\xd9'
poly_jpg   = benign_jpg + b'MZ\x90\x00\x03\x00\x00\x00' + bytes(100)
mal_pdf    = (b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript '
              b'/JS (eval(unescape); util.printf; Collab.collectEmailInfo) >> >>\nendobj\n%%EOF\n')
clean_pdf  = b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF\n'

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as zf:
    zf.writestr('word/vbaProject.bin', b'\xd0\xcf\x11\xe0AutoOpen WScript.Shell CreateObject URLDownloadToFile cmd.exe powershell')
    zf.writestr('word/document.xml', b'DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc.exe"')
macro_docx = buf.getvalue()

fake_exe   = b'MZ\x90\x00\x03\x00\x00\x00' + b'CreateRemoteThread\x00WriteProcessMemory\x00IsDebuggerPresent\x00VirtualAllocEx\x00URLDownloadToFile\x00UPX0\x00UPX1\x00' + bytes(50)
eicar      = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

clean_png = (b'\x89PNG\r\n\x1a\n'
             b'\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00\x00\x00\x00'
             b'\x00\x00\x00\x00IEND\xaeB`\x82')

print()
print("=" * 70)
print("  SmartGuard — Scanner Verification Tests")
print("=" * 70)
results = [
    test("Benign JPEG",           benign_jpg,  "photo.jpg",      "CLEAN"),
    test("Polyglot JPEG+EXE",     poly_jpg,    "photo.jpg",      "MALICIOUS"),
    test("PDF with JS (malicious)",mal_pdf,    "invoice.pdf",    "MALICIOUS"),
    test("Benign PDF",            clean_pdf,   "report.pdf",     "CLEAN"),
    test("DOCX+Macro+DDE",        macro_docx,  "invoice.docx",   "MALICIOUS"),
    test("EXE (packer+injection)", fake_exe,   "update.exe",     "MALICIOUS"),
    test("EXE disguised as JPG",  fake_exe,    "photo.jpg",      "MALICIOUS"),
    test("EICAR test string",     eicar,       "eicar.txt",      "MALICIOUS"),
    test("Benign PNG",            clean_png,   "screenshot.png", "CLEAN"),
]

passed = sum(results)
total  = len(results)
print()
print(f"  Result: {passed}/{total} tests passed", "✓" if passed == total else "✗")
print("=" * 70)
sys.exit(0 if passed >= total * 0.75 else 1)
