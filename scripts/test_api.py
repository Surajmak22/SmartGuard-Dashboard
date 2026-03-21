"""
API End-to-End Verification — SmartGuard AI
================================================
Tests the production FastAPI backend by running a clean image and a
synthetic malicious image through the full pipeline.
"""
import asyncio
import io
import time
from fastapi.testclient import TestClient

import sys
from pathlib import Path

# Fix import path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.main import app

client = TestClient(app)

def test_health():
    print("\n--- Testing GET /api/v1/health ---")
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    print("Status:", data.get("status"))
    print("Detection Layers:", len(data.get("detection_layers", [])))
    print("ClamAV Mode:", data.get("antivirus", {}).get("mode"))
    print("=> Health check PASSED")

def test_scan_clean():
    print("\n--- Testing POST /api/v1/scan (Clean File) ---")
    # Clean 2x2 white JPEG
    clean_jpg = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00C\x00"
        b"\x05\x03\x04\x04\x04\x03\x05\x04\x04\x04\x05\x05\x05\x06\x07\x0c\x08\x07\x07\x07\x0f\x0b"
        b"\x0b\t\x0c\x11\x0f\x12\x12\x11\x0f\x11\x11\x13\x16\x1c\x17\x13\x14\x1a\x15\x11\x11\x18!\x18"
        b"\x1a\x1d\x1d\x1f\x1f\x1f\x13\x17\"#\x1f \x1e\x1f\x1f\xff\xc0\x00\x0b\x08\x00\x02\x00\x02\x03\x01"
        b"\x11\x00\x02\x11\x01\x03\x11\x01\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xda\x00\x0c\x03\x01\x00\x02"
        b"\x11\x03\x11\x00?\x00\xfd\xfc\xff\xd9"
    )
    
    start = time.time()
    response = client.post(
        "/api/v1/scan",
        files={"file": ("test_clean.jpg", io.BytesIO(clean_jpg), "image/jpeg")},
        data={"sanitize": True}
    )
    duration = time.time() - start
    
    assert response.status_code == 200
    data = response.json()
    
    print(f"Decision:   {data.get('decision')}")
    print(f"Risk Score: {data.get('risk_score')}")
    print(f"Scan Time:  {duration*1000:.1f}ms (API reported {data.get('scan_time_ms')}ms)")
    print(f"Threats:    {len(data.get('threats', []))}")
    
    assert data.get("is_safe") is True
    assert data.get("decision") == "STORE"
    print("=> Clean scan PASSED")

def test_scan_malicious():
    print("\n--- Testing POST /api/v1/scan (Malicious Polyglot) ---")
    # JPEG with an appended ZIP archive (polyglot)
    base_jpg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + (b"\x00" * 300) + b"\xff\xd9"
    malicious_jpg = base_jpg + b"PK\x03\x04" + (b"A" * 50) + b"eval(unescape(alert(1)))" + (b"B" * 50)
    
    start = time.time()
    response = client.post(
        "/api/v1/scan",
        files={"file": ("malicious_polyglot.jpg", io.BytesIO(malicious_jpg), "image/jpeg")},
        data={"sanitize": True}
    )
    duration = time.time() - start
    
    assert response.status_code == 200
    data = response.json()
    
    print(f"Decision:   {data.get('decision')}")
    print(f"Risk Score: {data.get('risk_score')}")
    print(f"Scan Time:  {duration*1000:.1f}ms")
    print(f"Threats:    {len(data.get('threats', []))}")
    for t in data.get('threats', [])[:3]:
        print(f"  - {t}")
        
    print(f"Sanitized:  {data.get('sanitized')}")
    if data.get('sanitized'):
        print(f"DL URL:     {data.get('sanitized_download_url')}")
    
    # It should be flagged as risky, but because sanitize=True, it should end up SANITIZE or REJECT
    assert data.get("decision") in ["SANITIZE", "REJECT", "QUARANTINE"]
    print(f"=> Malicious scan PASSED (caught successfully with decision: {data.get('decision')})")

if __name__ == "__main__":
    test_health()
    test_scan_clean()
    test_scan_malicious()
    print("\n[+] All End-to-End API tests passed successfully!")
