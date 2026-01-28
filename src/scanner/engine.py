from typing import Dict, Any, List
from .signature_scanner import SignatureScanner
from .ml_scanner import MLScanner
from .heuristic_scanner import HeuristicScanner
import time
import numpy as np

class MalwareEngine:
    """
    The main orchestrator for Phase V Extended Malware Analysis.
    Combines 3 layers of security checks into a final risk assessment.
    """
    def __init__(self, ensemble=None):
        self.signature_layer = SignatureScanner()
        self.ml_layer = MLScanner(ensemble=ensemble)
        self.heuristic_layer = HeuristicScanner()

    def calculate_entropy_fragmentation(self, data: bytes) -> Dict[str, any]:
        """Checks for variations in entropy across file chunks to detect hidden payloads."""
        if len(data) < 1024: return {"score": 0, "signals": []}
        
        chunk_size = len(data) // 10
        entropies = []
        for i in range(10):
            chunk = data[i*chunk_size:(i+1)*chunk_size]
            entropies.append(self.ml_layer.calculate_entropy(chunk))
        
        variance = np.var(entropies)
        max_diff = np.max(entropies) - np.min(entropies)
        
        signals = []
        frag_score = 0
        if variance > 1.5:
            signals.append(f"Non-Uniform Entropy (Var: {round(variance, 2)}) - Potential Obfuscated Payload")
            frag_score += 40
        if max_diff > 3.0:
            signals.append("Extreme Entropy Divergence - Likely Encrypted Shellcode Fragment")
            frag_score += 50
            
        return {"score": frag_score, "signals": signals}

    def scan_file(self, file_data: bytes, filename: str) -> Dict[str, Any]:
        start_time = time.time()
        
        # Layer 1: Signature Scan
        sig_result = self.signature_layer.scan(file_data, filename)
        
        # Layer 2: ML Scan
        ml_result = self.ml_layer.scan(file_data)
        
        # Layer 3: Heuristic & Advanced Fragmentation
        heu_result = self.heuristic_layer.scan(file_data)
        frag_result = self.calculate_entropy_fragmentation(file_data)
        
        # Final Risk Aggregation (Weighted - Adjusted for Fragmentation)
        final_risk_score = (
            (sig_result['risk_score'] * 0.35) + 
            (ml_result['ml_risk_score'] * 0.25) + 
            (heu_result['risk_score'] * 0.25) +
            (frag_result['score'] * 0.15)
        )
        
        # Explainable AI: Generate Risk Breakdown
        explanations = []
        if sig_result['risk_score'] > 0:
            explanations.append(f"Signature Match ({sig_result['risk_score']}/100): Known threat pattern detected.")
        if ml_result['ml_risk_score'] > 60:
            explanations.append(f"Neural Anomaly ({ml_result['ml_risk_score']}/100): Structure resembles known malware families.")
        if heu_result['risk_score'] > 50:
            explanations.append(f"Heuristic Flag ({heu_result['risk_score']}/100): Suspicious API calls or offsets indentified.")
        if frag_result['score'] > 30:
            for signal in frag_result['signals']:
                explanations.append(f"Entropy Warning: {signal}")
                
        # Confidence Calibration
        confidence = ml_result.get('confidence', 0.5) * 100
        if final_risk_score > 40 and final_risk_score < 70 and confidence < 70:
            explanations.append("Low Confidence: AI detection is uncertain; manual review recommended.")

        # Final Classification
        if final_risk_score > 70 or sig_result['risk_score'] == 100:
            classification = "MALICIOUS"
            severity = "Critical" if final_risk_score > 90 else "High"
        elif final_risk_score > 40:
            classification = "SUSPICIOUS" # Uncertainty Range
            severity = "Medium"
        else:
            classification = "CLEAN"
            severity = "Low"
            explanations.append("File appears benign with no significant risk indicators.")

        scan_duration = time.time() - start_time
        
        return {
            "filename": filename,
            "file_size_kb": round(len(file_data) / 1024, 2),
            "sha256": sig_result['sha256'],
            "detection": classification,
            "severity": severity,
            "risk_score": round(final_risk_score, 1),
            "confidence": round(confidence, 1),
            "scan_time_ms": round(scan_duration * 1000, 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "layers": {
                "signature": sig_result,
                "ml": ml_result,
                "heuristic": heu_result
            },
            "all_threats": sig_result['threats'] + heu_result['threats'],
            "risk_breakdown": explanations
        }
