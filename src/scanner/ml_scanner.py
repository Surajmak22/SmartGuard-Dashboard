import numpy as np
import math
from typing import Dict, List
from ..models.hybrid_ensemble import HybridThreatDetector

class MLScanner:
    """
    Layer 2: ML-based detection.
    Extracts features from byte distribution and entropy for AI classification.
    """
    def __init__(self, ensemble: HybridThreatDetector = None):
        self.ensemble = ensemble

    def calculate_entropy(self, data: bytes) -> float:
        if not data: return 0.0
        counts = {}
        for b in data: counts[b] = counts.get(b, 0) + 1
        entropy = 0.0
        for count in counts.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def extract_byte_distribution(self, data: bytes) -> np.ndarray:
        """Calculates frequency of each byte (0-255)."""
        if not data: return np.zeros(256)
        counts = np.zeros(256)
        for b in data: counts[b] += 1
        return counts / len(data)

    def scan(self, file_data: bytes) -> Dict[str, any]:
        entropy = self.calculate_entropy(file_data)
        byte_dist = self.extract_byte_distribution(file_data)
        
        # Mock prediction if ensemble isn't loaded (for standalone testing)
        if self.ensemble is None:
            # Heuristic fallback for ML score
            ml_risk = 0
            if entropy > 7.9: ml_risk = 40 # Packed/Encrypted
            if entropy < 1.0 and len(file_data) > 100: ml_risk = 30 # Null padding/Shellcode
            
            return {
                "entropy": round(entropy, 4),
                "ml_risk_score": ml_risk,
                "confidence": 0.5,
                "layer": "Machine Learning (Baseline)"
            }
        
        # If ensemble is present, we use a reduced feature set (top 20) 
        # for real-time file scanning compatibility
        features = np.zeros(20)
        features[0] = entropy
        features[1:min(20, len(byte_dist)+1)] = byte_dist[:19]
        
        result = self.ensemble.predict(features.reshape(1, -1))
        
        return {
            "entropy": round(entropy, 4),
            "ml_risk_score": result['final_score'][0] * 100,
            "confidence": result['confidence'][0],
            "contributions": {
                "rf": result['rf_contribution'][0],
                "pattern": result['cnn_contribution'][0],
                "anomaly": result['ae_contribution'][0]
            },
            "layer": "Machine Learning (Hybrid Ensemble)"
        }
