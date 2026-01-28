import json
from typing import Dict, Any, List
import os

class ThreatCorrelator:
    """
    Intelligent Threat Correlation for Phase VII.
    Identifies variants and clusters based on historical data.
    """
    def __init__(self, history_file: str = "logs/malware_history.json"):
        self.history_file = history_file

    def find_correlations(self, current_scan: Dict[str, Any]) -> List[str]:
        correlations = []
        if not os.path.exists(self.history_file):
            return correlations

        try:
            with open(self.history_file, 'r') as f:
                history = json.load(f)
        except:
            return correlations

        # 1. Exact Hash Match in History
        for record in history:
            if record['sha256'] == current_scan['sha256'] and record.get('id') != current_scan.get('id'):
                correlations.append("Recurrent Hash: Exact same payload detected previously.")
                break

        # 2. Similarity Check (Entropy & Risk Level)
        critical_history = [r for r in history if r['detection'] == 'MALICIOUS']
        for record in critical_history:
            # Check for structural similarity (very basic mock logic)
            # If entropy and risk score are extremely close, it might be a variant
            entropy_diff = abs(record['layers']['ml']['entropy'] - current_scan['layers']['ml']['entropy'])
            risk_diff = abs(record['risk_score'] - current_scan['risk_score'])
            
            if entropy_diff < 0.05 and risk_diff < 5 and record['sha256'] != current_scan['sha256']:
                correlations.append(f"Heuristic Variant: Structural similarity to known threat {record['id']}")
                break

        return list(set(correlations))

    def find_similar_threats(self, sha256: str, risk_score: float, threshold: float = 0.9) -> List[Dict[str, Any]]:
        """
        Finds similar threats based on SHA256 and risk score.
        Returns a list of similar threat records.
        """
        similar_threats = []
        if not os.path.exists("logs/malware_history.json"):
            return similar_threats

        try:
            with open("logs/malware_history.json", 'r') as f:
                history = json.load(f)
        except:
            return similar_threats

        for record in history:
            # Skip valid records if they don't have necessary fields
            if 'sha256' not in record or 'risk_score' not in record:
                continue

            # Exact hash match
            if record['sha256'] == sha256:
                similar_threats.append({
                    "type": "Exact Match",
                    "id": record.get('id', 'Unknown'),
                    "filename": record.get('filename', 'Unknown'),
                    "timestamp": record.get('timestamp', 'Unknown'),
                    "risk_score": record['risk_score']
                })
                continue

            # Risk score similarity (within 5 points)
            if abs(record['risk_score'] - risk_score) < 5:
                similar_threats.append({
                    "type": "Risk Variant",
                    "id": record.get('id', 'Unknown'),
                    "filename": record.get('filename', 'Unknown'),
                    "timestamp": record.get('timestamp', 'Unknown'),
                    "risk_score": record['risk_score']
                })

        return similar_threats[:5]  # Return top 5 matches
