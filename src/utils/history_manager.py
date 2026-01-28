import json
import os
from typing import List, Dict, Any
from datetime import datetime

class HistoryManager:
    """
    Manages scan history and analytics data for Phase V.
    Stores records in a local JSON file for persistence.
    """
    def __init__(self, history_file: str = "logs/malware_history.json", max_records: int = 100):
        self.history_file = history_file
        self.max_records = max_records
        os.makedirs(os.path.dirname(history_file), exist_ok=True)
        
        if not os.path.exists(history_file):
            with open(history_file, 'w') as f:
                json.dump([], f)

    def add_record(self, record: Dict[str, Any]):
        try:
            with open(self.history_file, 'r+') as f:
                data = json.load(f)
                data.insert(0, record) # Newest first
                # Keep only max_records
                data = data[:self.max_records]
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()
        except Exception as e:
            print(f"History logging error: {e}")

    def get_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        try:
            with open(self.history_file, 'r') as f:
                data = json.load(f)
                return data[:limit]
        except:
            return []

    def get_analytics(self) -> Dict[str, Any]:
        history = self.get_history(limit=100)
        total = len(history)
        if total == 0:
            return {"total_scans": 0, "threat_ratio": 0, "severity_dist": {}}
        
        threats = len([r for r in history if r['detection'] != 'CLEAN'])
        severities = {}
        for r in history:
            s = r['severity']
            severities[s] = severities.get(s, 0) + 1
            
        return {
            "total_scans": total,
            "threat_ratio": round((threats / total) * 100, 1),
            "severity_dist": severities
        }
