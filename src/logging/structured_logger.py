import logging
import json
import time
from datetime import datetime
from collections import deque
from pathlib import Path
from typing import Dict, Any

class StructuredLogger:
    """
    JSON structured logger for production monitoring and threat tracking.
    """
    def __init__(self, log_dir: str = "logs", buffer_size: int = 50):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "smartguard_json.log"
        
        # In-memory buffer for last 50 alerts
        self.alert_buffer = deque(maxlen=buffer_size)
        
        # Configure standard logging to use JSON
        self.logger = logging.getLogger("SmartGuard_Structured")
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            handler = logging.FileHandler(self.log_file)
            self.logger.addHandler(handler)

    def log_prediction(self, ip: str, prediction: int, score: float, latency: float):
        """
        Logs a threat detection event in JSON format.
        """
        severity = self._calculate_severity(score)
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": ip,
            "prediction": "ATTACK" if prediction == 1 else "BENIGN",
            "threat_score": round(score, 4),
            "severity": severity,
            "response_time_ms": round(latency * 1000, 2)
        }
        
        # Save to JSON log file
        self.logger.info(json.dumps(log_entry))
        
        # Add to in-memory buffer if it's a threat or for dashboard visibility
        self.alert_buffer.append(log_entry)
        
        return log_entry

    def _calculate_severity(self, score: float) -> str:
        if score < 0.5:
            return "Low"
        elif score < 0.7:
            return "Medium"
        elif score < 0.9:
            return "High"
        else:
            return "Critical"

    def get_recent_alerts(self, count: int = 50):
        return list(self.alert_buffer)[-count:]

    def export_logs(self, format: str = "csv"):
        """Exports the current log file to CSV or returns as JSON list."""
        if format == "json":
            return list(self.alert_buffer)
        
        # Basic CSV export logic would go here
        return "Exported to CSV placeholder"
