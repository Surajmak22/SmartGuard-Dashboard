import pandas as pd
import json
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime

class LogExporter:
    """
    Utility to export logs and metrics in various formats (CSV, JSON, PDF).
    """
    @staticmethod
    def to_csv(log_list: list, output_path: str):
        df = pd.DataFrame(log_list)
        df.to_csv(output_path, index=False)
        return output_path

    @staticmethod
    def to_json(log_list: list, output_path: str):
        with open(output_path, 'w') as f:
            json.dump(log_list, f, indent=4)
        return output_path

    @staticmethod
    def generate_metrics_pdf(metrics: dict, output_path: str):
        """
        Generates a SOC-style PDF report for detection metrics.
        """
        c = canvas.Canvas(output_path, pagesize=letter)
        width, height = letter
        
        # Header
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, height - 50, "SmartGuard AI - Threat Detection Report")
        c.setFont("Helvetica", 10)
        c.drawString(50, height - 70, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Performance Metrics
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, height - 110, "Summary Metrics")
        
        y_pos = height - 130
        c.setFont("Helvetica", 10)
        for key, value in metrics.items():
            c.drawString(70, y_pos, f"{key.replace('_', ' ').title()}: {value}")
            y_pos -= 20
        
        # Security Note
        c.setFont("Helvetica-Oblique", 8)
        c.drawString(50, 50, "Classification: Internal SOC Use Only")
        
        c.showPage()
        c.save()
        return output_path
