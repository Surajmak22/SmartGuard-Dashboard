import json
from datetime import datetime
from typing import Dict, Any

class ReportGenerator:
    """
    Generates downloadable security reports in JSON and TXT formats.
    """
    
    def generate_json_report(self, scan_result: Dict[str, Any], filename: str = None) -> str:
        """Generate a JSON report from scan results."""
        report = {
            "report_metadata": {
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "report_type": "SmartGuard AI - Malware Analysis Report",
                "version": "8.0-ELITE"
            },
            "scan_summary": {
                "filename": filename if filename else scan_result.get("filename"),
                "file_size_kb": scan_result.get("file_size_kb"),
                "sha256": scan_result.get("sha256"),
                "scan_timestamp": scan_result.get("timestamp"),
                "scan_duration_ms": scan_result.get("scan_time_ms")
            },
            "threat_assessment": {
                "detection": scan_result.get("detection"),
                "severity": scan_result.get("severity"),
                "risk_score": scan_result.get("risk_score"),
                "confidence": scan_result.get("confidence")
            },
            "layer_analysis": scan_result.get("layers", {}),
            "threat_indicators": scan_result.get("all_threats", [])
        }
        return json.dumps(report, indent=2)
    
    def generate_text_report(self, scan_result: Dict[str, Any], filename: str = None) -> str:
        """Generate a professional text-based security report."""
        actual_filename = filename if filename else scan_result.get("filename")
        breakdown = scan_result.get("risk_breakdown", [])
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""
================================================================================
  _____ __  __    _    ____ _____ ____ _   _    _    ____  ____      _    ___ 
 |  ___|  \/  |  / \  |  _ \_   _/ ___| | | |  / \  |  _ \|  _ \    / \  |_ _|
 |___ \| |\/| | / _ \ | |_) || || |  _| | | | / _ \ | |_) | | | |  / _ \  | | 
  ___) | |  | |/ ___ \|  _ < | || |_| | |_| |/ ___ \|  _ <| |_| | / ___ \ | | 
 |____/|_|  |_/_/   \_\_| \_\|_| \____|\___//_/   \_\_| \_\____/ /_/   \_\___|
 
                           ELITE THREAT INTELLIGENCE
================================================================================

 [ CONFIDENTIAL ANALYSIS REPORT ]
 ------------------------------------------------------------------------------
 Generated:   {timestamp}
 Version:     8.0-ELITE (Neural Hybrid Engine)
 Reference:   {scan_result.get("sha256")[:16]}...
 
 ------------------------------------------------------------------------------
 ASSET DETAILS
 ------------------------------------------------------------------------------
 Filename:    {actual_filename:<40}
 Size:        {scan_result.get("file_size_kb")} KB
 SHA-256:     {scan_result.get("sha256")}
 Scan Time:   {scan_result.get("scan_time_ms")} ms
 
 ------------------------------------------------------------------------------
 THREAT ASSESSMENT
 ------------------------------------------------------------------------------
 Verdict:     [{scan_result.get("detection")}]
 Severity:    {scan_result.get("severity")}
 Risk Score:  {scan_result.get("risk_score")}/100
 Confidence:  {scan_result.get("confidence")}%
 
 ------------------------------------------------------------------------------
 ANALYSIS BREAKDOWN
 ------------------------------------------------------------------------------
"""
        if breakdown:
            for item in breakdown:
                report += f" [!] {item}\n"
        else:
            report += " [OK] No significant risk factors identified.\n"

        report += f"""
 ------------------------------------------------------------------------------
 LAYER DIAGNOSTICS
 ------------------------------------------------------------------------------
 LAYER 1: SIGNATURE
 - MIME Type: {scan_result.get("layers", {}).get("signature", {}).get("detected_mime")}
 - Risk:      {scan_result.get("layers", {}).get("signature", {}).get("risk_score")}

 LAYER 2: NEURAL ENGINE
 - Entropy:   {scan_result.get("layers", {}).get("ml", {}).get("entropy")}
 - Risk:      {scan_result.get("layers", {}).get("ml", {}).get("ml_risk_score")}

 LAYER 3: HEURISTICS
 - Risk:      {scan_result.get("layers", {}).get("heuristic", {}).get("risk_score")}

 ------------------------------------------------------------------------------
 THREAT INDICATORS
 ------------------------------------------------------------------------------
"""
        threats = scan_result.get("all_threats", [])
        if threats:
            for i, threat in enumerate(threats, 1):
                report += f" {i}. {threat}\n"
        else:
            report += " No active threats detected.\n"
        
        report += """
================================================================================
 END OF REPORT - SMARTGUARD AI
================================================================================
"""
        return report

    def generate_pdf_report(self, scan_result: Dict[str, Any], filename: str = None) -> bytes:
        """Generate a professional, high-design PDF report."""
        from fpdf import FPDF
        
        class PDF(FPDF):
            def header(self):
                # Professional Dark Header
                self.set_fill_color(10, 20, 35) # Dark Navy
                self.rect(0, 0, 210, 40, 'F')
                
                # Logo/Title
                self.set_font('Arial', 'B', 24)
                self.set_text_color(0, 245, 255) # Cyan
                self.cell(10)
                self.cell(0, 15, 'SMARTGUARD AI', 0, 1, 'L')
                
                self.set_font('Arial', '', 10)
                self.set_text_color(200, 200, 200) # Light Grey
                self.cell(10)
                self.cell(0, 5, 'ELITE THREAT INTELLIGENCE SYSTEM', 0, 1, 'L')
                self.cell(10)
                self.cell(0, 5, f'Report ID: {scan_result.get("sha256")[:16]}', 0, 1, 'L')
                self.ln(20)
                
                # Watermark
                self.set_font('Arial', 'B', 50)
                self.set_text_color(240, 240, 240)
                with self.rotation(45, 105, 148):
                    self.text(60, 180, "CONFIDENTIAL")

            def footer(self):
                self.set_y(-15)
                self.set_font('Arial', 'I', 8)
                self.set_text_color(128, 128, 128)
                self.cell(0, 10, f'Page {self.page_no()} | Generated by SmartGuard AI', 0, 0, 'C')

        pdf = PDF()
        pdf.add_page()
        actual_filename = filename if filename else scan_result.get("filename")
        
        # Colors
        COLOR_MALICIOUS = (255, 0, 60)
        COLOR_SUSPICIOUS = (255, 165, 0)
        COLOR_CLEAN = (0, 200, 80)
        COLOR_DARK = (20, 20, 20)
        
        # Determine Status Color
        detection = scan_result.get("detection")
        if detection == "MALICIOUS":
            theme_color = COLOR_MALICIOUS
        elif detection == "SUSPICIOUS":
            theme_color = COLOR_SUSPICIOUS
        else:
            theme_color = COLOR_CLEAN

        # --- Section: Executive Summary ---
        pdf.set_text_color(*COLOR_DARK)
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Executive Threat Summary', 0, 1)
        pdf.set_line_width(0.5)
        pdf.set_draw_color(*theme_color)
        pdf.line(10, 55, 200, 55)
        pdf.ln(5)

        # Status Box with Border
        pdf.set_line_width(1.5)
        pdf.set_draw_color(*theme_color)
        pdf.set_fill_color(*theme_color)
        # Draw filled rectangle with border
        pdf.rect(10, 60, 190, 25, 'DF')  # 'DF' = Draw and Fill
        
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Arial', 'B', 20)
        pdf.set_xy(15, 65)
        pdf.cell(90, 15, f"VERDICT: {detection}", 0, 0)
        
        pdf.set_font('Arial', 'B', 12)
        pdf.set_xy(130, 65)
        pdf.cell(65, 6, f"Risk Score: {scan_result.get('risk_score')}/100", 0, 1, 'R')
        pdf.set_xy(130, 72)
        pdf.cell(65, 6, f"Confidence: {scan_result.get('confidence')}%", 0, 1, 'R')
        
        pdf.ln(25)

        # --- Section: Asset Details ---
        pdf.set_text_color(*COLOR_DARK)
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Asset Information', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        # Table-like display
        pdf.set_fill_color(245, 245, 245)
        pdf.cell(40, 8, 'Filename:', 1, 0, 'L', 1)
        pdf.cell(150, 8, actual_filename, 1, 1, 'L')
        
        pdf.cell(40, 8, 'SHA-256:', 1, 0, 'L', 1)
        pdf.cell(150, 8, scan_result.get('sha256'), 1, 1, 'L')
        
        pdf.cell(40, 8, 'File Size:', 1, 0, 'L', 1)
        pdf.cell(50, 8, f"{scan_result.get('file_size_kb')} KB", 1, 0, 'L')
        pdf.cell(40, 8, 'Scan Time:', 1, 0, 'L', 1)
        pdf.cell(60, 8, str(scan_result.get('timestamp')), 1, 1, 'L')
        
        pdf.ln(10)
        
        # --- Section: Explainable AI ---
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Explainable AI Analysis', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        breakdown = scan_result.get("risk_breakdown", [])
        if breakdown:
            for item in breakdown:
                pdf.set_text_color(*theme_color)
                pdf.cell(10, 6, ">>", 0, 0)
                pdf.set_text_color(*COLOR_DARK)
                pdf.cell(0, 6, item, 0, 1)
        else:
            pdf.cell(0, 6, "No specific risk anomalies detected in file structure.", 0, 1)
            
        pdf.ln(10)
        
        # --- Section: Technical Breakdown ---
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Layered Security Analysis', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        # Layer 1
        pdf.set_font('Arial', 'B', 10)
        pdf.block_val = pdf.get_y()
        pdf.cell(60, 8, "Signature Analysis", 1, 0, 'C', 1)
        pdf.cell(60, 8, "Neural Network", 1, 0, 'C', 1)
        pdf.cell(60, 8, "Heuristics", 1, 1, 'C', 1)
        
        pdf.set_font('Arial', '', 10)
        pdf.cell(60, 20, f"Score: {scan_result.get('layers', {}).get('signature', {}).get('risk_score')}", 1, 0, 'C')
        pdf.cell(60, 20, f"Score: {scan_result.get('layers', {}).get('ml', {}).get('ml_risk_score')}", 1, 0, 'C')
        pdf.cell(60, 20, f"Score: {scan_result.get('layers', {}).get('heuristic', {}).get('risk_score')}", 1, 1, 'C')
        
        pdf.ln(10)

        # --- Section: Visual Risk Meter ---
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Risk Visualization', 0, 1)
        
        # Draw meter background
        pdf.set_fill_color(230, 230, 230)
        pdf.rect(10, pdf.get_y(), 190, 10, 'F')
        
        # Draw meter fill
        risk_score = scan_result.get('risk_score', 0)
        if risk_score > 0:
            pdf.set_fill_color(*theme_color)
            fill_width = (risk_score / 100) * 190
            pdf.rect(10, pdf.get_y(), fill_width, 10, 'F')
            
        pdf.ln(15)

        # --- Section: Threat Indicators ---
        if scan_result.get("all_threats"):
            pdf.set_font('Arial', 'B', 12)
            pdf.set_text_color(*COLOR_MALICIOUS)
            pdf.cell(0, 10, 'Detected Threat Indicators', 0, 1)
            pdf.set_font('Arial', '', 10)
            pdf.set_text_color(*COLOR_DARK)
            
                 
        return bytes(pdf.output(dest='S'))
