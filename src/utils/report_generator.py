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
            def cell(self, w, h=0, txt='', border=0, ln=0, align='', fill=False, link=''):
                if txt:
                    txt = str(txt).encode('latin-1', 'replace').decode('latin-1')
                super().cell(w, h, txt, border, ln, align, fill, link)
            
            def multi_cell(self, w, h, txt, border=0, align='J', fill=False):
                if txt:
                    txt = str(txt).encode('latin-1', 'replace').decode('latin-1')
                super().multi_cell(w, h, txt, border, align, fill)

            def text(self, x, y, txt=''):
                if txt:
                    txt = str(txt).encode('latin-1', 'replace').decode('latin-1')
                super().text(x, y, txt)

            def header(self):
                # Professional Dark Header
                self.set_fill_color(15, 23, 42) # Slate 900
                self.rect(0, 0, 210, 40, 'F')
                
                # Logo/Title
                self.set_font('Arial', 'B', 24)
                self.set_text_color(56, 189, 248) # Sky 400
                self.cell(10)
                self.cell(0, 15, 'SMARTGUARD AI', 0, 1, 'L')
                
                self.set_font('Arial', '', 10)
                self.set_text_color(203, 213, 225) # Slate 300
                self.cell(10)
                self.cell(0, 5, 'THREAT INTELLIGENCE & FILE ANALYSIS REPORT', 0, 1, 'L')
                self.cell(10)
                self.cell(0, 5, f'Report ID: {scan_result.get("sha256", "Unknown")[:16]}', 0, 1, 'L')
                self.ln(20)

            def footer(self):
                self.set_y(-15)
                self.set_font('Arial', 'I', 8)
                self.set_text_color(148, 163, 184) # Slate 400
                self.cell(0, 10, f'Page {self.page_no()} | Generated by SmartGuard AI Defense Systems', 0, 0, 'C')

        pdf = PDF()
        pdf.add_page()
        actual_filename = filename if filename else scan_result.get("filename", "Unknown")
        
        # Colors
        COLOR_MALICIOUS = (239, 68, 68)   # Red 500
        COLOR_SUSPICIOUS = (245, 158, 11) # Amber 500
        COLOR_CLEAN = (16, 185, 129)      # Emerald 500
        COLOR_DARK = (15, 23, 42)         # Slate 900
        COLOR_TEXT = (51, 65, 85)         # Slate 700
        
        # Determine Status Color
        decision = str(scan_result.get("decision", "UNKNOWN")).upper()
        if decision in ("REJECT", "QUARANTINE"):
            theme_color = COLOR_MALICIOUS
        elif decision == "SANITIZE":
            theme_color = COLOR_SUSPICIOUS
        else:
            theme_color = COLOR_CLEAN
            
        risk_score = float(scan_result.get('risk_score', 0))

        # --- Section: Executive Summary ---
        pdf.set_text_color(*COLOR_DARK)
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Executive Threat Summary', 0, 1)
        pdf.set_draw_color(*theme_color)
        pdf.set_line_width(0.5)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

        # Status Box
        pdf.set_fill_color(*theme_color)
        pdf.rect(10, pdf.get_y(), 190, 25, 'F')
        
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Arial', 'B', 20)
        
        y_pos = pdf.get_y() + 5
        pdf.set_xy(15, y_pos)
        pdf.cell(90, 15, f"VERDICT: {decision}", 0, 0)
        
        pdf.set_font('Arial', 'B', 14)
        pdf.set_xy(130, y_pos + 4)
        pdf.cell(65, 7, f"Risk Score: {risk_score:.1f}/100", 0, 1, 'R')
        
        pdf.set_xy(10, y_pos + 25)
        pdf.ln(5)

        # --- Section: Asset Details ---
        pdf.set_text_color(*COLOR_DARK)
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'File Identity & Metadata', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        # Table-like display
        pdf.set_fill_color(241, 245, 249) # Slate 100
        pdf.set_draw_color(203, 213, 225) # Slate 300
        pdf.set_text_color(*COLOR_TEXT)
        
        file_size = scan_result.get('file_size_kb', 0)
        scan_time = scan_result.get('scan_time_ms', 0)
        
        pdf.cell(40, 8, 'Filename:', 1, 0, 'L', 1)
        pdf.cell(150, 8, actual_filename, 1, 1, 'L')
        
        pdf.cell(40, 8, 'SHA-256:', 1, 0, 'L', 1)
        pdf.cell(150, 8, str(scan_result.get('sha256', 'Unknown')), 1, 1, 'L')
        
        pdf.cell(40, 8, 'File Size:', 1, 0, 'L', 1)
        pdf.cell(50, 8, f"{file_size} KB", 1, 0, 'L')
        pdf.cell(40, 8, 'Scan Time:', 1, 0, 'L', 1)
        pdf.cell(60, 8, f"{scan_time} ms", 1, 1, 'L')
        
        pdf.ln(8)
        
        # --- Section: Explainable AI ---
        pdf.set_text_color(*COLOR_DARK)
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'AI Analysis & Insights', 0, 1)
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(*COLOR_TEXT)
        
        breakdown = scan_result.get("risk_breakdown", [])
        if breakdown:
            for item in breakdown:
                # Draw small colored dot/arrow
                pdf.set_text_color(*theme_color)
                pdf.cell(8, 6, ">>", 0, 0)
                pdf.set_text_color(*COLOR_TEXT)
                # Multi-cell ensures text wraps correctly
                pdf.multi_cell(182, 6, item, 0, 'L')
                pdf.ln(2)
        else:
            pdf.cell(0, 6, "No specific risk anomalies detected in file structure.", 0, 1)
            
        pdf.ln(5)
        
        # --- Section: Technical Breakdown ---
        pdf.set_text_color(*COLOR_DARK)
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Layered Security Engine Results', 0, 1)
        
        pdf.set_font('Arial', 'B', 10)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_text_color(*COLOR_DARK)
        
        pdf.cell(60, 8, "Signature Scanner", 1, 0, 'C', 1)
        pdf.cell(60, 8, "Neural Network (ML)", 1, 0, 'C', 1)
        pdf.cell(60, 8, "Heuristic Analysis", 1, 1, 'C', 1)
        
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(*COLOR_TEXT)
        
        layers = scan_result.get('layer_scores', {})
        sig_score = layers.get('signature', {}).get('risk_score', 'N/A')
        ml_score = layers.get('ml', {}).get('risk_score', 'N/A')
        heur_score = layers.get('heuristic', {}).get('risk_score', 'N/A')
        
        pdf.cell(60, 12, f"Score: {sig_score}", 1, 0, 'C')
        pdf.cell(60, 12, f"Score: {ml_score}", 1, 0, 'C')
        pdf.cell(60, 12, f"Score: {heur_score}", 1, 1, 'C')
        
        pdf.ln(8)

        # --- Section: Visual Risk Meter ---
        pdf.set_text_color(*COLOR_DARK)
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, 'Risk Visualization', 0, 1)
        
        # Draw meter background
        pdf.set_fill_color(226, 232, 240) # Slate 200
        pdf.rect(10, pdf.get_y(), 190, 8, 'F')
        
        # Draw meter fill
        if risk_score > 0:
            pdf.set_fill_color(*theme_color)
            fill_width = min((risk_score / 100) * 190, 190)
            pdf.rect(10, pdf.get_y(), fill_width, 8, 'F')
            
        pdf.ln(12)

        # --- Section: Threat Indicators ---
        threats = scan_result.get("threats", [])
        if threats:
            pdf.set_font('Arial', 'B', 14)
            pdf.set_text_color(*COLOR_MALICIOUS)
            pdf.cell(0, 10, 'Detected Threat Indicators', 0, 1)
            pdf.set_font('Arial', '', 10)
            pdf.set_text_color(*COLOR_TEXT)
            for i, threat in enumerate(threats, 1):
                pdf.cell(8, 6, f"{i}.", 0, 0)
                pdf.multi_cell(182, 6, threat, 0, 'L')
                pdf.ln(1)
            pdf.ln(5)

        # --- NEW PAGE FOR NON-TECHNICAL HELP ---
        pdf.add_page()
        
        # --- Glossary ---
        pdf.set_text_color(*COLOR_DARK)
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Glossary (Simple Explanations)', 0, 1)
        pdf.set_draw_color(203, 213, 225)
        pdf.set_line_width(0.5)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        pdf.set_text_color(*COLOR_TEXT)
        glossary = [
            ("SHA-256", "A unique digital fingerprint for the file. No two different files in the world share the same fingerprint. If a hacker changes even one pixel of an image, the fingerprint completely changes."),
            ("Entropy", "A measure of how 'random' the data inside the file is. Normal files have predictable patterns. If entropy is very high (close to 8.0), the file is entirely scrambled. Hackers do this to hide viruses inside innocent-looking files."),
            ("Heuristic Analysis", "Instead of looking for an exact match of a known virus, this looks for suspicious behavior. It's like airport security searching for strange items rather than a specific person's face."),
            ("Signature Scanner", "Checks the file against a giant database of known bad files. Think of it like comparing the file's fingerprint to a police 'Most Wanted' list."),
            ("Machine Learning (ML)", "Our Artificial Intelligence 'Brain' that learned how to spot malware by studying millions of safe and dangerous files. It catches brand-new threats humans have never seen before.")
        ]
        
        for term, definition in glossary:
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(45, 8, f"{term}:", 0, 0)
            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(145, 6, definition)
            pdf.ln(2)
            
        pdf.ln(5)

        # --- Actionable Advice ---
        if decision in ("REJECT", "QUARANTINE"):
            pdf.set_fill_color(254, 242, 242) # Red 50
            pdf.set_draw_color(239, 68, 68)   # Red 500
            pdf.set_line_width(1.0)
            
            # Start position for rectangle
            rect_y = pdf.get_y()
            pdf.rect(10, rect_y, 190, 65, 'DF')
            
            pdf.set_xy(15, rect_y + 5)
            pdf.set_text_color(185, 28, 28) # Red 700
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, 'URGENT: What You Should Do Now', 0, 1)
            
            pdf.set_text_color(153, 27, 27) # Red 800
            pdf.set_font('Arial', '', 11)
            
            advice = [
                "1. DO NOT OPEN THE FILE: Delete the file from your computer immediately. Right-click the file, select Delete, and then empty your Recycle Bin/Trash.",
                "2. RUN A FULL VIRUS SCAN: Open Windows Defender, McAfee, Norton, or whatever Antivirus you have installed, and run a 'Full System Scan'.",
                "3. SECURE YOUR ACCOUNTS: If you downloaded this file from an email link or a strange website, use a different device (like your phone) to change your email and banking passwords right away."
            ]
            
            for item in advice:
                pdf.set_x(15)
                pdf.multi_cell(180, 6, item)
                pdf.ln(2)

        return bytes(pdf.output(dest='S'))
