from __future__ import annotations

import datetime
from io import BytesIO
from typing import List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


class IncidentReportGenerator:
    """
    Generates professional PDF incident reports for SmartGuard AI.
    """

    def generate_file_report(
        self,
        filename: str,
        detected_type: str,
        is_safe: bool,
        risk_score: float,
        threats: List[str],
        file_hash: str,
    ) -> bytes:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        
        styles = getSampleStyleSheet()
        title_style = styles["Heading1"]
        heading_style = styles["Heading2"]
        normal_style = styles["Normal"]
        
        elements = []

        # 1. Header
        status_text = "SAFE" if is_safe else "THREAT DETECTED"
        elements.append(Paragraph(f"🛡️ SmartGuard AI - File Security Report", title_style))
        elements.append(Spacer(1, 12))
        
        # 2. Summary Table
        status_color = colors.green if is_safe else colors.red
        data = [
            ["File Name:", filename],
            ["Detected Type:", detected_type],
            ["Overall Status:", status_text],
            ["Risk Score:", f"{risk_score}/100"],
            ["SHA-256 Hash:", Paragraph(file_hash, normal_style)],
        ]
        
        t = Table(data, hAlign="LEFT", colWidths=[100, 350])
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR", (1, 2), (1, 2), status_color),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 20))

        # 3. Threats / Findings
        elements.append(Paragraph("Security Findings", heading_style))
        if not threats:
            elements.append(Paragraph("✅ No suspicious patterns detected during heuristic analysis.", normal_style))
        else:
            for threat in threats:
                elements.append(Paragraph(f"⚠️ {threat}", normal_style))
        
        elements.append(Spacer(1, 20))
        elements.append(Paragraph("Note: This report is generated based on heuristic and entropy analysis. For absolute certainty, use a full behavioral sandbox.", styles["Italic"]))

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

    def generate_report(
        self,
        incident_id: str,
        timestamp: str,
        confidence: float,
        severity: str,
        explanations: List[str],
        analyst_notes: str = "",
    ) -> bytes:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        
        styles = getSampleStyleSheet()
        title_style = styles["Heading1"]
        heading_style = styles["Heading2"]
        normal_style = styles["Normal"]
        
        # Custom styles
        alert_style = ParagraphStyle(
            "AlertStyle",
            parent=normal_style,
            textColor=colors.red if severity == "High" else colors.orange,
            fontName="Helvetica-Bold",
        )

        elements = []

        # 1. Header
        elements.append(Paragraph("🛡️ SmartGuard AI - Incident Report", title_style))
        elements.append(Spacer(1, 12))
        
        # 2. Incident Summary Table
        data = [
            ["Incident ID:", incident_id],
            ["Timestamp:", timestamp],
            ["Severity:", severity],
            ["Confidence Score:", f"{confidence:.2%}"],
        ]
        
        t = Table(data, hAlign="LEFT")
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR", (1, 2), (1, 2), colors.red if severity == "High" else colors.black),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (1, 0), colors.whitesmoke),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 20))

        # 3. Translucent AI / Explanation
        elements.append(Paragraph("Analysis & Logic (XAI)", heading_style))
        elements.append(Paragraph("The following factors contributed to this detection:", normal_style))
        elements.append(Spacer(1, 10))
        
        if not explanations:
            elements.append(Paragraph("No specific feature explanations available.", normal_style))
        else:
            for exp in explanations:
                # Bullet points
                elements.append(Paragraph(f"• {exp}", normal_style))
        
        elements.append(Spacer(1, 20))

        # 4. Analyst Notes
        elements.append(Paragraph("Analyst Notes", heading_style))
        if analyst_notes:
            elements.append(Paragraph(analyst_notes, normal_style))
        else:
            elements.append(Paragraph("___________________________________________________________________", normal_style))
            elements.append(Paragraph("(No notes provided)", normal_style))

        # 5. Build
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()
