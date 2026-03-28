import json
from datetime import datetime
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from io import BytesIO


def generate_json_report(scan_data: Dict[str, Any]) -> str:
    return json.dumps(scan_data, indent=2, default=str)


def generate_pdf_report(scan_data: Dict[str, Any]) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("Phishara — Threat Analysis Report", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    story.append(Spacer(1, 12))

    # Summary
    risk_level = scan_data.get("risk_level", "unknown").upper()
    risk_score = scan_data.get("risk_score", 0)
    story.append(Paragraph(f"Target: {scan_data.get('input_value', '')}", styles["Heading2"]))
    story.append(Paragraph(f"Type: {scan_data.get('input_type', '').upper()}", styles["Normal"]))
    story.append(Paragraph(f"Risk Score: {risk_score}/100", styles["Normal"]))
    story.append(Paragraph(f"Risk Level: {risk_level}", styles["Normal"]))
    story.append(Spacer(1, 12))

    # Explanation
    story.append(Paragraph("Findings:", styles["Heading2"]))
    for exp in scan_data.get("explanation", []):
        story.append(Paragraph(f"• {exp}", styles["Normal"]))
    story.append(Spacer(1, 12))

    # Details table
    details = scan_data.get("details", {})
    if details:
        story.append(Paragraph("Analysis Details:", styles["Heading2"]))
        table_data = [["Property", "Value"]]
        for k, v in details.items():
            if not isinstance(v, (list, dict)):
                table_data.append([str(k), str(v)])
        if len(table_data) > 1:
            t = Table(table_data, colWidths=[200, 300])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f0f0")]),
            ]))
            story.append(t)

    doc.build(story)
    return buffer.getvalue()
