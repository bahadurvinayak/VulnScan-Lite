
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)

from config import Config


def generate_pdf_report(scan_results):

    os.makedirs(Config.REPORT_FOLDER, exist_ok=True)

    filename = f"vulnscan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(Config.REPORT_FOLDER, filename)

    document = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0ea5e9")
    )

    story = []

    story.append(Paragraph("VulnScan Lite", title_style))
    story.append(Paragraph("Website Security Assessment Report", styles["Heading2"]))
    story.append(Spacer(1, 20))

    score_data = scan_results.get("security_score", {})

    summary = [
        ["Website URL", scan_results.get("url", "N/A")],
        ["HTTP Status", str(scan_results.get("status_code", "N/A"))],
        ["Security Score", f"{score_data.get('score', 0)}/100"],
        ["Risk Rating", score_data.get("rating", "Unknown")],
        ["Report Generated", datetime.now().strftime("%d-%m-%Y %H:%M:%S")]
    ]

    summary_table = Table(summary, colWidths=[140, 350])

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#dbeafe")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    story.append(summary_table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("Vulnerability Findings", styles["Heading2"]))

    findings = scan_results.get("findings", [])

    if findings:
        finding_data = [["Finding", "Severity", "Description"]]

        for finding in findings:
            finding_data.append([
                finding.get("title", "N/A"),
                finding.get("severity", "N/A"),
                finding.get("description", "N/A")
            ])

        finding_table = Table(
            finding_data,
            colWidths=[130, 75, 285],
            repeatRows=1
        )

        finding_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))

        story.append(finding_table)
    else:
        story.append(Paragraph(
            "No findings were detected by the configured checks.",
            styles["BodyText"]
        ))

    story.append(Spacer(1, 20))
    story.append(Paragraph("Security Header Checks", styles["Heading2"]))

    header_data = [["Header", "Status", "Risk"]]

    for item in scan_results.get("security_headers", []):
        header_data.append([
            item.get("name", "N/A"),
            item.get("status", "N/A"),
            item.get("risk", "N/A")
        ])

    if len(header_data) > 1:
        header_table = Table(header_data, colWidths=[220, 120, 150])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 7)
        ]))
        story.append(header_table)

    story.append(Spacer(1, 25))
    story.append(Paragraph(
        "Disclaimer: This report contains results from lightweight, "
        "non-intrusive checks. It is not a guarantee that the website "
        "is free from vulnerabilities.",
        styles["Italic"]
    ))

    document.build(story)

    return filename
