from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .realtime import DetectionEvent
from .security_analyst import local_security_analyst_report


def _footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(18 * mm, 10 * mm, "Sentinel NID SOC - Confidential")
    canvas.drawRightString(192 * mm, 10 * mm, f"Page {document.page}")
    canvas.restoreState()


def build_incident_pdf(event: DetectionEvent, analyst_report: str | None = None) -> bytes:
    """Generate a portable SOC incident report without writing server-local files."""
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title=f"SOC Incident Report - {event.category}",
        author="Sentinel NID SOC",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SocTitle", parent=styles["Title"], textColor=colors.HexColor("#0B5D47"), alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="SocHeading", parent=styles["Heading2"], textColor=colors.HexColor("#0B5D47"), spaceBefore=10))
    styles.add(ParagraphStyle(name="SocBody", parent=styles["BodyText"], leading=14, spaceAfter=5))

    stats = event.statistics or {}
    story = [
        Paragraph("SENTINEL NID SOC", styles["SocTitle"]),
        Paragraph("Incident Analysis Report", styles["Title"]),
        Paragraph(
            f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            styles["SocBody"],
        ),
        Spacer(1, 6),
        Table(
            [
                ["Classification", event.category],
                ["Severity", event.severity],
                ["Source", event.source_display],
                ["Destination", event.destination_display],
                ["Traffic scope", event.traffic_scope],
                ["Packets", str(event.rows)],
                ["Decision support", f"{event.confidence:.1%}"],
                ["Model threat score", f"{event.attack_probability:.1%}"],
                ["Threat intelligence", f"{event.threat_score:.0f}%"],
                ["Threat provider", str(stats.get("threat_intel_provider", "Local"))],
                ["Country / organization", f"{event.source_country} / {stats.get('threat_intel_organization', 'Unknown')}"],
                ["MITRE techniques", str(stats.get("mitre_technique_ids", "None"))],
                ["Protocol summary", str(stats.get("protocol_summary", "Unknown"))],
                ["Destination service", f"{stats.get('top_destination_port', 0)} / {stats.get('port_service', 'Unknown')}"],
                ["Notification status", str(stats.get("notification_status", "Not requested"))],
            ],
            colWidths=[48 * mm, 115 * mm],
        ),
        Spacer(1, 12),
        Paragraph("Evidence", styles["SocHeading"]),
    ]
    story[-3].setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8F4F0")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#0B5D47")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#A8C7BD")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    for reason in event.reasons or ["No specific detection reason recorded."]:
        story.append(Paragraph(f"- {escape(str(reason))}", styles["SocBody"]))

    story.append(Paragraph("Threat Intelligence", styles["SocHeading"]))
    for label in event.threat_labels or ["No reputation labels available."]:
        story.append(Paragraph(f"- {escape(str(label))}", styles["SocBody"]))

    story.append(Paragraph("Model Evidence", styles["SocHeading"]))
    feature_rows = [["Feature", "Importance", "Direction", "Method"]]
    for item in (event.top_features or [])[:8]:
        feature_rows.append(
            [
                str(item.get("feature", "Unknown")),
                f"{float(item.get('importance', 0)):.1%}",
                str(item.get("direction", "Unknown")),
                str(item.get("method", "evidence")),
            ]
        )
    if len(feature_rows) == 1:
        feature_rows.append(["No feature evidence", "-", "-", "-"])
    feature_table = Table(feature_rows, colWidths=[52 * mm, 28 * mm, 45 * mm, 38 * mm])
    feature_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B5D47")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#A8C7BD")),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(feature_table)

    story.extend([PageBreak(), Paragraph("AI Security Analyst Assessment", styles["SocHeading"])])
    report = analyst_report or local_security_analyst_report(event)
    for line in report.splitlines():
        cleaned = line.strip().lstrip("#").strip()
        if not cleaned:
            story.append(Spacer(1, 5))
        elif line.startswith("#"):
            story.append(Paragraph(escape(cleaned), styles["SocHeading"]))
        else:
            story.append(Paragraph(escape(cleaned), styles["SocBody"]))

    document.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return output.getvalue()
