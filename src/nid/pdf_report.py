from __future__ import annotations

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
                ["MITRE techniques", str(stats.get("mitre_technique_ids", "None"))],
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

    document.build(story)
    return output.getvalue()
