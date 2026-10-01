import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from app.config import REPORT_DIR, TEMPLATES_DIR
from app.models import Alert, Case


def _env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
    )


def render_html(case: Case, alerts: list[Alert]) -> str:
    template = _env().get_template("report.html")
    rows = []
    for alert in alerts:
        rows.append(
            {
                "id": alert.id,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "host": alert.host,
                "src_ip": alert.src_ip,
                "timestamp": alert.timestamp,
                "status": alert.status,
                "mitre": f"{alert.mitre_technique_id} {alert.mitre_technique_name} ({alert.mitre_tactic})",
                "evidence": json.dumps(json.loads(alert.evidence_json), indent=2),
            }
        )
    return template.render(case=case, alerts=rows)


def write_html_report(case: Case, alerts: list[Alert]) -> Path:
    html = render_html(case, alerts)
    path = Path(REPORT_DIR) / f"case-{case.id}.html"
    path.write_text(html, encoding="utf-8")
    return path


def write_pdf_report(case: Case, alerts: list[Alert]) -> Path:
    path = Path(REPORT_DIR) / f"case-{case.id}.pdf"
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"SentinelForge Case Report #{case.id}", styles["Title"]),
        Paragraph(f"Title: {case.title}", styles["Heading2"]),
        Paragraph(f"Status: {case.status}", styles["Normal"]),
        Paragraph(f"Notes: {case.notes or 'None'}", styles["Normal"]),
        Spacer(1, 12),
    ]
    for alert in alerts:
        story.append(Paragraph(f"Alert {alert.id}: {alert.rule_name}", styles["Heading3"]))
        story.append(Paragraph(f"Severity: {alert.severity} | Status: {alert.status}", styles["Normal"]))
        story.append(
            Paragraph(
                f"MITRE: {alert.mitre_technique_id} {alert.mitre_technique_name} / {alert.mitre_tactic}",
                styles["Normal"],
            )
        )
        story.append(Paragraph(f"Host: {alert.host} | IP: {alert.src_ip} | Time: {alert.timestamp}", styles["Normal"]))
        story.append(Spacer(1, 8))
    doc = SimpleDocTemplate(str(path), pagesize=letter)
    doc.build(story)
    return path
