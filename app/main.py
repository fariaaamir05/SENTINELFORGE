import json

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy.orm import Session

from app.db import get_db, init_db
from app.detection import sync_rules_to_db
from app.ingest import ingest_upload
from app.iocs import extract_from_evidence
from app.models import Alert, Case, CaseAlert, Event, Rule
from app.ollama_client import analyze_alert
from app.reports import write_html_report, write_pdf_report
from app.schemas import (
    AlertOut,
    AlertStatusUpdate,
    CaseAlertAttach,
    CaseCreate,
    CaseNoteAdd,
    CaseOut,
    CaseStatusUpdate,
    UploadResponse,
)

app = FastAPI(title="SentinelForge", version="0.1.0")


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    db = next(get_db())
    try:
        sync_rules_to_db(db)
    finally:
        db.close()


def _alert_out(alert: Alert) -> AlertOut:
    event_ids = json.loads(alert.event_ids or "[]")
    analysis = json.loads(alert.ai_analysis_json) if alert.ai_analysis_json else None
    return AlertOut(
        id=alert.id,
        rule_name=alert.rule_name,
        severity=alert.severity,
        host=alert.host,
        src_ip=alert.src_ip,
        timestamp=alert.timestamp,
        status=alert.status,
        mitre_technique_id=alert.mitre_technique_id,
        mitre_technique_name=alert.mitre_technique_name,
        mitre_tactic=alert.mitre_tactic,
        evidence=json.loads(alert.evidence_json),
        event_ids=event_ids,
        ai_analysis=analysis,
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/logs/upload", response_model=UploadResponse)
async def upload_logs(file: UploadFile = File(...), db: Session = Depends(get_db)):
    upload, events, alerts = await ingest_upload(db, file)
    return UploadResponse(
        upload_id=upload.id,
        filename=upload.filename,
        sha256=upload.sha256,
        log_type=upload.log_type,
        events_stored=len(events),
        alerts_generated=len(alerts),
    )


@app.get("/api/events")
def list_events(db: Session = Depends(get_db)):
    rows = db.query(Event).order_by(Event.id.desc()).limit(500).all()
    return [
        {
            "id": row.id,
            "log_type": row.log_type,
            "timestamp": row.timestamp,
            "host": row.host,
            "src_ip": row.src_ip,
            "user": row.user,
            "process": row.process,
            "command_line": row.command_line,
            "status_code": row.status_code,
            "normalized": json.loads(row.normalized_json),
        }
        for row in rows
    ]


@app.get("/api/rules")
def list_rules(db: Session = Depends(get_db)):
    return [
        {
            "id": row.id,
            "name": row.name,
            "mitre_technique_id": row.mitre_technique_id,
            "enabled": bool(row.enabled),
        }
        for row in db.query(Rule).all()
    ]


@app.get("/api/alerts", response_model=list[AlertOut])
def list_alerts(db: Session = Depends(get_db)):
    return [_alert_out(row) for row in db.query(Alert).order_by(Alert.id.desc()).all()]


@app.get("/api/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_out(alert)


@app.patch("/api/alerts/{alert_id}", response_model=AlertOut)
def update_alert(alert_id: int, body: AlertStatusUpdate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    allowed = {"new", "triaged", "confirmed", "false_positive", "closed"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail="Invalid status")
    alert.status = body.status
    db.commit()
    db.refresh(alert)
    return _alert_out(alert)


@app.get("/api/alerts/{alert_id}/iocs")
def alert_iocs(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return extract_from_evidence(json.loads(alert.evidence_json))


@app.post("/api/alerts/{alert_id}/analyze")
def analyze(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    try:
        result = analyze_alert(alert.rule_name, json.loads(alert.evidence_json))
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Ollama analysis failed: {exc}") from exc
    alert.ai_analysis_json = result.model_dump_json()
    db.commit()
    return result


@app.post("/api/cases", response_model=CaseOut)
def create_case(body: CaseCreate, db: Session = Depends(get_db)):
    case = Case(title=body.title, notes=body.notes, status="open")
    db.add(case)
    db.commit()
    db.refresh(case)
    return CaseOut(id=case.id, title=case.title, status=case.status, notes=case.notes, alert_ids=[])


@app.post("/api/cases/{case_id}/alerts", response_model=CaseOut)
def attach_alerts(case_id: int, body: CaseAlertAttach, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    for alert_id in body.alert_ids:
        if not db.get(Alert, alert_id):
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
        exists = (
            db.query(CaseAlert)
            .filter(CaseAlert.case_id == case_id, CaseAlert.alert_id == alert_id)
            .first()
        )
        if not exists:
            db.add(CaseAlert(case_id=case_id, alert_id=alert_id))
    db.commit()
    return _case_out(db, case)


@app.patch("/api/cases/{case_id}", response_model=CaseOut)
def update_case(case_id: int, body: CaseStatusUpdate, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    allowed = {"open", "investigating", "contained", "closed"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail="Invalid case status")
    case.status = body.status
    db.commit()
    db.refresh(case)
    return _case_out(db, case)


@app.post("/api/cases/{case_id}/notes", response_model=CaseOut)
def add_note(case_id: int, body: CaseNoteAdd, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    prefix = f"{case.notes}\n" if case.notes else ""
    case.notes = f"{prefix}- {body.note}"
    db.commit()
    db.refresh(case)
    return _case_out(db, case)


@app.get("/api/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: int, db: Session = Depends(get_db)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return _case_out(db, case)


@app.get("/api/reports/{case_id}/html")
def report_html(case_id: int, db: Session = Depends(get_db)):
    case, alerts = _case_with_alerts(db, case_id)
    path = write_html_report(case, alerts)
    return HTMLResponse(path.read_text(encoding="utf-8"))


@app.get("/api/reports/{case_id}/pdf")
def report_pdf(case_id: int, db: Session = Depends(get_db)):
    case, alerts = _case_with_alerts(db, case_id)
    path = write_pdf_report(case, alerts)
    return FileResponse(path, media_type="application/pdf", filename=path.name)


def _case_alert_ids(db: Session, case_id: int) -> list[int]:
    return [row.alert_id for row in db.query(CaseAlert).filter(CaseAlert.case_id == case_id).all()]


def _case_out(db: Session, case: Case) -> CaseOut:
    return CaseOut(
        id=case.id,
        title=case.title,
        status=case.status,
        notes=case.notes,
        alert_ids=_case_alert_ids(db, case.id),
    )


def _case_with_alerts(db: Session, case_id: int) -> tuple[Case, list[Alert]]:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    ids = _case_alert_ids(db, case_id)
    alerts = db.query(Alert).filter(Alert.id.in_(ids)).all() if ids else []
    return case, alerts
