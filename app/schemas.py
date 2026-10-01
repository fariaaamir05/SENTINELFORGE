from pydantic import BaseModel, Field


class UploadResponse(BaseModel):
    upload_id: int
    filename: str
    sha256: str
    log_type: str
    events_stored: int
    alerts_generated: int


class AlertOut(BaseModel):
    id: int
    rule_name: str
    severity: str
    host: str | None
    src_ip: str | None
    timestamp: str | None
    status: str
    mitre_technique_id: str | None
    mitre_technique_name: str | None
    mitre_tactic: str | None
    evidence: dict | list
    event_ids: list[int]
    ai_analysis: dict | None = None


class AlertStatusUpdate(BaseModel):
    status: str


class CaseCreate(BaseModel):
    title: str
    notes: str = ""


class CaseAlertAttach(BaseModel):
    alert_ids: list[int] = Field(min_length=1)


class CaseStatusUpdate(BaseModel):
    status: str


class CaseNoteAdd(BaseModel):
    note: str


class CaseOut(BaseModel):
    id: int
    title: str
    status: str
    notes: str
    alert_ids: list[int]


class AIAnalysisOut(BaseModel):
    summary: str
    likely_intent: str
    recommended_actions: list[str]
    confidence: str
