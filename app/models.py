from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Upload(Base):
    __tablename__ = "uploads"

    id = Column(Integer, primary_key=True)
    filename = Column(String(512), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    log_type = Column(String(64), nullable=False)
    byte_size = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    events = relationship("Event", back_populates="upload")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    upload_id = Column(Integer, ForeignKey("uploads.id"), nullable=False)
    file_hash = Column(String(64), nullable=False, index=True)
    log_type = Column(String(64), nullable=False)
    timestamp = Column(String(64), nullable=True)
    host = Column(String(256), nullable=True)
    src_ip = Column(String(64), nullable=True)
    user = Column(String(256), nullable=True)
    process = Column(String(512), nullable=True)
    parent_process = Column(String(512), nullable=True)
    command_line = Column(Text, nullable=True)
    event_id = Column(String(64), nullable=True)
    status_code = Column(String(16), nullable=True)
    http_method = Column(String(16), nullable=True)
    http_path = Column(Text, nullable=True)
    normalized_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    upload = relationship("Upload", back_populates="events")


class Rule(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True)
    name = Column(String(256), unique=True, nullable=False)
    yaml_path = Column(String(512), nullable=False)
    mitre_technique_id = Column(String(32), nullable=True)
    enabled = Column(Integer, default=1, nullable=False)
    yaml_content = Column(Text, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    rule_name = Column(String(256), nullable=False, index=True)
    severity = Column(String(32), nullable=False)
    host = Column(String(256), nullable=True)
    src_ip = Column(String(64), nullable=True)
    timestamp = Column(String(64), nullable=True)
    evidence_json = Column(Text, nullable=False)
    status = Column(String(32), default="new", nullable=False)
    mitre_technique_id = Column(String(32), nullable=True)
    mitre_technique_name = Column(String(256), nullable=True)
    mitre_tactic = Column(String(256), nullable=True)
    event_ids = Column(Text, nullable=True)
    ai_analysis_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True)
    title = Column(String(512), nullable=False)
    status = Column(String(32), default="open", nullable=False)
    notes = Column(Text, default="", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class CaseAlert(Base):
    __tablename__ = "case_alerts"

    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
