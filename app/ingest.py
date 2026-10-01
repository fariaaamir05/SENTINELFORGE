import json
from pathlib import Path

from fastapi import HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import MAX_UPLOAD_BYTES, UPLOAD_DIR
from app.detection import run_detection, sync_rules_to_db
from app.hashing import sha256_bytes
from app.models import Event, Upload
from app.parsers import detect_log_type, parse_logs


def store_events(db: Session, upload: Upload, parsed: list[dict]) -> list[Event]:
    stored = []
    for item in parsed:
        event = Event(
            upload_id=upload.id,
            file_hash=upload.sha256,
            log_type=item.get("log_type") or upload.log_type,
            timestamp=item.get("timestamp"),
            host=item.get("host") or None,
            src_ip=item.get("src_ip") or None,
            user=item.get("user") or None,
            process=item.get("process") or None,
            parent_process=item.get("parent_process") or None,
            command_line=item.get("command_line") or None,
            event_id=item.get("event_id") or None,
            status_code=item.get("status_code") or None,
            http_method=item.get("http_method") or None,
            http_path=item.get("http_path") or None,
            normalized_json=json.dumps(item),
        )
        db.add(event)
        stored.append(event)
    db.commit()
    for event in stored:
        db.refresh(event)
    return stored


async def ingest_upload(db: Session, file: UploadFile):
    sync_rules_to_db(db)
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large")
    digest = sha256_bytes(data)
    filename = file.filename or "upload.bin"
    dest = Path(UPLOAD_DIR) / f"{digest}_{filename}"
    dest.write_bytes(data)
    text = data.decode("utf-8", errors="replace")
    log_type = detect_log_type(filename, text[:4000])
    parsed = parse_logs(log_type, text, digest)
    if not parsed:
        raise HTTPException(status_code=400, detail="No parseable events found")
    upload = Upload(
        filename=filename,
        sha256=digest,
        log_type=log_type,
        byte_size=len(data),
    )
    db.add(upload)
    db.commit()
    db.refresh(upload)
    events = store_events(db, upload, parsed)
    alerts = run_detection(db, events)
    return upload, events, alerts
