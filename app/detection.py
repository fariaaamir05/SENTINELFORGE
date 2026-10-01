import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session

from app.config import RULES_DIR
from app.mitre import map_technique
from app.models import Alert, Event, Rule


def load_yaml_rules() -> list[dict[str, Any]]:
    rules = []
    for path in sorted(Path(RULES_DIR).glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        data["_path"] = str(path)
        data["_filename"] = path.name
        rules.append(data)
    return rules


def sync_rules_to_db(db: Session) -> None:
    for rule in load_yaml_rules():
        existing = db.query(Rule).filter(Rule.name == rule["title"]).first()
        content = Path(rule["_path"]).read_text(encoding="utf-8")
        technique = (rule.get("mitre") or {}).get("technique_id")
        if existing:
            existing.yaml_content = content
            existing.yaml_path = rule["_path"]
            existing.mitre_technique_id = technique
            continue
        db.add(
            Rule(
                name=rule["title"],
                yaml_path=rule["_path"],
                mitre_technique_id=technique,
                yaml_content=content,
                enabled=1,
            )
        )
    db.commit()


def _haystack(event: Event) -> dict[str, str]:
    payload = json.loads(event.normalized_json)
    return {
        "process": (event.process or "").lower(),
        "parent": (event.parent_process or "").lower(),
        "command": (event.command_line or "").lower(),
        "failed_login": str(bool(payload.get("failed_login"))).lower(),
        "status_code": (event.status_code or ""),
        "src_ip": event.src_ip or "",
        "host": event.host or "",
        "user": event.user or "",
        "payload": payload,
    }


def _contains_any(text: str, needles: list[str]) -> bool:
    return any(needle.lower() in text for needle in needles)


def match_keyword(rule: dict[str, Any], event: Event) -> bool:
    det = rule["detection"]
    fields = _haystack(event)
    process_needles = det.get("process_contains") or []
    if process_needles and not _contains_any(fields["process"] + " " + fields["command"], process_needles):
        return False
    command_needles = det.get("command_contains_any") or []
    if command_needles and not _contains_any(fields["command"], command_needles):
        return False
    return bool(command_needles or process_needles)


def match_parent_child(rule: dict[str, Any], event: Event) -> bool:
    det = rule["detection"]
    fields = _haystack(event)
    parent_ok = _contains_any(fields["parent"], det.get("parent_contains") or [])
    child_ok = _contains_any(fields["process"] + " " + fields["command"], det.get("child_contains") or [])
    return parent_ok and child_ok


def _group_key(event: Event, fields: list[str]) -> str:
    parts = []
    for field in fields:
        parts.append(str(getattr(event, field, None) or json.loads(event.normalized_json).get(field) or "unknown"))
    return "|".join(parts)


def match_threshold(rule: dict[str, Any], events: list[Event]) -> list[list[Event]]:
    det = rule["detection"]
    field = det["field"]
    equals = det["equals"]
    min_count = int(det.get("count", 5))
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        payload = json.loads(event.normalized_json)
        if field == "failed_login":
            if not payload.get("failed_login"):
                continue
        else:
            value = getattr(event, field, None)
            if value is None:
                value = payload.get(field)
            if str(value) != str(equals):
                continue
        grouped[_group_key(event, det.get("group_by") or ["src_ip"])].append(event)
    hits = []
    for bucket in grouped.values():
        if len(bucket) >= min_count:
            hits.append(bucket)
    return hits


def _alert_from_events(rule: dict[str, Any], matched: list[Event]) -> Alert:
    first = matched[0]
    technique_id = (rule.get("mitre") or {}).get("technique_id")
    name, tactic = map_technique(technique_id)
    evidence = {
        "rule_id": rule.get("id"),
        "description": rule.get("description"),
        "match_count": len(matched),
        "events": [
            {
                "event_id": event.id,
                "timestamp": event.timestamp,
                "host": event.host,
                "src_ip": event.src_ip,
                "user": event.user,
                "process": event.process,
                "parent_process": event.parent_process,
                "command_line": (event.command_line or "")[:500],
                "status_code": event.status_code,
                "http_path": event.http_path,
            }
            for event in matched[:20]
        ],
    }
    return Alert(
        rule_name=rule["title"],
        severity=rule.get("severity", "medium"),
        host=first.host,
        src_ip=first.src_ip,
        timestamp=first.timestamp,
        evidence_json=json.dumps(evidence),
        status="new",
        mitre_technique_id=technique_id,
        mitre_technique_name=name,
        mitre_tactic=tactic,
        event_ids=json.dumps([event.id for event in matched]),
    )


def run_detection(db: Session, events: list[Event]) -> list[Alert]:
    if not events:
        return []
    alerts: list[Alert] = []
    for rule in load_yaml_rules():
        kind = rule.get("detection", {}).get("kind")
        if kind == "threshold":
            for bucket in match_threshold(rule, events):
                alerts.append(_alert_from_events(rule, bucket))
            continue
        matched = []
        for event in events:
            if kind == "keyword" and match_keyword(rule, event):
                matched.append(event)
            elif kind == "parent_child" and match_parent_child(rule, event):
                matched.append(event)
        if matched:
            alerts.append(_alert_from_events(rule, matched))
    for alert in alerts:
        db.add(alert)
    db.commit()
    for alert in alerts:
        db.refresh(alert)
    return alerts
