import json
import re
from datetime import datetime
from typing import Any

SYSLOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)(?: \S+)?" (?P<status>\d{3}) (?P<size>\S+)'
)


def _iso_now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def detect_log_type(filename: str, sample: str) -> str:
    lower = filename.lower()
    if lower.endswith(".json") or sample.lstrip().startswith("{") or sample.lstrip().startswith("["):
        return "sysmon_json"
    if SYSLOG_RE.search(sample) or "combined" in lower or "access" in lower or "nginx" in lower or "apache" in lower:
        return "web_access"
    if lower.endswith(".log") or lower.endswith(".txt"):
        return "web_access"
    return "sysmon_json"


def parse_logs(log_type: str, content: str, file_hash: str) -> list[dict[str, Any]]:
    if log_type == "sysmon_json":
        return parse_sysmon_json(content, file_hash)
    return parse_web_access(content, file_hash)


def parse_sysmon_json(content: str, file_hash: str) -> list[dict[str, Any]]:
    payload = _load_json_payload(content)
    events = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        events.append(_normalize_sysmon(item, file_hash))
    return events


def _load_json_payload(content: str) -> list[Any]:
    text = content.strip()
    if not text:
        return []
    try:
        loaded = json.loads(text)
        if isinstance(loaded, list):
            return loaded
        if isinstance(loaded, dict):
            if isinstance(loaded.get("Events"), list):
                return loaded["Events"]
            return [loaded]
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
        return rows
    return []


def _normalize_sysmon(item: dict[str, Any], file_hash: str) -> dict[str, Any]:
    event_id = str(item.get("EventID") or item.get("Id") or item.get("event_id") or "")
    command = str(item.get("CommandLine") or item.get("command_line") or "")
    image = str(item.get("Image") or item.get("process") or item.get("ProcessName") or "")
    parent = str(item.get("ParentImage") or item.get("parent_process") or "")
    host = str(item.get("Computer") or item.get("host") or item.get("Hostname") or "")
    user = str(item.get("User") or item.get("user") or "")
    src_ip = str(item.get("SourceIp") or item.get("src_ip") or item.get("IpAddress") or "")
    timestamp = str(item.get("UtcTime") or item.get("TimeCreated") or item.get("timestamp") or _iso_now())
    status = str(item.get("Status") or item.get("status") or item.get("TargetUserName") or "")
    if item.get("EventType") == "failed_login" or item.get("logon_type") == "failed":
        event_id = event_id or "4625"
    normalized = {
        "log_type": "sysmon_json",
        "file_hash": file_hash,
        "timestamp": timestamp,
        "host": host,
        "src_ip": src_ip,
        "user": user or str(item.get("TargetUserName") or ""),
        "process": image,
        "parent_process": parent,
        "command_line": command,
        "event_id": event_id,
        "status_code": str(item.get("status_code") or ""),
        "http_method": "",
        "http_path": "",
        "message": str(item.get("Message") or item.get("message") or ""),
        "event_type": str(item.get("EventType") or item.get("event_type") or ""),
        "raw": {k: v for k, v in item.items() if k != "raw"},
    }
    if "failed" in normalized["event_type"].lower() or event_id in {"4625", "4771"}:
        normalized["failed_login"] = True
    if str(item.get("failed_login")).lower() in {"true", "1", "yes"}:
        normalized["failed_login"] = True
    if status.lower() in {"failed", "failure"}:
        normalized["failed_login"] = True
    return normalized


def parse_web_access(content: str, file_hash: str) -> list[dict[str, Any]]:
    events = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = SYSLOG_RE.search(line)
        if not match:
            continue
        events.append(
            {
                "log_type": "web_access",
                "file_hash": file_hash,
                "timestamp": match.group("time"),
                "host": "",
                "src_ip": match.group("ip"),
                "user": "",
                "process": "",
                "parent_process": "",
                "command_line": "",
                "event_id": "",
                "status_code": match.group("status"),
                "http_method": match.group("method"),
                "http_path": match.group("path"),
                "message": line,
                "raw": {"line": line},
            }
        )
    return events
