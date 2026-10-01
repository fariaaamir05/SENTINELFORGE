import json
import os
import tempfile
from pathlib import Path

os.environ["SENTINELFORGE_DB"] = str(Path(tempfile.mkdtemp()) / "sentinelforge-test.db")

from fastapi.testclient import TestClient

from app.db import init_db
from app.iocs import extract_iocs
from app.main import app
from app.parsers import parse_logs

client = TestClient(app)
SAMPLE_DIR = Path(__file__).resolve().parent.parent / "samples"


def setup_module() -> None:
    Path(os.environ["SENTINELFORGE_DB"]).parent.mkdir(parents=True, exist_ok=True)
    init_db()


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_sha256_and_sysmon_detections():
    path = SAMPLE_DIR / "sysmon_malicious.json"
    response = client.post("/api/logs/upload", files={"file": ("sysmon.json", path.read_bytes(), "application/json")})
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["sha256"]) == 64
    assert body["events_stored"] == 8
    assert body["alerts_generated"] >= 3
    alerts = client.get("/api/alerts").json()
    names = {item["rule_name"] for item in alerts}
    assert "Repeated failed login attempts" in names
    assert "Suspicious PowerShell command" in names
    assert "Encoded PowerShell" in names
    assert "Office application spawning PowerShell or CMD" in names
    encoded = next(item for item in alerts if item["rule_name"] == "Encoded PowerShell")
    assert encoded["mitre_technique_id"] == "T1027"
    assert encoded["mitre_tactic"] == "Defense Evasion"
    assert encoded["severity"] == "critical"


def test_web_scan_and_cases_and_reports():
    path = SAMPLE_DIR / "nginx_access.log"
    response = client.post("/api/logs/upload", files={"file": ("access.log", path.read_bytes(), "text/plain")})
    assert response.status_code == 200, response.text
    alerts = client.get("/api/alerts").json()
    scan = next(item for item in alerts if "404" in item["rule_name"])
    case = client.post("/api/cases", json={"title": "Web scan", "notes": "initial"}).json()
    attached = client.post(f"/api/cases/{case['id']}/alerts", json={"alert_ids": [scan["id"]]}).json()
    assert scan["id"] in attached["alert_ids"]
    updated = client.patch(f"/api/cases/{case['id']}", json={"status": "investigating"}).json()
    assert updated["status"] == "investigating"
    noted = client.post(f"/api/cases/{case['id']}/notes", json={"note": "Blocked source IP"}).json()
    assert "Blocked source IP" in noted["notes"]
    html = client.get(f"/api/reports/{case['id']}/html")
    assert html.status_code == 200
    assert "SentinelForge" in html.text
    pdf = client.get(f"/api/reports/{case['id']}/pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"].startswith("application/pdf")


def test_benign_sample_false_positive_check():
    before = {item["id"] for item in client.get("/api/alerts").json()}
    path = SAMPLE_DIR / "sysmon_benign.json"
    response = client.post("/api/logs/upload", files={"file": ("benign.json", path.read_bytes(), "application/json")})
    assert response.status_code == 200
    after = client.get("/api/alerts").json()
    new_alerts = [item for item in after if item["id"] not in before]
    assert new_alerts == []


def test_ioc_extractor():
    found = extract_iocs("connect 10.1.2.3 to http://evil.example.com/a.exe hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert "10.1.2.3" in found["ip_addresses"]
    assert "http://evil.example.com/a.exe" in found["urls"]
    assert any(item.endswith("example.com") for item in found["domains"])
    assert found["hashes"]


def test_parser_normalizes_sysmon():
    raw = json.dumps([{"EventID": 1, "Image": "cmd.exe", "CommandLine": "cmd /c whoami", "Computer": "HOST"}])
    events = parse_logs("sysmon_json", raw, "abc")
    assert events[0]["process"] == "cmd.exe"
    assert events[0]["host"] == "HOST"
    assert events[0]["file_hash"] == "abc"
