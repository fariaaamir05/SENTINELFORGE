import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
DB_PATH = Path(os.environ.get("SENTINELFORGE_DB", DATA_DIR / "sentinelforge.db"))
RULES_DIR = BASE_DIR / "rules"
MITRE_PATH = DATA_DIR / "mitre_attack.json"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

SQLITE_URL = f"sqlite:///{DB_PATH.as_posix()}"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "llama3.2"
MAX_UPLOAD_BYTES = 20 * 1024 * 1024

for path in (DATA_DIR, UPLOAD_DIR, REPORT_DIR):
    path.mkdir(parents=True, exist_ok=True)
