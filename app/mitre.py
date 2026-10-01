import json
from pathlib import Path

from app.config import MITRE_PATH

_CACHE: dict[str, dict] | None = None


def load_mitre() -> dict[str, dict]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    data = json.loads(Path(MITRE_PATH).read_text(encoding="utf-8"))
    _CACHE = {item["technique_id"]: item for item in data["techniques"]}
    return _CACHE


def map_technique(technique_id: str | None) -> tuple[str | None, str | None]:
    if not technique_id:
        return None, None
    item = load_mitre().get(technique_id)
    if not item:
        return None, None
    return item.get("name"), item.get("tactic")
