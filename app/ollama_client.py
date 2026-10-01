import json
import re
from typing import Any

import httpx
from pydantic import ValidationError

from app.config import OLLAMA_MODEL, OLLAMA_URL
from app.schemas import AIAnalysisOut

JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)

SYSTEM_PROMPT = (
    "You are a SOC analyst. Respond with JSON only. No markdown. "
    "Schema: {\"summary\": string, \"likely_intent\": string, "
    "\"recommended_actions\": [string], \"confidence\": \"low|medium|high\"}."
)


def sanitize_evidence(evidence: dict[str, Any] | list[Any]) -> dict[str, Any]:
    raw = json.dumps(evidence)
    raw = re.sub(r"(password|secret|token|api[_-]?key)\s*[:=]\s*\S+", r"\1=***", raw, flags=re.I)
    if len(raw) > 4000:
        raw = raw[:4000] + "...truncated"
    return {"sanitized_evidence": raw}


def _force_json(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = JSON_BLOCK_RE.search(text)
        if not match:
            raise ValueError("Ollama did not return JSON")
        return json.loads(match.group(0))


def analyze_alert(rule_name: str, evidence: dict[str, Any] | list[Any]) -> AIAnalysisOut:
    payload = sanitize_evidence(evidence)
    prompt = (
        f"{SYSTEM_PROMPT}\nRule: {rule_name}\nEvidence: {json.dumps(payload)}"
    )
    body = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0},
    }
    with httpx.Client(timeout=60.0) as client:
        response = client.post(OLLAMA_URL, json=body)
        response.raise_for_status()
        output = response.json().get("response", "")
    parsed = _force_json(output)
    try:
        return AIAnalysisOut.model_validate(parsed)
    except ValidationError as exc:
        raise ValueError(f"AI JSON failed validation: {exc}") from exc
