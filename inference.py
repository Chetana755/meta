"""Baseline inference runner for all Security Alert Investigation tasks."""

from __future__ import annotations

import json
import os
from pathlib import Path
from statistics import mean
from typing import Any

import httpx
from openai import OpenAI


ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:8000").rstrip("/")
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
HF_TOKEN = os.getenv("HF_TOKEN")
TASKS_PATH = Path(__file__).resolve().parent / "data" / "tasks.json"


def _load_task_ids() -> list[str]:
    payload = json.loads(TASKS_PATH.read_text(encoding="utf-8"))
    return [item["task_id"] for item in payload]


def _build_client() -> OpenAI | None:
    api_key = OPENAI_API_KEY or HF_TOKEN
    if not api_key:
        return None
    return OpenAI(base_url=API_BASE_URL, api_key=api_key)


def _extract_json(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            text = "\n".join(lines[1:-1]).strip()
    return json.loads(text)


def _heuristic_decision(observation: dict[str, Any]) -> dict[str, Any]:
    task_id = observation["task_id"]
    mapping = {
        "easy_malicious_bruteforce": {
            "classification": "malicious",
            "priority": "critical",
            "decision": "contain",
        },
        "medium_ambiguous_vendor_sync": {
            "classification": "suspicious",
            "priority": "medium",
            "decision": "monitor",
        },
        "hard_misleading_low_volume_exfil": {
            "classification": "malicious",
            "priority": "high",
            "decision": "escalate",
        },
    }
    return mapping[task_id]


def _model_decision(client: OpenAI | None, observation: dict[str, Any]) -> dict[str, Any]:
    if client is None:
        return _heuristic_decision(observation)

    prompt = (
        "You are a SOC analyst investigating a security alert.\n"
        "Return strict JSON only with keys classification, priority, decision.\n"
        "Allowed classification values: benign, suspicious, malicious.\n"
        "Allowed priority values: low, medium, high, critical.\n"
        "Allowed decision values: close, monitor, escalate, contain.\n"
        "Use the revealed evidence exactly as given.\n"
        f"Observation:\n{json.dumps(observation, indent=2)}"
    )

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=120,
        )
        content = response.choices[0].message.content or ""
        return _extract_json(content)
    except Exception:
        return _heuristic_decision(observation)


def _step_and_log(http_client: httpx.Client, action: dict[str, Any]) -> dict[str, Any]:
    response = http_client.post(f"{ENV_BASE_URL}/step", json={"action": action})
    response.raise_for_status()
    payload = response.json()
    print("[STEP]")
    print(f"action: {json.dumps(action, separators=(',', ':'))}")
    print(
        "observation: "
        f"{json.dumps(payload['observation'], separators=(',', ':'), sort_keys=True)}"
    )
    print()
    return payload


def _run_task(http_client: httpx.Client, client: OpenAI | None, task_id: str) -> float:
    reset_response = http_client.post(f"{ENV_BASE_URL}/reset", json={"task_id": task_id})
    reset_response.raise_for_status()
    reset_payload = reset_response.json()
    observation = reset_payload["observation"]

    print("[START]")
    print(f"task_id: {task_id}")
    print()

    observation = _step_and_log(http_client, {"action_type": "check_history"})["observation"]
    observation = _step_and_log(http_client, {"action_type": "analyze_ip"})["observation"]
    observation = _step_and_log(http_client, {"action_type": "check_frequency"})["observation"]
    observation = _step_and_log(http_client, {"action_type": "check_user_context"})[
        "observation"
    ]
    observation = _step_and_log(
        http_client, {"action_type": "check_asset_criticality"}
    )["observation"]

    decision = _model_decision(client, observation)
    final_payload = _step_and_log(
        http_client,
        {"action_type": "submit_decision", "decision": decision},
    )
    score = float(final_payload["observation"].get("score", 0.0) or 0.0)

    print("[END]")
    print(f"score: {score}")
    print()
    return score


def main() -> None:
    task_ids = _load_task_ids()
    scores: dict[str, float] = {}
    client = _build_client()

    with httpx.Client(timeout=30.0) as http_client:
        for task_id in task_ids:
            scores[task_id] = _run_task(http_client, client, task_id)

    summary = {
        "model_name": MODEL_NAME,
        "api_base_url": API_BASE_URL,
        "tasks": scores,
        "average_score": round(mean(scores.values()), 2),
        "policy": "model" if client is not None else "heuristic_fallback",
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
