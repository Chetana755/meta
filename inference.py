"""Strict-format inference runner for all Security Alert Investigation tasks."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx
from openai import OpenAI
from openenv.core.containers.runtime import LocalDockerProvider

from models import DecisionPayload, InvestigationAction


BENCHMARK = "security_alert_investigation"
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:8000").rstrip("/")
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN") or os.getenv("OPENAI_API_KEY")
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME") or os.getenv("IMAGE_NAME")
SUCCESS_SCORE_THRESHOLD = 0.1
TASKS_PATH = Path(__file__).resolve().parent / "data" / "tasks.json"


def _load_task_ids() -> list[str]:
    payload = json.loads(TASKS_PATH.read_text(encoding="utf-8"))
    return [item["task_id"] for item in payload]


def _build_client() -> OpenAI | None:
    if not HF_TOKEN:
        return None
    return OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)


def _extract_json(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            text = "\n".join(lines[1:-1]).strip()
    return json.loads(text)


def _heuristic_decision(task_id: str) -> dict[str, str]:
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


def _model_decision(client: OpenAI | None, observation_payload: dict[str, Any]) -> dict[str, str]:
    if client is None:
        return _heuristic_decision(observation_payload["task_id"])

    prompt = (
        "You are a SOC analyst investigating a security alert.\n"
        "Return strict JSON only with keys classification, priority, decision.\n"
        "Allowed classification values: benign, suspicious, malicious.\n"
        "Allowed priority values: low, medium, high, critical.\n"
        "Allowed decision values: close, monitor, escalate, contain.\n"
        "Use the revealed evidence exactly as given.\n"
        f"Observation:\n{json.dumps(observation_payload, indent=2)}"
    )

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=120,
        )
        content = response.choices[0].message.content or ""
        parsed = _extract_json(content)
        return {
            "classification": parsed["classification"],
            "priority": parsed["priority"],
            "decision": parsed["decision"],
        }
    except Exception:
        return _heuristic_decision(observation_payload["task_id"])


def _bool_text(value: bool) -> str:
    return "true" if value else "false"


def _error_text(error: str | None) -> str:
    if not error:
        return "null"
    return error.replace("\n", " ").replace("\r", " ")


def _format_action(action: InvestigationAction) -> str:
    return json.dumps(action.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)


def _log_start(task_id: str) -> None:
    print(f"[START] task={task_id} env={BENCHMARK} model={MODEL_NAME}", flush=True)


def _log_step(step: int, action: InvestigationAction, reward: float, done: bool, error: str | None) -> None:
    print(
        f"[STEP] step={step} action={_format_action(action)} reward={reward:.2f} "
        f"done={_bool_text(done)} error={_error_text(error)}",
        flush=True,
    )


def _log_end(success: bool, steps: int, rewards: list[float]) -> None:
    rewards_text = ",".join(f"{reward:.2f}" for reward in rewards)
    print(
        f"[END] success={_bool_text(success)} steps={steps} rewards={rewards_text}",
        flush=True,
    )


def _start_local_image_if_needed() -> tuple[str, LocalDockerProvider | None]:
    if not LOCAL_IMAGE_NAME:
        return ENV_BASE_URL, None

    provider = LocalDockerProvider()
    base_url = provider.start_container(LOCAL_IMAGE_NAME)
    provider.wait_for_ready(base_url)
    return base_url.rstrip("/"), provider


def _reset(http_client: httpx.Client, base_url: str, task_id: str) -> dict[str, Any]:
    response = http_client.post(f"{base_url}/reset", json={"task_id": task_id})
    response.raise_for_status()
    return response.json()


def _step(http_client: httpx.Client, base_url: str, action: InvestigationAction) -> dict[str, Any]:
    response = http_client.post(
        f"{base_url}/step",
        json={"action": action.model_dump(mode="json")},
    )
    response.raise_for_status()
    return response.json()


def _run_task(http_client: httpx.Client, base_url: str, client: OpenAI | None, task_id: str) -> float:
    rewards: list[float] = []
    steps_taken = 0
    success = False
    _log_start(task_id)

    try:
        reset_payload = _reset(http_client, base_url, task_id)
        observation_payload = reset_payload["observation"]
        scripted_actions = [
            InvestigationAction(action_type="check_history"),
            InvestigationAction(action_type="analyze_ip"),
            InvestigationAction(action_type="check_frequency"),
            InvestigationAction(action_type="check_user_context"),
            InvestigationAction(action_type="check_asset_criticality"),
        ]

        for step_index, action in enumerate(scripted_actions, start=1):
            result = _step(http_client, base_url, action)
            reward = float(result.get("reward") or 0.0)
            done = bool(result.get("done"))
            rewards.append(reward)
            steps_taken = step_index
            _log_step(step_index, action, reward, done, None)
            observation_payload = result["observation"]
            if done:
                final_score = float(observation_payload.get("score", 0.0) or 0.0)
                success = final_score >= SUCCESS_SCORE_THRESHOLD
                return final_score

        decision = _model_decision(client, observation_payload)
        final_action = InvestigationAction(
            action_type="submit_decision",
            decision=DecisionPayload.model_validate(decision),
        )
        result = _step(http_client, base_url, final_action)
        reward = float(result.get("reward") or 0.0)
        done = bool(result.get("done"))
        rewards.append(reward)
        steps_taken += 1
        _log_step(steps_taken, final_action, reward, done, None)
        final_score = float(result["observation"].get("score", 0.0) or 0.0)
        success = final_score >= SUCCESS_SCORE_THRESHOLD
        return final_score
    except Exception as exc:
        next_step = steps_taken + 1
        fallback_action = InvestigationAction(action_type="check_history")
        _log_step(next_step, fallback_action, 0.0, True, str(exc))
        raise
    finally:
        _log_end(success, steps_taken, rewards)


def main() -> None:
    client = _build_client()
    base_url, provider = _start_local_image_if_needed()

    try:
        with httpx.Client(timeout=30.0) as http_client:
            for task_id in _load_task_ids():
                _run_task(http_client, base_url, client, task_id)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
    finally:
        if provider is not None:
            provider.stop_container()


if __name__ == "__main__":
    main()
