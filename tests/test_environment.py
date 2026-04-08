from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROJECT_ROOT.parent
VENV_SITE_PACKAGES = WORKSPACE_ROOT / ".venv" / "Lib" / "site-packages"

if str(VENV_SITE_PACKAGES) not in sys.path:
    sys.path.insert(0, str(VENV_SITE_PACKAGES))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient

from server.app import app


client = TestClient(app)


def test_reset_and_state_endpoint_work() -> None:
    reset_response = client.post("/reset", json={"task_id": "easy_malicious_bruteforce"})
    assert reset_response.status_code == 200
    reset_payload = reset_response.json()
    assert reset_payload["observation"]["task_id"] == "easy_malicious_bruteforce"
    assert reset_payload["reward"] == 0.0

    state_response = client.get("/state")
    assert state_response.status_code == 200
    state_payload = state_response.json()
    assert state_payload["task_id"] == "easy_malicious_bruteforce"
    assert state_payload["step_count"] == 0


def test_dense_rewards_and_info_are_reported() -> None:
    client.post("/reset", json={"task_id": "easy_malicious_bruteforce"})

    first = client.post("/step", json={"action": {"action_type": "check_history"}})
    assert first.status_code == 200
    first_payload = first.json()
    assert first_payload["reward"] == 0.2
    assert first_payload["observation"]["info"]["result"] == "history_revealed"

    repeated = client.post("/step", json={"action": {"action_type": "check_history"}})
    assert repeated.status_code == 200
    repeated_payload = repeated.json()
    assert repeated_payload["reward"] == -0.1
    assert repeated_payload["observation"]["info"]["result"] == "repeated_action"

    invalid = client.post("/step", json={"action": {"action_type": "nonsense_action"}})
    assert invalid.status_code == 200
    invalid_payload = invalid.json()
    assert invalid_payload["reward"] == -0.2
    assert invalid_payload["observation"]["info"]["invalid_action"] is True

    user_context = client.post("/step", json={"action": {"action_type": "check_user_context"}})
    assert user_context.status_code == 200
    user_payload = user_context.json()
    assert user_payload["observation"]["user_context"] != ""

    asset = client.post(
        "/step", json={"action": {"action_type": "check_asset_criticality"}}
    )
    assert asset.status_code == 200
    asset_payload = asset.json()
    assert asset_payload["observation"]["asset_criticality"] != ""


def test_all_three_tasks_grade_deterministically() -> None:
    expected = {
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

    for task_id, decision in expected.items():
        client.post("/reset", json={"task_id": task_id})
        client.post("/step", json={"action": {"action_type": "check_history"}})
        client.post("/step", json={"action": {"action_type": "analyze_ip"}})
        client.post("/step", json={"action": {"action_type": "check_frequency"}})
        client.post("/step", json={"action": {"action_type": "check_user_context"}})
        client.post(
            "/step", json={"action": {"action_type": "check_asset_criticality"}}
        )
        result = client.post(
            "/step",
            json={
                "action": {
                    "action_type": "submit_decision",
                    "decision": decision,
                }
            },
        )
        assert result.status_code == 200
        payload = result.json()
        assert payload["done"] is True
        assert payload["observation"]["score"] == 0.99
        assert payload["observation"]["info"]["grader_components"]["classification"] == 0.3
        assert payload["observation"]["info"]["grader_components"]["priority"] == 0.2
        assert payload["observation"]["info"]["grader_components"]["decision"] == 0.2
        assert (
            payload["observation"]["info"]["grader_components"]["investigation_completeness"]
            == 0.2
        )
        assert payload["observation"]["info"]["grader_components"]["efficiency"] >= 0.05
