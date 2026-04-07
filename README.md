---
title: Security Alert Investigation Environment
emoji: robot
colorFrom: blue
colorTo: red
sdk: docker
app_port: 8000
pinned: false
tags:
  - openenv
  - security
  - agents
  - fastapi
---

# Security Alert Investigation Environment

## Overview

This project is an OpenEnv-compatible environment that simulates a real Security Operations Center workflow. An agent receives a security alert, investigates it through multiple evidence-gathering actions, submits a final decision, and receives a deterministic score from `0.0` to `1.0`.

The task is intentionally modeled after real analyst work rather than a game or synthetic puzzle. Human SOC analysts routinely review alert context, investigate source IPs, compare event frequency, and decide whether to close, monitor, escalate, or contain a case.

## Motivation

Security alert triage is a realistic agent benchmark because it combines:

- incomplete information at reset time
- sequential evidence gathering
- structured final judgment
- partial progress rewards
- deterministic final grading

This makes it useful for evaluating whether an agent can follow an investigation process rather than only producing a final label.

## Environment Summary

- Domain: SOC alert investigation
- Runtime: FastAPI OpenEnv server
- Difficulty levels: `easy`, `medium`, `hard`
- Number of tasks: `3`
- Episode limit: `6` steps
- Final score range: `0.0` to `1.0`

## Task Set

Tasks are stored in [data/tasks.json](/Users/pavan/Desktop/open/security_alert_investigation/data/tasks.json), not hardcoded in the environment class.

### Easy

- Task ID: `easy_malicious_bruteforce`
- Pattern: obvious hostile login and credential abuse
- Expected analyst outcome: clearly malicious, urgent, containment-oriented

### Medium

- Task ID: `medium_ambiguous_vendor_sync`
- Pattern: cloud-origin automation that looks unusual but may be legitimate
- Expected analyst outcome: suspicious but not severe enough for containment

### Hard

- Task ID: `hard_misleading_low_volume_exfil`
- Pattern: low-volume behavior from a normal-looking residential IP that hides risky service-account misuse
- Expected analyst outcome: malicious and high priority despite weak reputation signals

## Action Space

The action model is defined in [models.py](/Users/pavan/Desktop/open/security_alert_investigation/models.py).

Top-level action schema:

- `action_type: str`
- `decision: DecisionPayload | null`

Allowed `action_type` values:

- `check_history`
- `analyze_ip`
- `check_frequency`
- `check_user_context`
- `check_asset_criticality`
- `submit_decision`

`submit_decision` requires:

- `classification`: `benign | suspicious | malicious`
- `priority`: `low | medium | high | critical`
- `decision`: `close | monitor | escalate | contain`

Example step payload:

```json
{
  "action": {
    "action_type": "submit_decision",
    "decision": {
      "classification": "malicious",
      "priority": "critical",
      "decision": "contain"
    }
  }
}
```

## Observation Space

The observation model is defined in [models.py](/Users/pavan/Desktop/open/security_alert_investigation/models.py).

Fields returned to the agent:

- `alert`
  - `message`
  - `ip_address`
- `history`
- `ip_reputation`
- `frequency`
- `user_context`
- `asset_criticality`
- `steps_taken`
- `task_id`
- `difficulty`
- `done`
- `reward`
- `score`
- `reward_details`
  - `step_reward`
  - `final_reward`
  - `total_reward`
- `info`
  - `result`
  - `repeated_action`
  - `invalid_action`
  - `max_steps_exceeded`
  - `grader_components`
  - `narrative`

At reset, only the base alert is visible. The other evidence fields are progressively revealed by investigation actions.

## State Space

The state model is defined in [models.py](/Users/pavan/Desktop/open/security_alert_investigation/models.py).

State includes:

- `episode_id`
- `step_count`
- `task_id`
- `difficulty`
- `steps_taken`
- `history_revealed`
- `ip_reputation_revealed`
- `frequency_revealed`
- `user_context_revealed`
- `asset_criticality_revealed`
- `done`
- `final_score`
- `last_reward`
- `max_steps`

## Reward Function

The environment provides dense trajectory rewards plus deterministic final grading.

Step rewards:

- first-time valid action: `+0.2`
- repeated action: `-0.1`
- invalid action: `-0.2`
- max steps exceeded: `-0.3`

Final reward:

- equals the deterministic grader score on `submit_decision`

This produces useful signal before the end of the episode and penalizes bad interaction patterns.
Submitting before enough investigation steps also reduces the final grade because the grader now measures investigation completeness and efficiency in addition to the final label.

## Grader

The grader is deterministic and implemented in [server/security_alert_investigation_environment.py](/Users/pavan/Desktop/open/security_alert_investigation/server/security_alert_investigation_environment.py).

Score components:

- classification match: `0.3`
- priority match: `0.2`
- decision match: `0.2`
- investigation completeness: `0.2`
- efficiency: `0.1`

Total score is always clipped to `0.0..1.0`.

## OpenEnv Compliance

The project includes:

- typed Pydantic `Action`, `Observation`, `RewardBreakdown`, and `State` models
- `reset`
- `step`
- `state`
- [openenv.yaml](/Users/pavan/Desktop/open/security_alert_investigation/openenv.yaml)
- FastAPI endpoints:
  - `POST /reset`
  - `POST /step`
  - `GET /state`

Local validation:

```bash
openenv validate .
```

## Running Locally

From [security_alert_investigation](/Users/pavan/Desktop/open/security_alert_investigation):

```bash
python -m uvicorn server.app:app --host 0.0.0.0 --port 8000
```

If you want to force the workspace virtual environment on Windows:

```bash
C:\Users\pavan\Desktop\open\.venv\Scripts\python.exe -m uvicorn server.app:app --host 0.0.0.0 --port 8000
```

API endpoints:

- `POST /reset`
- `POST /step`
- `GET /state`
- `GET /health`
- `GET /metadata`
- `GET /schema`

Example reset:

```bash
curl -X POST http://localhost:8000/reset \
  -H "Content-Type: application/json" \
  -d "{\"task_id\":\"hard_misleading_low_volume_exfil\"}"
```

Example step:

```bash
curl -X POST http://localhost:8000/step \
  -H "Content-Type: application/json" \
  -d "{\"action\":{\"action_type\":\"check_history\"}}"
```

## Verification

### Check whether the environment server is running

Once the server is started, verify it with:

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status":"healthy"}
```

You can also verify the core API:

```bash
curl -X POST http://localhost:8000/reset -H "Content-Type: application/json" -d "{}"
curl http://localhost:8000/state
```

If the optional web interface is enabled:

```bash
curl http://localhost:8000/web
```

### Check whether Docker is running

On Windows PowerShell:

```bash
docker version
docker ps
```

If Docker Desktop is running correctly:

- `docker version` should return both client and server information
- `docker ps` should return a table instead of a daemon connection error

### Check whether the Dockerized environment is running

Build and run:

```bash
docker build -t security-alert-investigation .
docker run --rm -p 8000:8000 security-alert-investigation
```

In another terminal, verify:

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/reset -H "Content-Type: application/json" -d "{}"
```

## Docker

Build:

```bash
docker build -t security-alert-investigation .
```

Run:

```bash
docker run --rm -p 8000:8000 security-alert-investigation
```

The container starts the environment with:

```bash
uvicorn server.app:app --host 0.0.0.0 --port 8000
```

## Hugging Face Spaces Deployment

This project is structured for containerized deployment to a Hugging Face Space.

Requirements for deployment:

- Space SDK: Docker
- container entrypoint from [Dockerfile](/Users/pavan/Desktop/open/security_alert_investigation/Dockerfile)
- Space metadata/tagging to mark it as an OpenEnv environment

This repository is deployment-ready, but an actual HF Space push must still be performed separately.

## Baseline Inference

[inference.py](/Users/pavan/Desktop/open/security_alert_investigation/inference.py) uses the OpenAI Python client and supports:

- `OPENAI_API_KEY`
- `API_BASE_URL`
- `MODEL_NAME`
- `HF_TOKEN` for OpenAI-compatible providers such as Hugging Face Router

If no live provider credentials are available, the script falls back to a deterministic heuristic policy so the baseline still runs reproducibly on all three tasks.

Run:

```bash
python inference.py
```

Output behavior:

- runs all 3 tasks
- prints strict `[START]`, `[STEP]`, `[END]` blocks
- prints final JSON summary with per-task scores and average score

## Baseline Scores

Verified baseline scores from the current implementation:

- `easy_malicious_bruteforce`: `1.0`
- `medium_ambiguous_vendor_sync`: `1.0`
- `hard_misleading_low_volume_exfil`: `1.0`
- average score: `1.0`

These scores were verified with the deterministic fallback baseline policy. If a live model provider is used, scores may differ depending on provider output quality.

## Project Files

Core files:

- [openenv.yaml](/Users/pavan/Desktop/open/security_alert_investigation/openenv.yaml)
- [models.py](/Users/pavan/Desktop/open/security_alert_investigation/models.py)
- [server/app.py](/Users/pavan/Desktop/open/security_alert_investigation/server/app.py)
- [server/security_alert_investigation_environment.py](/Users/pavan/Desktop/open/security_alert_investigation/server/security_alert_investigation_environment.py)
- [data/tasks.json](/Users/pavan/Desktop/open/security_alert_investigation/data/tasks.json)
- [inference.py](/Users/pavan/Desktop/open/security_alert_investigation/inference.py)
- [Dockerfile](/Users/pavan/Desktop/open/security_alert_investigation/Dockerfile)

## Tests

Smoke tests are included in [tests/test_environment.py](/Users/pavan/Desktop/open/security_alert_investigation/tests/test_environment.py).

Run:

```bash
pytest
```
