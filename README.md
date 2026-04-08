---
title: Security Alert Investigation Environment
emoji: 🤖
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

An OpenEnv-compatible benchmark that simulates SOC alert triage. The agent receives a security alert, investigates using staged evidence-gathering actions, submits a final decision, and receives a deterministic score strictly inside the range `(0, 1)`.

## Overview

This environment is built around realistic analyst workflow rather than a toy puzzle. At reset time the agent only sees the base alert. Additional evidence must be gathered step by step before submitting a final judgement.

The benchmark is designed to test:

- sequential reasoning
- evidence gathering
- structured final decision making
- reward-aware behavior
- reliable grading with deterministic scores

## Benchmark Summary

- Domain: security operations / alert triage
- Runtime: FastAPI + OpenEnv
- Tasks: `3`
- Difficulty levels: `easy`, `medium`, `hard`
- Max episode length: `6` steps
- Final score range: `(0, 1)`

## Tasks

Tasks are defined in [data/tasks.json](/Users/pavan/Desktop/open/security_alert_investigation/data/tasks.json).

- `easy_malicious_bruteforce`
  Clear hostile login activity against privileged finance identities. Expected outcome is malicious, critical, and containment-oriented.
- `medium_ambiguous_vendor_sync`
  Unusual cloud-origin automation with incomplete governance signals. Expected outcome is suspicious, medium priority, and monitor.
- `hard_misleading_low_volume_exfil`
  Low-volume service-account misuse from a normal-looking residential IP. Expected outcome is malicious, high priority, and escalate.

## Action Space

The typed action model is defined in [models.py](/Users/pavan/Desktop/open/security_alert_investigation/models.py).

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

Example:

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

The typed observation model is defined in [models.py](/Users/pavan/Desktop/open/security_alert_investigation/models.py).

Key fields:

- `alert`
- `history`
- `ip_reputation`
- `frequency`
- `user_context`
- `asset_criticality`
- `steps_taken`
- `task_id`
- `difficulty`
- `score`
- `reward_details`
- `info`

At reset, only the alert is visible. Investigation actions progressively reveal the remaining fields.

## Reward and Grading

The environment provides both dense rewards and deterministic final grading.

Step rewards:

- first-time valid action: `+0.2`
- repeated action: `-0.1`
- invalid action: `-0.2`
- max steps exceeded: `-0.3`

Final grading components:

- classification match: `0.3`
- priority match: `0.2`
- decision match: `0.2`
- investigation completeness: `0.2`
- efficiency: `0.1`

Total score is clipped to stay strictly inside `(0, 1)`.

The grader implementation lives in [server/security_alert_investigation_environment.py](/Users/pavan/Desktop/open/security_alert_investigation/server/security_alert_investigation_environment.py).

## OpenEnv Compliance

This project includes:

- [openenv.yaml](/Users/pavan/Desktop/open/security_alert_investigation/openenv.yaml)
- typed Pydantic action, observation, and state models
- `reset`
- `step`
- `state`
- FastAPI/OpenEnv server entrypoint in [server/app.py](/Users/pavan/Desktop/open/security_alert_investigation/server/app.py)

Validate locally:

```bash
openenv validate .
```

## Running Locally

From [security_alert_investigation](/Users/pavan/Desktop/open/security_alert_investigation):

```bash
python -m uvicorn server.app:app --host 0.0.0.0 --port 8000
```

Windows virtualenv example:

```bash
C:\Users\pavan\Desktop\open\.venv\Scripts\python.exe -m uvicorn server.app:app --host 0.0.0.0 --port 8000
```

Useful endpoints:

- `GET /health`
- `POST /reset`
- `POST /step`
- `GET /state`
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

## Docker

Build:

```bash
docker build -t openenv-security_alert_investigation .
```

Run:

```bash
docker run --rm -p 8000:8000 openenv-security_alert_investigation
```

## Inference

The submission baseline lives at [inference.py](/Users/pavan/Desktop/open/security_alert_investigation/inference.py).

It:

- uses the OpenAI Python client
- reads `API_BASE_URL`, `MODEL_NAME`, and `HF_TOKEN`
- supports `LOCAL_IMAGE_NAME` for Docker-image-based execution
- supports `ENV_BASE_URL` for connecting to a running environment
- emits strict one-line `[START]`, `[STEP]`, and `[END]` logs for evaluator parsing

### Required Environment Variables

- `API_BASE_URL`
- `MODEL_NAME`
- `HF_TOKEN`

Optional:

- `LOCAL_IMAGE_NAME`
- `ENV_BASE_URL`

Example `.env` values are provided in [.env.example](/Users/pavan/Desktop/open/security_alert_investigation/.env.example).

### Running Inference

Against a running local server:

```bash
python inference.py
```

With an explicit environment URL:

```bash
ENV_BASE_URL=http://localhost:8000 python inference.py
```

With a local Docker image:

```bash
LOCAL_IMAGE_NAME=openenv-security_alert_investigation python inference.py
```

### Output Format

The script emits exactly these line types:

```text
[START] task=<task_name> env=<benchmark> model=<model_name>
[STEP] step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
[END] success=<true|false> steps=<n> rewards=<r1,r2,...,rn>
```

## Baseline Result

Verified baseline scores:

- `easy_malicious_bruteforce`: `0.99`
- `medium_ambiguous_vendor_sync`: `0.99`
- `hard_misleading_low_volume_exfil`: `0.99`

## Deployment

This project is deployed as a Hugging Face Docker Space.

- Space page: `https://huggingface.co/spaces/krishnaSri56/security_alert_investigation`
- Live URL: `https://krishnasri56-security-alert-investigation.hf.space`
- GitHub repo: `https://github.com/Chetana755/meta`

For deployment/runtime configuration, set:

- `API_BASE_URL`
- `MODEL_NAME`
- `HF_TOKEN`
- `LOCAL_IMAGE_NAME` as optional support if running inference from a local Docker image

## Project Structure

- [openenv.yaml](/Users/pavan/Desktop/open/security_alert_investigation/openenv.yaml)
- [models.py](/Users/pavan/Desktop/open/security_alert_investigation/models.py)
- [client.py](/Users/pavan/Desktop/open/security_alert_investigation/client.py)
- [server/app.py](/Users/pavan/Desktop/open/security_alert_investigation/server/app.py)
- [server/security_alert_investigation_environment.py](/Users/pavan/Desktop/open/security_alert_investigation/server/security_alert_investigation_environment.py)
- [data/tasks.json](/Users/pavan/Desktop/open/security_alert_investigation/data/tasks.json)
- [Dockerfile](/Users/pavan/Desktop/open/security_alert_investigation/Dockerfile)
- [inference.py](/Users/pavan/Desktop/open/security_alert_investigation/inference.py)

## Tests

Smoke tests are included in [tests/test_environment.py](/Users/pavan/Desktop/open/security_alert_investigation/tests/test_environment.py).

Run:

```bash
pytest
```
