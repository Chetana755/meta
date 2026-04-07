"""Optional typed client for the Security Alert Investigation environment."""

from __future__ import annotations

from typing import Any

from openenv.core import EnvClient
from openenv.core.client_types import StepResult

try:
    from .models import InvestigationAction, InvestigationObservation, InvestigationState
except ImportError:
    from models import (  # type: ignore
        InvestigationAction,
        InvestigationObservation,
        InvestigationState,
    )


class SecurityAlertInvestigationEnv(
    EnvClient[InvestigationAction, InvestigationObservation, InvestigationState]
):
    def _step_payload(self, action: InvestigationAction) -> dict[str, Any]:
        return action.model_dump(mode="json")

    def _parse_result(self, payload: dict[str, Any]) -> StepResult[InvestigationObservation]:
        observation = InvestigationObservation.model_validate(payload.get("observation", {}))
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: dict[str, Any]) -> InvestigationState:
        return InvestigationState.model_validate(payload)
