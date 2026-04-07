"""Typed models for the Security Alert Investigation environment."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from openenv.core.env_server.types import Action, Observation, State
from pydantic import BaseModel, Field, model_validator


class Difficulty(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class Classification(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Priority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    CLOSE = "close"
    MONITOR = "monitor"
    ESCALATE = "escalate"
    CONTAIN = "contain"


class AlertModel(BaseModel):
    message: str = Field(..., description="Human-readable alert summary.")
    ip_address: str = Field(..., description="Source IP associated with the alert.")


class DecisionPayload(BaseModel):
    classification: Classification
    priority: Priority
    decision: Decision


class RewardBreakdown(BaseModel):
    step_reward: float = Field(default=0.0, description="Dense reward from the current step.")
    final_reward: float = Field(
        default=0.0, description="Deterministic final grader score applied on submission."
    )
    total_reward: float = Field(default=0.0, description="Total reward returned for the step.")


class StepInfo(BaseModel):
    result: str = Field(..., description="Machine-readable step outcome.")
    repeated_action: bool = False
    invalid_action: bool = False
    max_steps_exceeded: bool = False
    grader_components: dict[str, float] = Field(default_factory=dict)
    narrative: str = ""


class ExpectedInvestigation(BaseModel):
    recommended_actions: list[str] = Field(default_factory=list)
    minimum_actions_before_submit: int = Field(default=3, ge=0)


class InvestigationAction(Action):
    action_type: str = Field(..., description="Investigation action to perform.")
    decision: DecisionPayload | None = Field(
        default=None,
        description="Final decision payload when action_type is submit_decision.",
    )

    @model_validator(mode="after")
    def validate_submit_payload(self) -> "InvestigationAction":
        if self.action_type == "submit_decision" and self.decision is None:
            raise ValueError("decision is required for submit_decision")
        if self.action_type != "submit_decision" and self.decision is not None:
            raise ValueError("decision is only allowed for submit_decision")
        return self


class InvestigationObservation(Observation):
    alert: AlertModel
    history: list[str] = Field(default_factory=list)
    ip_reputation: str = ""
    frequency: str = ""
    user_context: str = ""
    asset_criticality: str = ""
    steps_taken: list[str] = Field(default_factory=list)
    task_id: str = Field(..., description="Active task identifier.")
    difficulty: Difficulty
    score: float | None = Field(default=None, ge=0.0, le=1.0)
    reward_details: RewardBreakdown = Field(default_factory=RewardBreakdown)
    info: StepInfo = Field(
        default_factory=lambda: StepInfo(result="ready"),
        description="Structured info payload for the most recent step.",
    )


class InvestigationState(State):
    task_id: str | None = None
    difficulty: Difficulty | None = None
    steps_taken: list[str] = Field(default_factory=list)
    history_revealed: bool = False
    ip_reputation_revealed: bool = False
    frequency_revealed: bool = False
    user_context_revealed: bool = False
    asset_criticality_revealed: bool = False
    done: bool = False
    final_score: float | None = Field(default=None, ge=0.0, le=1.0)
    last_reward: float = 0.0
    max_steps: int = Field(default=4, ge=1)


class TaskRecord(BaseModel):
    task_id: str
    difficulty: Difficulty
    alert: AlertModel
    history: list[str]
    ip_reputation: str
    frequency: str
    user_context: str
    asset_criticality: str
    expected_decision: DecisionPayload
    expected_investigation: ExpectedInvestigation
    narrative: str = Field(..., description="Human explanation of the ground truth.")


class ResetOptions(BaseModel):
    difficulty: Difficulty | None = None
    task_id: str | None = None


class ResetResponseEnvelope(BaseModel):
    observation: InvestigationObservation
    reward: float | None
    done: bool


class StepResponseEnvelope(BaseModel):
    observation: InvestigationObservation
    reward: float | None
    done: bool


AllowedActionLiteral = Literal[
    "check_history",
    "analyze_ip",
    "check_frequency",
    "check_user_context",
    "check_asset_criticality",
    "submit_decision",
]


def observation_to_text(observation: InvestigationObservation) -> dict[str, Any]:
    return {
        "task_id": observation.task_id,
        "difficulty": observation.difficulty.value,
        "alert": observation.alert.model_dump(),
        "history": observation.history,
        "ip_reputation": observation.ip_reputation,
        "frequency": observation.frequency,
        "user_context": observation.user_context,
        "asset_criticality": observation.asset_criticality,
        "steps_taken": observation.steps_taken,
        "done": observation.done,
        "reward": observation.reward,
        "score": observation.score,
    }
