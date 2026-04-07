"""Environment implementation for SOC alert investigation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import EnvironmentMetadata

try:
    from ..models import (
        Difficulty,
        InvestigationAction,
        InvestigationObservation,
        InvestigationState,
        RewardBreakdown,
        StepInfo,
        TaskRecord,
    )
except ImportError:
    from models import (  # type: ignore
        Difficulty,
        InvestigationAction,
        InvestigationObservation,
        InvestigationState,
        RewardBreakdown,
        StepInfo,
        TaskRecord,
    )


class SecurityAlertInvestigationEnvironment(
    Environment[InvestigationAction, InvestigationObservation, InvestigationState]
):
    """Deterministic investigation environment with dense rewards."""

    SUPPORTS_CONCURRENT_SESSIONS = True
    MAX_STEPS = 6

    def __init__(self) -> None:
        super().__init__()
        self._tasks = self._load_tasks()
        self._task_cycle = {
            Difficulty.EASY: 0,
            Difficulty.MEDIUM: 0,
            Difficulty.HARD: 0,
        }
        self._ordered_tasks = {
            difficulty: [task for task in self._tasks if task.difficulty == difficulty]
            for difficulty in Difficulty
        }
        self._current_task: TaskRecord | None = None
        self._state = InvestigationState(episode_id=str(uuid4()), max_steps=self.MAX_STEPS)

    def reset(
        self,
        seed: int | None = None,
        episode_id: str | None = None,
        **kwargs: Any,
    ) -> InvestigationObservation:
        options = kwargs
        task_id = options.get("task_id")
        difficulty = options.get("difficulty")
        self._current_task = self._select_task(task_id=task_id, difficulty=difficulty)
        self._state = InvestigationState(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
            task_id=self._current_task.task_id,
            difficulty=self._current_task.difficulty,
            steps_taken=[],
            history_revealed=False,
            ip_reputation_revealed=False,
            frequency_revealed=False,
            user_context_revealed=False,
            asset_criticality_revealed=False,
            done=False,
            final_score=None,
            last_reward=0.0,
            max_steps=self.MAX_STEPS,
        )
        return self._build_observation(reward=0.0, score=None, done=False)

    def step(
        self,
        action: InvestigationAction,
        timeout_s: float | None = None,
        **kwargs: Any,
    ) -> InvestigationObservation:
        if self._current_task is None:
            self.reset()

        assert self._current_task is not None

        if self._state.done:
            return self._build_observation(
                reward=-0.2,
                score=self._state.final_score,
                done=True,
                info=StepInfo(
                    result="episode_already_completed",
                    invalid_action=True,
                    narrative="The episode has already ended. Reset before taking more actions.",
                ),
            )

        self._state.step_count += 1
        reward = 0.0
        action_name = action.action_type
        repeated = action_name in self._state.steps_taken
        info = StepInfo(
            result="pending",
            repeated_action=repeated,
            narrative=self._current_task.narrative,
        )

        if repeated:
            reward = -0.1
            info.result = "repeated_action"
        elif action_name == "check_history":
            self._state.history_revealed = True
            self._state.steps_taken.append(action_name)
            reward = 0.2
            info.result = "history_revealed"
        elif action_name == "analyze_ip":
            self._state.ip_reputation_revealed = True
            self._state.steps_taken.append(action_name)
            reward = 0.2
            info.result = "ip_reputation_revealed"
        elif action_name == "check_frequency":
            self._state.frequency_revealed = True
            self._state.steps_taken.append(action_name)
            reward = 0.2
            info.result = "frequency_revealed"
        elif action_name == "check_user_context":
            self._state.user_context_revealed = True
            self._state.steps_taken.append(action_name)
            reward = 0.2
            info.result = "user_context_revealed"
        elif action_name == "check_asset_criticality":
            self._state.asset_criticality_revealed = True
            self._state.steps_taken.append(action_name)
            reward = 0.2
            info.result = "asset_criticality_revealed"
        elif action_name == "submit_decision":
            self._state.steps_taken.append(action_name)
            score, components = self._grade(action)
            reward = score
            self._state.final_score = score
            self._state.done = True
            self._state.last_reward = reward
            return self._build_observation(
                reward=reward,
                score=score,
                done=True,
                info=StepInfo(
                    result="submitted",
                    grader_components=components,
                    narrative=self._current_task.narrative,
                ),
            )
        else:
            reward = -0.2
            info.result = "invalid_action"
            info.invalid_action = True

        if not self._state.done and self._state.step_count >= self.MAX_STEPS:
            self._state.done = True
            self._state.final_score = 0.0
            reward = -0.3
            info.result = "max_steps_exceeded"
            info.max_steps_exceeded = True

        self._state.last_reward = reward
        return self._build_observation(
            reward=reward,
            score=self._state.final_score,
            done=self._state.done,
            info=info,
        )

    @property
    def state(self) -> InvestigationState:
        return self._state

    def state_snapshot(self) -> InvestigationState:
        return self._state

    def get_metadata(self) -> EnvironmentMetadata:
        return EnvironmentMetadata(
            name="Security Alert Investigation Environment",
            description="Investigate SOC alerts through staged evidence gathering and deterministic scoring.",
            version="1.0.0",
            author="Codex",
        )

    def _build_observation(
        self,
        reward: float,
        score: float | None,
        done: bool,
        info: StepInfo | None = None,
    ) -> InvestigationObservation:
        assert self._current_task is not None
        step_reward = 0.0 if done and score is not None else reward
        final_reward = score or 0.0
        return InvestigationObservation(
            alert=self._current_task.alert,
            history=self._current_task.history if self._state.history_revealed else [],
            ip_reputation=(
                self._current_task.ip_reputation if self._state.ip_reputation_revealed else ""
            ),
            frequency=self._current_task.frequency if self._state.frequency_revealed else "",
            user_context=(
                self._current_task.user_context if self._state.user_context_revealed else ""
            ),
            asset_criticality=(
                self._current_task.asset_criticality
                if self._state.asset_criticality_revealed
                else ""
            ),
            steps_taken=list(self._state.steps_taken),
            done=done,
            reward=reward,
            metadata={"narrative": self._current_task.narrative},
            task_id=self._current_task.task_id,
            difficulty=self._current_task.difficulty,
            score=score,
            reward_details=RewardBreakdown(
                step_reward=step_reward,
                final_reward=final_reward,
                total_reward=reward,
            ),
            info=info or StepInfo(result="ready", narrative=self._current_task.narrative),
        )

    def _grade(self, action: InvestigationAction) -> tuple[float, dict[str, float]]:
        assert self._current_task is not None
        assert action.decision is not None
        expected = self._current_task.expected_decision
        expected_investigation = self._current_task.expected_investigation
        recommended = set(expected_investigation.recommended_actions)
        gathered = set(
            action_name
            for action_name in self._state.steps_taken
            if action_name != "submit_decision"
        )
        components = {
            "classification": 0.0,
            "priority": 0.0,
            "decision": 0.0,
            "investigation_completeness": 0.0,
            "efficiency": 0.0,
        }
        if action.decision.classification == expected.classification:
            components["classification"] = 0.3
        if action.decision.priority == expected.priority:
            components["priority"] = 0.2
        if action.decision.decision == expected.decision:
            components["decision"] = 0.2
        if recommended:
            completeness_ratio = len(gathered & recommended) / len(recommended)
            components["investigation_completeness"] = round(0.2 * completeness_ratio, 2)
        if len(gathered) == expected_investigation.minimum_actions_before_submit:
            components["efficiency"] = 0.1
        elif len(gathered) > expected_investigation.minimum_actions_before_submit:
            components["efficiency"] = 0.05
        elif len(gathered) == max(expected_investigation.minimum_actions_before_submit - 1, 0):
            components["efficiency"] = 0.02
        score = round(min(max(sum(components.values()), 0.0), 1.0), 2)
        return score, components

    def _select_task(
        self,
        task_id: str | None,
        difficulty: str | Difficulty | None,
    ) -> TaskRecord:
        if task_id:
            for task in self._tasks:
                if task.task_id == task_id:
                    return task
            raise ValueError(f"Unknown task_id: {task_id}")

        if difficulty is None:
            bucket = self._ordered_tasks[Difficulty.EASY]
            index = self._task_cycle[Difficulty.EASY] % len(bucket)
            self._task_cycle[Difficulty.EASY] += 1
            return bucket[index]

        resolved = difficulty if isinstance(difficulty, Difficulty) else Difficulty(difficulty)
        bucket = self._ordered_tasks[resolved]
        index = self._task_cycle[resolved] % len(bucket)
        self._task_cycle[resolved] += 1
        return bucket[index]

    @staticmethod
    def _load_tasks() -> list[TaskRecord]:
        data_path = Path(__file__).resolve().parents[1] / "data" / "tasks.json"
        payload = json.loads(data_path.read_text(encoding="utf-8"))
        return [TaskRecord.model_validate(item) for item in payload]
