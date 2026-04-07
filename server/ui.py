"""Custom Gradio UI for the Security Alert Investigation environment."""

from __future__ import annotations

import json
from pathlib import Path

import gradio as gr


TASKS = json.loads(
    (Path(__file__).resolve().parents[1] / "data" / "tasks.json").read_text(
        encoding="utf-8"
    )
)
TASK_IDS = [""] + [task["task_id"] for task in TASKS]


def build_security_ui(
    web_manager,
    action_fields,
    metadata,
    is_chat_env,
    title,
    quick_start_md,
):
    """Build a focused analyst console for the environment."""

    def _format_observation(result: dict, state: dict) -> tuple[str, ...]:
        observation = result.get("observation", {})
        alert = observation.get("alert", {})
        return (
            observation.get("task_id", ""),
            observation.get("difficulty", ""),
            alert.get("message", ""),
            alert.get("ip_address", ""),
            "\n".join(observation.get("history", [])) or "Not revealed yet",
            observation.get("ip_reputation", "") or "Not revealed yet",
            observation.get("frequency", "") or "Not revealed yet",
            observation.get("user_context", "") or "Not revealed yet",
            observation.get("asset_criticality", "") or "Not revealed yet",
            ", ".join(observation.get("steps_taken", [])) or "None",
            str(result.get("reward")),
            str(observation.get("score")),
            str(result.get("done")),
            str(state.get("step_count", 0)),
            str(state.get("max_steps", 4)),
            json.dumps(state, indent=2),
        )

    async def handle_reset(difficulty: str, task_id: str):
        payload: dict[str, str] = {}
        if difficulty and difficulty != "auto":
            payload["difficulty"] = difficulty
        if task_id:
            payload["task_id"] = task_id
        result = await web_manager.reset_environment(payload)
        return _format_observation(result, web_manager.get_state())

    async def handle_action(action_type: str):
        result = await web_manager.step_environment({"action_type": action_type})
        return _format_observation(result, web_manager.get_state())

    async def handle_submit(classification: str, priority: str, decision: str):
        result = await web_manager.step_environment(
            {
                "action_type": "submit_decision",
                "decision": {
                    "classification": classification,
                    "priority": priority,
                    "decision": decision,
                },
            }
        )
        return _format_observation(result, web_manager.get_state())

    with gr.Blocks() as demo:
        gr.Markdown(f"## {title}")
        gr.Markdown(
            "Review the alert, reveal evidence deliberately, and submit a final SOC decision."
        )

        with gr.Row():
            difficulty = gr.Dropdown(
                choices=["auto", "easy", "medium", "hard"],
                value="auto",
                label="Difficulty",
                scale=1,
            )
            task_id = gr.Dropdown(
                choices=TASK_IDS,
                value="",
                label="Task ID Override",
                scale=2,
            )
            reset_btn = gr.Button("Reset Case", variant="primary", scale=1)

        with gr.Row():
            task_out = gr.Textbox(label="Task ID", interactive=False)
            difficulty_out = gr.Textbox(label="Difficulty", interactive=False)
            reward_out = gr.Textbox(label="Last Reward", interactive=False)
            score_out = gr.Textbox(label="Final Score", interactive=False)
            done_out = gr.Textbox(label="Done", interactive=False)

        with gr.Row():
            with gr.Column(scale=2):
                alert_message = gr.Textbox(
                    label="Alert Message", lines=4, interactive=False
                )
                ip_address = gr.Textbox(label="IP Address", interactive=False)
                history = gr.Textbox(label="History", lines=6, interactive=False)
                ip_reputation = gr.Textbox(
                    label="IP Reputation", lines=4, interactive=False
                )
                frequency = gr.Textbox(label="Frequency", lines=4, interactive=False)
                user_context = gr.Textbox(
                    label="User Context", lines=4, interactive=False
                )
                asset_criticality = gr.Textbox(
                    label="Asset Criticality", lines=4, interactive=False
                )

            with gr.Column(scale=1):
                gr.Markdown("### Investigation")
                check_history_btn = gr.Button("Check History")
                analyze_ip_btn = gr.Button("Analyze IP")
                check_frequency_btn = gr.Button("Check Frequency")
                check_user_context_btn = gr.Button("Check User Context")
                check_asset_criticality_btn = gr.Button("Check Asset Criticality")

                gr.Markdown("### Final Decision")
                classification = gr.Dropdown(
                    choices=["benign", "suspicious", "malicious"],
                    value="suspicious",
                    label="Classification",
                )
                priority = gr.Dropdown(
                    choices=["low", "medium", "high", "critical"],
                    value="medium",
                    label="Priority",
                )
                decision = gr.Dropdown(
                    choices=["close", "monitor", "escalate", "contain"],
                    value="monitor",
                    label="Decision",
                )
                submit_btn = gr.Button("Submit Final Decision", variant="primary")

        with gr.Row():
            steps_taken = gr.Textbox(label="Steps Taken", interactive=False)
            step_count = gr.Textbox(label="Step Count", interactive=False)
            max_steps = gr.Textbox(label="Max Steps", interactive=False)

        state_json = gr.Code(label="State JSON", language="json", interactive=False)

        outputs = [
            task_out,
            difficulty_out,
            alert_message,
            ip_address,
            history,
            ip_reputation,
            frequency,
            user_context,
            asset_criticality,
            steps_taken,
            reward_out,
            score_out,
            done_out,
            step_count,
            max_steps,
            state_json,
        ]

        reset_btn.click(handle_reset, inputs=[difficulty, task_id], outputs=outputs)
        check_history_btn.click(
            fn=lambda: handle_action("check_history"),
            outputs=outputs,
        )
        analyze_ip_btn.click(
            fn=lambda: handle_action("analyze_ip"),
            outputs=outputs,
        )
        check_frequency_btn.click(
            fn=lambda: handle_action("check_frequency"),
            outputs=outputs,
        )
        check_user_context_btn.click(
            fn=lambda: handle_action("check_user_context"),
            outputs=outputs,
        )
        check_asset_criticality_btn.click(
            fn=lambda: handle_action("check_asset_criticality"),
            outputs=outputs,
        )
        submit_btn.click(
            handle_submit,
            inputs=[classification, priority, decision],
            outputs=outputs,
        )

    return demo
