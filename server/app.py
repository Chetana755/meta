"""FastAPI app for the Security Alert Investigation environment."""

from __future__ import annotations

from openenv.core.env_server.http_server import create_app

try:
    from ..models import InvestigationAction, InvestigationObservation
    from .security_alert_investigation_environment import (
        SecurityAlertInvestigationEnvironment,
    )
    from .ui import build_security_ui
except ImportError:
    from models import InvestigationAction, InvestigationObservation  # type: ignore
    from server.security_alert_investigation_environment import (  # type: ignore
        SecurityAlertInvestigationEnvironment,
    )
    from server.ui import build_security_ui  # type: ignore


_ENVIRONMENT = SecurityAlertInvestigationEnvironment()


def _get_environment() -> SecurityAlertInvestigationEnvironment:
    """Return the shared environment instance used by HTTP reset/step/state routes."""
    return _ENVIRONMENT


app = create_app(
    _get_environment,
    InvestigationAction,
    InvestigationObservation,
    env_name="security_alert_investigation",
    max_concurrent_envs=1,
    gradio_builder=build_security_ui,
)


def main(host: str = "0.0.0.0", port: int = 8000) -> None:
    import uvicorn

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
