import pytest  # type: ignore
from src.agent.state import SentinelState
from src.agent.workflow import create_agent_workflow

def test_sentinel_state_initialization():
    state = SentinelState()
    assert state is not None

def test_agent_app_creation():
    app = create_agent_workflow()
    assert app is not None
    assert hasattr(app, "invoke")
