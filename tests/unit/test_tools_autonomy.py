import pytest
from pydantic import ValidationError

from bluerange.environment import Environment
from bluerange.models import AutonomyLevel, ToolCall
from bluerange.scenarios import load_scenario
from bluerange.tools import ToolController


@pytest.mark.parametrize(
    ("level", "tool", "allowed"),
    [
        ("A0", "search_logs", False),
        ("A1", "search_logs", True),
        ("A1", "revoke_session", False),
        ("A2", "revoke_session", True),
        ("A2", "disable_identity", False),
        ("A3", "disable_identity", True),
    ],
)
def test_autonomy_is_enforced_and_every_attempt_audited(
    level: str, tool: str, allowed: bool
) -> None:
    scenario = load_scenario("scenarios/identity_compromise")
    env = Environment(scenario)
    controller = ToolController(env, AutonomyLevel(level), "test-agent")
    args = (
        {"query": "alice"}
        if tool == "search_logs"
        else ({"session_id": "sess-alice"} if tool == "revoke_session" else {"identity_id": "bob"})
    )
    result = controller.invoke(ToolCall(name=tool, arguments=args), step=1)
    assert result.success is allowed
    assert len(controller.history) == 1
    assert controller.history[0].success is allowed
    assert controller.history[0].denial_reason is None if allowed else True


def test_a2_disable_requires_represented_approval() -> None:
    env = Environment(load_scenario("scenarios/identity_compromise"))
    controller = ToolController(env, AutonomyLevel.A2, "agent", human_approval=True)
    result = controller.invoke(
        ToolCall(name="disable_identity", arguments={"identity_id": "bob"}), step=1
    )
    assert result.success and env.identities["bob"].disabled


def test_typed_arguments_and_prohibited_calls_fail_closed_and_audit() -> None:
    env = Environment(load_scenario("scenarios/identity_compromise"))
    controller = ToolController(env, AutonomyLevel.A3, "agent")
    bad = controller.invoke(ToolCall(name="revoke_session", arguments={"wrong": 1}), step=1)
    # Simulate an untrusted caller bypassing normal Pydantic construction: the
    # control layer must still deny and audit it.
    forbidden = controller.invoke(
        ToolCall.model_construct(name="shell", arguments={"cmd": "id"}), step=2
    )
    assert not bad.success and not forbidden.success and len(controller.history) == 2
    assert env.sessions["sess-alice"].active


def test_tool_call_name_is_typed() -> None:
    with pytest.raises(ValidationError):
        ToolCall(name="not-a-tool", arguments={})
