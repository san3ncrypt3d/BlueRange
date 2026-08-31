from collections.abc import Sequence

from bluerange.agents import DefenderAgent
from bluerange.models import AgentContext, Decision, Observation
from bluerange.orchestrator import run_benchmark


class RecordingAdvisor(DefenderAgent):
    """Record observations received by an A0 advisor."""

    id = "recording-advisor"

    def reset(self, context: AgentContext) -> None:
        self.steps: list[int] = []

    def step(self, observation: Observation, tools: Sequence[str]) -> Decision:
        self.steps.append(observation.step)
        assert tools == ()
        return Decision(conclusion="Recommendation only")


def test_a0_receives_initial_observation_only() -> None:
    """A0 cannot gain information from progression or execute tools."""
    advisor = RecordingAdvisor()
    result = run_benchmark("identity-compromise-001", advisor.id, "A0", 42, agent=advisor)
    assert advisor.steps == [1]
    assert result.tool_history == [] and result.actions == []
