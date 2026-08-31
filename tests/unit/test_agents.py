from bluerange.agents import LLMDefenderAgent, MockModelProvider
from bluerange.models import AgentContext, AutonomyLevel, Observation


def test_mock_llm_emits_typed_action_and_malformed_output_fails_closed() -> None:
    context = AgentContext(scenario_id="scenario", autonomy=AutonomyLevel.A2, seed=42)
    good = LLMDefenderAgent(
        MockModelProvider(['{"tool":"search_logs","arguments":{"query":"alice"}}'])
    )
    good.reset(context)
    assert good.step(Observation(step=1, events=[]), ()).tool_calls[0].name == "search_logs"
    bad = LLMDefenderAgent(MockModelProvider(["revoke everything"]))
    bad.reset(context)
    decision = bad.step(Observation(step=1, events=[]), ())
    assert decision.tool_calls == [] and "malformed" in decision.conclusion.lower()
