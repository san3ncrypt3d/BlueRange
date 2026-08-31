import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from bluerange.agents import LLMDefenderAgent, MockModelProvider
from bluerange.environment import Environment
from bluerange.models import AgentContext, AutonomyLevel, BenchmarkResult, Observation, ToolCall
from bluerange.orchestrator import run_benchmark, semantic_fingerprint
from bluerange.scenarios import ScenarioError, load_ground_truth, load_scenario
from bluerange.tools import ToolController


def test_tool_arguments_reject_extras_and_redact_invalid_values() -> None:
    controller = ToolController(
        Environment(load_scenario("scenarios/identity_compromise")), AutonomyLevel.A3, "agent"
    )
    result = controller.invoke(
        ToolCall(name="search_logs", arguments={"query": "alice", "secret": "do-not-log"}), 1
    )
    assert not result.success
    audit = controller.history[0]
    assert audit.arguments == {"query": "[invalid]", "secret": "[invalid]"}
    assert "do-not-log" not in audit.model_dump_json()


@pytest.mark.parametrize("filename", ["scenario.yaml", "telemetry.json", "ground_truth.protected.yaml"])
def test_scenario_inputs_reject_unknown_fields(tmp_path: Path, filename: str) -> None:
    source = Path("scenarios/identity_compromise")
    for item in source.iterdir():
        (tmp_path / item.name).write_bytes(item.read_bytes())
    target = tmp_path / filename
    if filename.endswith(".json"):
        value = json.loads(target.read_text())
        value[0]["unexpected"] = True
        target.write_text(json.dumps(value))
    else:
        target.write_text(target.read_text() + "\nunexpected: true\n")
    with pytest.raises(ScenarioError):
        (load_ground_truth if filename.startswith("ground") else load_scenario)(tmp_path)


def test_llm_output_rejects_unknown_fields() -> None:
    agent = LLMDefenderAgent(
        MockModelProvider(
            ['{"tool":"search_logs","arguments":{"query":"alice"},"untrusted":true}']
        )
    )
    agent.reset(AgentContext(scenario_id="scenario", autonomy=AutonomyLevel.A2, seed=42))
    decision = agent.step(Observation(step=1, events=[]), ())
    assert decision.tool_calls == [] and "malformed" in decision.conclusion.lower()


def test_result_invariants_and_semantic_fingerprint() -> None:
    first = run_benchmark("identity-compromise-001", "baseline", "A2", 42)
    second = run_benchmark("identity-compromise-001", "baseline", "A2", 42)
    assert semantic_fingerprint(first) == semantic_fingerprint(second) == first.semantic_fingerprint
    assert sum(category.maximum for category in first.categories) == 100
    assert first.final_score == sum(category.score for category in first.categories)
    raw = first.model_dump()
    raw["final_score"] += 1
    with pytest.raises(ValidationError):
        BenchmarkResult.model_validate(raw)


@pytest.mark.parametrize("value", ["", "x" * 501])
def test_queries_have_safe_length_bounds(value: str) -> None:
    controller = ToolController(
        Environment(load_scenario("scenarios/identity_compromise")), AutonomyLevel.A3, "agent"
    )
    assert not controller.invoke(ToolCall(name="search_logs", arguments={"query": value}), 1).success
