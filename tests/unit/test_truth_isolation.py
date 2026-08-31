import json

import pytest
from pydantic import BaseModel, ValidationError

import bluerange.scenarios as public_scenarios
from bluerange.environment import Environment
from bluerange.models import AgentContext, AutonomyLevel, ToolCall
from bluerange.orchestrator import run_benchmark
from bluerange.scenarios import load_scenario
from bluerange.tools import ToolController


def test_public_scenario_api_exports_no_truth_or_control_selection_surface() -> None:
    for name in (
        "build_instance",
        "ObservableInstance",
        "GroundTruth",
        "load_ground_truth",
    ):
        assert not hasattr(public_scenarios, name)


def test_supported_agent_surfaces_do_not_expose_truth_labels_or_nested_truth() -> None:
    scenario = load_scenario("scenarios/identity_compromise")
    environment = Environment(scenario)
    controller = ToolController(environment, AutonomyLevel.A2, "attacker")
    observation = environment.observe(2)
    tool_result = controller.invoke(
        ToolCall(
            name="inspect_identity", arguments={"identity_id": observation.events[0].identity_id}
        ),
        2,
    )
    context = AgentContext(scenario_id=scenario.id, autonomy=AutonomyLevel.A2, seed=712)
    surfaces = [
        scenario,
        environment.scenario,
        observation,
        tool_result,
        context,
        controller.history,
    ]
    exposed = "\n".join(_render(surface) for surface in surfaces).lower()
    for label in (
        "ground_truth",
        "compromised_identity",
        "compromised_sessions",
        "attack_steps",
        "attacker_final_objective_step",
        "legitimate_identities",
    ):
        assert label not in exposed
    assert not hasattr(scenario, "truth")
    assert not hasattr(scenario, "control")
    assert not hasattr(environment, "truth")


def test_validation_errors_and_public_result_metadata_do_not_reveal_control_label() -> None:
    with pytest.raises(ValidationError) as captured:
        AgentContext.model_validate(
            {"scenario_id": "bad id", "autonomy": "A2", "seed": -1, "ground_truth": "probe"}
        )
    assert "compromised" not in str(captured.value).lower()
    result = run_benchmark(
        "identity-compromise-001", "baseline", "A2", 9001, profile="AMBIGUOUS", control=True
    )
    metadata = result.model_dump(
        mode="json",
        exclude={
            "tool_history",
            "actions",
            "evidence",
            "conclusion",
            "narrative",
            "categories",
            "score_breakdown",
            "penalties",
            "score_reasons",
        }
    )
    assert "control" not in metadata
    assert "compromised_identity" not in json.dumps(metadata).lower()


def _render(value: object) -> str:
    if isinstance(value, BaseModel):
        serialized = value.model_dump_json()
    else:
        serialized = json.dumps(value, default=lambda item: item.model_dump(mode="json"))
    return f"{serialized}\n{value!r}\n{value!s}"
