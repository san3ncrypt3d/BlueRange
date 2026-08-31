from pathlib import Path

import pytest

from bluerange.environment import Environment
from bluerange.scenarios import ScenarioError, load_ground_truth, load_scenario

SCENARIO = Path("scenarios/identity_compromise")


def test_loads_versioned_scenario_and_keeps_truth_separate() -> None:
    scenario = load_scenario(SCENARIO)
    truth = load_ground_truth(SCENARIO)
    assert (scenario.id, scenario.version, scenario.max_steps, scenario.seed) == (
        "identity-compromise-001",
        "1.0",
        30,
        42,
    )
    assert truth.compromised_identity == "alice"
    public = scenario.model_dump_json().lower()
    assert all(word not in public for word in ("compromised", "ground_truth", "mitre"))


def test_rejects_malformed_scenario(tmp_path: Path) -> None:
    (tmp_path / "scenario.yaml").write_text("id: broken\n", encoding="utf-8")
    (tmp_path / "telemetry.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ScenarioError):
        load_scenario(tmp_path)


def test_agent_facing_environment_and_results_have_no_truth_metadata() -> None:
    """Operational objects must not reveal evaluator-only answers."""
    scenario = load_scenario(SCENARIO)
    environment = Environment(scenario)
    exposed = (
        scenario.model_dump_json()
        + environment.observe(6).model_dump_json()
        + environment.execute("search_logs", {"query": "alice"}).model_dump_json()
    ).lower()
    for forbidden in ("ground_truth", "mitre", "compromised", "malicious", "attack"):
        assert forbidden not in exposed
