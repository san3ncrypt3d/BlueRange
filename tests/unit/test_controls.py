from typer.testing import CliRunner

from bluerange.agents import __all__ as production_agents
from bluerange.cli import app
from bluerange.models import BenchmarkResult
from bluerange.orchestrator import run_benchmark
from bluerange.scenarios import EvidenceProfile
from bluerange.scenarios._evaluator import build_evaluator_instance
from tests.support.agents import (
    DisableEverythingAgent,
    DoNothingAgent,
    MinimalInvestigatorAgent,
    OracleDefender,
    OverconfidentAgent,
    RandomResponderAgent,
    SafeControlAgent,
)


def test_negative_controls_have_expected_properties() -> None:
    do_nothing = run_benchmark("identity-compromise-001", "x", "A2", 101, DoNothingAgent())
    destructive = run_benchmark("identity-compromise-001", "x", "A3", 101, DisableEverythingAgent())
    investigator = run_benchmark(
        "identity-compromise-001", "x", "A2", 101, MinimalInvestigatorAgent()
    )
    assert do_nothing.final_score < investigator.final_score
    assert _component(investigator, "investigation accuracy") > 0
    assert _component(investigator, "containment") == 0
    assert _category(destructive, "safety") < _category(do_nothing, "safety")


def test_random_is_seeded_and_varies_across_instances() -> None:
    first = run_benchmark("identity-compromise-001", "x", "A2", 501, RandomResponderAgent())
    repeated = run_benchmark("identity-compromise-001", "x", "A2", 501, RandomResponderAgent())
    varied = run_benchmark("identity-compromise-001", "x", "A2", 502, RandomResponderAgent())
    assert first.semantic_fingerprint == repeated.semantic_fingerprint
    assert first.semantic_fingerprint != varied.semantic_fingerprint


def test_benign_control_rewards_safe_disposition_and_penalizes_overconfidence() -> None:
    safe = run_benchmark(
        "identity-compromise-001",
        "x",
        "A2",
        9001,
        SafeControlAgent(),
        profile=EvidenceProfile.AMBIGUOUS,
        control=True,
    )
    reckless = run_benchmark(
        "identity-compromise-001",
        "x",
        "A2",
        9001,
        OverconfidentAgent(),
        profile=EvidenceProfile.AMBIGUOUS,
        control=True,
    )
    assert safe.final_score > reckless.final_score
    assert not safe.actions
    assert _component(safe, "containment") == 10


def test_oracle_is_test_only_and_approaches_maximum() -> None:
    instance = build_evaluator_instance(101)
    result = run_benchmark(
        "identity-compromise-001", "x", "A2", 101, OracleDefender(instance.truth)
    )
    assert result.final_score >= 90
    assert "OracleDefender" not in production_agents
    assert CliRunner().invoke(app, ["run", "--agent", "test-oracle"]).exit_code != 0


def _category(result: BenchmarkResult, name: str) -> float:
    return next(item.score for item in result.categories if item.category == name)


def _component(result: BenchmarkResult, name: str) -> float:
    return next(item.awarded for item in result.score_breakdown if item.component == name)
