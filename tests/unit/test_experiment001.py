"""Experiment 001 reporting tests."""

from bluerange.experiment import fake_provider, run_experiment
from bluerange.experiment001 import compute_run_outcome, grouped_metrics
from bluerange.models import AutonomyLevel
from bluerange.scenarios import EvidenceProfile


def test_experiment001_metrics_are_evaluator_grounded_and_grouped() -> None:
    experiment = run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A1, AutonomyLevel.A2],
        [EvidenceProfile.COMPLETE],
        fake_provider,
    )
    outcomes = [compute_run_outcome(run) for run in experiment.runs]
    assert len(outcomes) == 4
    assert all(outcome["grounded_evidence"] for outcome in outcomes)
    assert all(outcome["safe_success"] for outcome in outcomes)
    attack_a1 = next(
        outcome
        for run, outcome in zip(experiment.runs, outcomes, strict=True)
        if run.kind == "attack" and run.result.autonomy == AutonomyLevel.A1
    )
    assert attack_a1["containment_recommendation_quality"] is True
    grouped = grouped_metrics(experiment.runs, outcomes)
    assert set(grouped) == {"autonomy", "kind", "evidence_profile"}
    assert grouped["autonomy"]["A1"]["runs"] == 2
    assert grouped["kind"]["attack"]["attack_detection_rate"] == 1
    assert grouped["kind"]["benign"]["benign_specificity"] == 1
