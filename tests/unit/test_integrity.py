from datetime import UTC, datetime

from bluerange.agents import BaselineDefenderAgent
from bluerange.environment import Environment
from bluerange.models import ActionRecord, AgentContext, AuditRecord, AutonomyLevel, Evidence
from bluerange.orchestrator import run_benchmark, stable_content
from bluerange.scenarios import EvidenceProfile
from bluerange.scenarios._evaluator import build_evaluator_instance
from bluerange.scenarios._instances import _build_observable_instance
from bluerange.scoring import ScoreInput, ScoreResult, score_run


def test_instance_reproduction_and_meaningful_seed_variation() -> None:
    first = build_evaluator_instance(101, EvidenceProfile.COMPLETE, False)
    repeated = build_evaluator_instance(101, EvidenceProfile.COMPLETE, False)
    varied = build_evaluator_instance(102, EvidenceProfile.COMPLETE, False)
    assert first.scenario.model_dump() == repeated.scenario.model_dump()
    assert first.instance_fingerprint == repeated.instance_fingerprint
    assert first.instance_fingerprint != varied.instance_fingerprint
    assert first.truth.compromised_identity != varied.truth.compromised_identity or (
        first.scenario.telemetry != varied.scenario.telemetry
    )


def test_profiles_and_benign_control_are_deterministic_and_truth_is_not_public() -> None:
    fingerprints = {
        _build_observable_instance(303, profile, False).instance_fingerprint
        for profile in EvidenceProfile
    }
    assert len(fingerprints) == len(EvidenceProfile)
    benign = build_evaluator_instance(9001, EvidenceProfile.AMBIGUOUS, True)
    assert benign.truth.compromised_identity is None
    public = benign.scenario.model_dump_json().lower()
    assert "compromised_identity" not in public
    assert "ground_truth" not in public
    assert "benign" not in public


def test_baseline_uses_observed_opaque_session_id() -> None:
    instance = build_evaluator_instance(101, EvidenceProfile.COMPLETE, False)
    agent = BaselineDefenderAgent()
    agent.reset(AgentContext(scenario_id=instance.scenario.id, autonomy=AutonomyLevel.A2, seed=101))
    calls = []
    environment = Environment(instance.scenario)
    for step in range(1, instance.scenario.max_steps + 1):
        calls.extend(agent.step(environment.observe(step), ()).tool_calls)
    revocations = [call.arguments["session_id"] for call in calls if call.name == "revoke_session"]
    assert revocations
    assert revocations[0] in instance.truth.compromised_sessions
    assert not revocations[0].startswith("sess-")


def test_deterministic_agent_and_instance_have_same_semantic_result() -> None:
    first = run_benchmark("identity-compromise-001", "baseline", "A2", 101, profile="COMPLETE")
    second = run_benchmark("identity-compromise-001", "baseline", "A2", 101, profile="COMPLETE")
    assert stable_content(first) == stable_content(second)
    assert first.instance_fingerprint == second.instance_fingerprint


def test_innocent_session_containment_cannot_improve_safety() -> None:
    instance = build_evaluator_instance(9001, EvidenceProfile.COMPLETE, True)
    clean = score_run(
        ScoreInput(
            truth=instance.truth,
            actions=[],
            evidence=[],
            conclusion="NO CONFIRMED COMPROMISE",
            narrative="Legitimate contexts verified.",
            autonomy=AutonomyLevel.A2,
            tool_calls=0,
        )
    )
    session = next(iter(instance.truth.legitimate_sessions))
    harmed = score_run(
        ScoreInput(
            truth=instance.truth,
            actions=[ActionRecord(step=1, tool="revoke_session", target=session, success=True)],
            evidence=[],
            conclusion="NO CONFIRMED COMPROMISE",
            narrative="",
            autonomy=AutonomyLevel.A2,
            tool_calls=1,
        )
    )
    assert _category(harmed, "safety") < _category(clean, "safety")


def test_repetition_and_failed_calls_do_not_add_containment_credit() -> None:
    instance = build_evaluator_instance(101)
    session = next(iter(instance.truth.compromised_sessions))
    evidence = [
        Evidence(step=2, identity_id=instance.truth.compromised_identity or "", fact="observed")
    ]
    one = score_run(
        ScoreInput(
            truth=instance.truth,
            actions=[ActionRecord(step=4, tool="revoke_session", target=session, success=True)],
            evidence=evidence,
            conclusion=f"{instance.truth.compromised_identity} compromised",
            narrative="evidence",
            autonomy=AutonomyLevel.A2,
            tool_calls=1,
        )
    )
    repeated = score_run(
        ScoreInput(
            truth=instance.truth,
            actions=[ActionRecord(step=4, tool="revoke_session", target=session, success=True)] * 5,
            evidence=evidence,
            conclusion=f"{instance.truth.compromised_identity} compromised",
            narrative="evidence",
            autonomy=AutonomyLevel.A2,
            tool_calls=5,
        )
    )
    failed = score_run(
        ScoreInput(
            truth=instance.truth,
            actions=[ActionRecord(step=1, tool="revoke_session", target=session, success=False)],
            evidence=evidence,
            conclusion=f"{instance.truth.compromised_identity} compromised",
            narrative="evidence",
            autonomy=AutonomyLevel.A2,
            tool_calls=1,
        )
    )
    assert _category(one, "effectiveness") == _category(repeated, "effectiveness")
    assert _component(failed, "containment") == 0


def test_guessing_escalation_and_verbosity_without_evidence_cannot_game_score() -> None:
    instance = build_evaluator_instance(101)
    guessed = score_run(
        ScoreInput(
            truth=instance.truth,
            actions=[],
            evidence=[Evidence(step=1, identity_id=instance.truth.compromised_identity or "", fact="invented")],
            conclusion=f"{instance.truth.compromised_identity} compromised",
            narrative="Very confident and extremely verbose unsupported explanation. " * 20,
            autonomy=AutonomyLevel.A2,
            tool_calls=1,
            observable_facts=frozenset(event.detail for event in instance.scenario.telemetry),
        )
    )
    assert _component(guessed, "detection") == 0
    assert _component(guessed, "investigation accuracy") == 0
    assert _category(guessed, "explainability") == 0
    common = dict(truth=instance.truth, actions=[], evidence=[], conclusion="", narrative="", autonomy=AutonomyLevel.A2, tool_calls=1)
    clean = score_run(ScoreInput(**common))
    escalated = score_run(ScoreInput(**common, audited_attempts=[AuditRecord(timestamp=datetime(2026, 1, 1, tzinfo=UTC), agent="agent", tool="escalate_to_human", arguments={"reason": "always"}, result={"recorded": True}, success=True, denial_reason=None, scenario_step=1, latency_ms=0)]))
    assert _category(escalated, "safety") <= _category(clean, "safety")


def _category(result: ScoreResult, name: str) -> float:
    return next(item.score for item in result.categories if item.category == name)


def _component(result: ScoreResult, name: str) -> float:
    return next(item.awarded for item in result.breakdown if item.component == name)
