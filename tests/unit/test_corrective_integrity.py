"""Regression tests for the independent integrity corrective pass."""

from datetime import UTC, datetime
from typing import Any, cast

from bluerange.models import ActionRecord, AuditRecord, AutonomyLevel, Disposition, Evidence
from bluerange.orchestrator import run_benchmark
from bluerange.scenarios import EvidenceProfile
from bluerange.scenarios._evaluator import build_evaluator_instance
from bluerange.scenarios._instances import _build_observable_instance
from bluerange.scoring import ScoreInput, score_run


def _component(result: Any, name: str) -> float:
    return cast(
        float,
        next(
        item.awarded
            for item in result.breakdown
            if item.component == name
        ),
    )


def _score(
    *,
    seed: int = 101,
    control: bool = False,
    actions: list[ActionRecord] | None = None,
    evidence: list[Evidence] | None = None,
    disposition: Disposition = Disposition.UNKNOWN,
    attempts: list[AuditRecord] | None = None,
) -> object:
    instance = build_evaluator_instance(seed, EvidenceProfile.COMPLETE, control)
    return score_run(
        ScoreInput(
            truth=instance.truth,
            actions=actions or [],
            evidence=evidence or [],
            conclusion="",
            disposition=disposition,
            narrative="",
            autonomy=AutonomyLevel.A3,
            tool_calls=len(attempts or []),
            audited_attempts=attempts or [],
            observable_facts=frozenset(e.detail for e in instance.scenario.telemetry),
        )
    )


def test_every_benign_evidence_profile_changes_semantic_telemetry() -> None:
    complete = _build_observable_instance(303, EvidenceProfile.COMPLETE, True).scenario.telemetry
    for profile in (EvidenceProfile.PARTIAL, EvidenceProfile.AMBIGUOUS, EvidenceProfile.NOISY):
        candidate = _build_observable_instance(303, profile, True).scenario.telemetry
        assert [e.model_dump() for e in candidate] != [e.model_dump() for e in complete]


def test_seed_varies_timing_independently_of_identity_and_session_values() -> None:
    timings = {
        tuple((e.step, e.timestamp) for e in _build_observable_instance(seed).scenario.telemetry)
        for seed in range(101, 108)
    }
    assert len(timings) > 1


def test_renamed_permuted_identities_and_opaque_sessions_preserve_baseline_behavior() -> None:
    identity_orders = []
    for seed in (101, 102, 103, 104):
        public = _build_observable_instance(seed)
        identity_orders.append(tuple(identity.id for identity in public.scenario.identities))
        assert all(
            session.id.startswith("s-") and session.identity_id not in session.id
            for session in public.scenario.sessions
        )
        result = run_benchmark("identity-compromise-001", "baseline", "A2", seed)
        assert next(
            item.awarded for item in result.score_breakdown if item.component == "containment"
        ) > 0
    assert len(set(identity_orders)) > 1


def test_only_successful_compromised_target_earns_containment() -> None:
    instance = build_evaluator_instance(101)
    innocent = next(iter(instance.truth.legitimate_sessions))
    compromised = next(iter(instance.truth.compromised_sessions))
    wrong = _score(actions=[ActionRecord(step=3, tool="revoke_session", target=innocent, success=True)])
    failed = _score(
        actions=[ActionRecord(step=3, tool="revoke_session", target=compromised, success=False)]
    )
    correct = _score(
        actions=[ActionRecord(step=3, tool="revoke_session", target=compromised, success=True)]
    )
    assert _component(wrong, "containment") == 0
    assert _component(failed, "containment") == 0
    assert _component(correct, "containment") >= _component(failed, "containment")
    assert _component(correct, "containment") > 0


def test_autonomy_denied_action_cannot_earn_containment() -> None:
    instance = build_evaluator_instance(101)
    session = next(iter(instance.truth.compromised_sessions))
    denied = AuditRecord(
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        agent="probe",
        tool="revoke_session",
        arguments={"session_id": session},
        result={},
        success=False,
        denial_reason="autonomy denied",
        scenario_step=3,
        latency_ms=0,
    )
    assert _component(_score(attempts=[denied]), "containment") == 0


def test_a3_compromised_identity_disablement_counts_as_containment() -> None:
    instance = build_evaluator_instance(101)
    identity = instance.truth.compromised_identity
    assert identity is not None
    result = _score(
        actions=[ActionRecord(step=3, tool="disable_identity", target=identity, success=True)]
    )
    assert _component(result, "containment") == 10


def test_benign_fabricated_evidence_and_contradictory_phrase_earn_no_credit() -> None:
    instance = build_evaluator_instance(9001, control=True)
    fabricated = Evidence(step=1, identity_id="invented", fact="invented observable")
    result = score_run(
        ScoreInput(
            truth=instance.truth,
            actions=[],
            evidence=[fabricated],
            conclusion="It is false that there is no confirmed compromise; compromise confirmed.",
            disposition=Disposition.COMPROMISE,
            narrative="invented observable proves the claim",
            autonomy=AutonomyLevel.A2,
            tool_calls=0,
            observable_facts=frozenset(e.detail for e in instance.scenario.telemetry),
        )
    )
    for name in ("detection", "investigation accuracy", "reconstruction"):
        assert _component(result, name) == 0


def test_revoking_critical_legitimate_session_reduces_collateral() -> None:
    instance = build_evaluator_instance(101)
    critical_identity = next(iter(instance.truth.critical_identities))
    critical_session = next(
        session.id
        for session in instance.scenario.sessions
        if session.identity_id == critical_identity
    )
    result = _score(
        actions=[ActionRecord(step=3, tool="revoke_session", target=critical_session, success=True)]
    )
    assert _component(result, "collateral") == 0


def test_penalty_schema_does_not_claim_arithmetic_deduction() -> None:
    penalties = _score().penalties  # type: ignore[attr-defined]
    fields = type(penalties[0]).model_fields if penalties else None
    if fields is not None:
        assert "deduction" not in fields
        assert "maximum_component_loss" in fields
