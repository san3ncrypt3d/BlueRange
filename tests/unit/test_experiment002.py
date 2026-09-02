"""Experiment 002 protocol tests written before the v2 implementation."""

import json
from typing import Any, cast

from bluerange.experiment002 import (
    V2Decision,
    build_public_context,
    compute_v2_metrics,
    run_experiment_v2,
    validate_evidence_refs,
)
from bluerange.models import AutonomyLevel
from bluerange.models.gateway import FakeModelProvider
from bluerange.models.schemas import ProviderRequest, RuntimeBudgets
from bluerange.scenarios import EvidenceProfile


def _assessment(refs: list[str] | None = None) -> dict[str, object]:
    return {
        "disposition": "COMPROMISE",
        "subject": "subject-1",
        "confidence": 0.9,
        "evidence_refs": refs or ["event-001"],
        "incident_summary": "Observed activity supports compromise.",
        "recommended_response": "Revoke the affected session.",
        "performed_response": None,
        "remaining_uncertainty": "None material.",
    }


def test_evidence_references_are_strict_and_resolve_only_exposed_facts() -> None:
    parsed = V2Decision.model_validate(
        {"lifecycle_state": "FINALIZE", "assessment": _assessment(), "action": None}
    )
    resolved = validate_evidence_refs(
        parsed.assessment.evidence_refs,
        {"event-001": {"detail": "observable", "identity_id": "subject-1", "step": 2}},
    )
    assert resolved[0].fact == "observable"
    assert resolved[0].identity_id == "subject-1"
    try:
        validate_evidence_refs(["event-999"], {})
    except ValueError as exc:
        assert str(exc) == "unknown evidence reference"
    else:
        raise AssertionError("unexposed evidence reference accepted")


def test_public_context_is_separated_compact_and_contains_no_private_labels() -> None:
    context, evidence = build_public_context(
        scenario_id="scenario-1",
        description="description",
        autonomy=AutonomyLevel.A1,
        observations=[],
        prior_results=[],
        current_assessment=None,
        remaining={"model_turns": 2, "investigation_calls": 1, "response_actions": 1},
        requestable_tools=["search_logs"],
        executable_tools=["search_logs"],
    )
    assert set(context) == {
        "SCENARIO",
        "CURRENT_OBSERVATION",
        "ACCUMULATED_EVIDENCE",
        "PRIOR_TOOL_RESULTS",
        "CURRENT_ASSESSMENT",
        "AVAILABLE_ACTIONS",
    }
    assert evidence == {}
    lowered = json.dumps(context).lower()
    for forbidden in ("ground_truth", "expected_answer", "final_score", '"attack"', '"benign"'):
        assert forbidden not in lowered


def test_duplicate_successful_investigation_is_recorded_without_budget_charge() -> None:
    def provider() -> FakeModelProvider:
        calls = 0

        def script(request: ProviderRequest, _index: int) -> str:
            nonlocal calls
            public = json.loads(request.messages[-1].content)
            ref = next(iter(public["ACCUMULATED_EVIDENCE"]))
            subject = public["ACCUMULATED_EVIDENCE"][ref]["identity_id"]
            calls += 1
            if calls <= 2:
                return json.dumps(
                    {
                        "lifecycle_state": "INVESTIGATE",
                        "assessment": _assessment([ref]) | {"subject": subject},
                        "action": {
                            "type": "tool",
                            "name": "inspect_identity",
                            "arguments": {"identity_id": subject},
                        },
                    }
                )
            return json.dumps(
                {
                    "lifecycle_state": "FINALIZE",
                    "assessment": _assessment([ref]) | {"subject": subject},
                    "action": None,
                }
            )

        return FakeModelProvider(script=script)

    result = run_experiment_v2(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A1],
        [EvidenceProfile.COMPLETE],
        provider,
        RuntimeBudgets(model_turns=3, investigation_calls=1, response_actions=1),
    )
    for run in result.runs:
        assert run.protocol.duplicate_investigation_attempts == 1
        assert run.protocol.unique_investigation_calls == 1
        assert len(run.result.tool_history) == 1


def test_one_schema_only_repair_and_audit_boundary() -> None:
    prompts: list[dict[str, object]] = []

    def script(request: ProviderRequest, index: int) -> str:
        prompts.append(json.loads(request.messages[-1].content))
        if index == 0:
            return "{}"
        public = prompts[0]
        evidence = cast(dict[str, dict[str, Any]], public["ACCUMULATED_EVIDENCE"])
        ref = next(iter(evidence))
        subject = evidence[ref]["identity_id"]
        return json.dumps(
            {
                "lifecycle_state": "FINALIZE",
                "assessment": _assessment([ref]) | {"subject": subject},
                "action": None,
            }
        )

    result = run_experiment_v2(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A1],
        [EvidenceProfile.COMPLETE],
        lambda: FakeModelProvider(script=script),
        RuntimeBudgets(model_turns=1),
    )
    for run in result.runs:
        assert run.protocol.repair_attempted
        assert run.protocol.repair_succeeded
        assert run.protocol.initial_malformed_outputs == 1
        repair = prompts[1]
        assert set(repair) == {"SCHEMA_REPAIR"}
        serialized = json.dumps(repair).lower()
        assert "expected_answer" not in serialized and "ground_truth" not in serialized
        assert "event-001" not in serialized and "subject-1" not in serialized


def test_metrics_recompute_protocol_and_recognition_separately() -> None:
    result = run_experiment_v2(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A1],
        [EvidenceProfile.COMPLETE],
        lambda: FakeModelProvider(responses=[json.dumps({})]),
        RuntimeBudgets(model_turns=1),
    )
    metrics = compute_v2_metrics(result.runs)
    assert metrics["runs"] == 2
    assert 0 <= metrics["first_pass_protocol_validity_rate"] <= 1
    assert 0 <= metrics["post_repair_protocol_validity_rate"] <= 1
    assert "attack_recognition_rate" in metrics
    assert "attack_detection_rate" in metrics
