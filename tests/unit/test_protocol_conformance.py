"""Neutral defender-v2 protocol conformance tests, written before implementation."""

import json
from typing import Any

import pytest
from pydantic import ValidationError

from bluerange.models.gateway import FakeModelProvider, OpenAICompatibleProvider, OutputMode
from bluerange.models.schemas import ModelMessage
from bluerange.protocol_conformance import (
    ConformanceDecision,
    ProviderRequestCap,
    accepted_literals,
    build_protocol_presentation,
    classify_failure,
    conformance_request,
    run_conformance_case,
    run_conformance_lab,
)


def _assessment(refs: list[str] | None = None) -> dict[str, object]:
    return {
        "disposition": "UNKNOWN",
        "subject": None,
        "confidence": 0.5,
        "evidence_refs": refs if refs is not None else ["event-001"],
        "incident_summary": "Synthetic observations require review.",
        "recommended_response": None,
        "performed_response": None,
        "remaining_uncertainty": "The observations are synthetic.",
    }


def _decision(state: str, action: object) -> str:
    return json.dumps({"lifecycle_state": state, "assessment": _assessment(), "action": action})


@pytest.mark.parametrize(
    ("state", "action"),
    [
        (
            "INVESTIGATE",
            {"type": "tool", "name": "inspect_object", "arguments": {"object_id": "object-001"}},
        ),
        (
            "RESPOND",
            {
                "type": "recommendation",
                "name": "quarantine_object",
                "arguments": {"object_id": "object-001"},
            },
        ),
        ("FINALIZE", None),
    ],
)
def test_isolated_lifecycle_contract(state: str, action: object) -> None:
    parsed = ConformanceDecision.model_validate_json(_decision(state, action))
    assert parsed.lifecycle_state == state
    assert "action" in parsed.model_dump()


@pytest.mark.parametrize("state", ["investigate", "Respond", "finalize", "UNKNOWN"])
def test_lifecycle_casing_is_strict(state: str) -> None:
    with pytest.raises(ValidationError):
        ConformanceDecision.model_validate_json(_decision(state, None))


def test_literals_are_derived_from_schema_and_displayed() -> None:
    literals = accepted_literals(ConformanceDecision)
    assert literals["lifecycle_state"] == ["INVESTIGATE", "RESPOND", "FINALIZE"]
    assert literals["assessment.disposition"] == ["UNKNOWN", "COMPROMISE", "BENIGN"]
    assert literals["action.type"] == ["tool", "recommendation"]
    assert literals["action.name"] == ["inspect_object", "quarantine_object"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.pop("action"),
        lambda value: value.update(extra=True),
        lambda value: value.update(action=[{"name": "inspect_object"}, {"name": "inspect_object"}]),
        lambda value: value.update(tool_calls=[]),
    ],
)
def test_missing_extra_and_multiple_actions_fail(mutation: Any) -> None:
    value = json.loads(_decision("FINALIZE", None))
    mutation(value)
    with pytest.raises(ValidationError):
        ConformanceDecision.model_validate(value)


def test_presentation_has_one_canonical_action_and_no_native_tools() -> None:
    presentation = build_protocol_presentation(ConformanceDecision)
    lowered = presentation.lower()
    assert '"action"' in lowered
    for competing in ('"tool_call"', '"tool_calls"', '"actions"', '"next_action"'):
        assert competing not in lowered
    request = conformance_request("FINALIZE")
    assert request.tools == []


def test_json_object_transport_omits_provider_native_tool_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class Response:
        status = 200

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {"choices": [{"message": {"content": _decision("FINALIZE", None)}}]}
            ).encode()

    def urlopen(request: Any, timeout: float) -> Response:
        captured.update(json.loads(request.data))
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    provider = OpenAICompatibleProvider(
        "model", "http://local", structured_output=OutputMode.JSON_OBJECT
    )
    provider.complete(conformance_request("FINALIZE"))
    assert "tools" not in captured and "tool_choice" not in captured


def test_repair_is_structural_preserves_identifiers_and_is_audited() -> None:
    invalid = json.dumps({"lifecycle_state": "FINALIZE", "assessment": _assessment(), "action": {}})
    valid = _decision("FINALIZE", None)
    provider = FakeModelProvider(responses=[invalid, valid])
    result = run_conformance_case(provider, "FINALIZE", ProviderRequestCap(12))
    assert result.post_repair_valid and result.repair_attempted and result.repair_succeeded
    repair = json.loads(result.requests[1].messages[-1].content)["SCHEMA_REPAIR"]
    assert repair["original_invalid_json"] == invalid
    assert repair["validation_errors"]
    assert repair["accepted_enum_values"] == accepted_literals(ConformanceDecision)
    assert repair["required_fields_and_types"]
    instruction = repair["instruction"].lower()
    assert "do not add evidence or identifiers" in instruction
    assert "do not change" in instruction and "conclusion" in instruction
    assert len(result.turn_audits) == 2
    assert result.turn_audits[0]["protocol_valid"] is False
    assert result.turn_audits[0]["provider_call_id"]
    assert result.turn_audits[0]["latency_ms"] > 0


def test_repair_introducing_unknown_reference_fails_and_stops() -> None:
    invalid = "{}"
    fabricated = _decision("FINALIZE", None).replace("event-001", "event-999")
    provider = FakeModelProvider(responses=[invalid, fabricated, _decision("FINALIZE", None)])
    result = run_conformance_case(provider, "FINALIZE", ProviderRequestCap(12))
    assert not result.post_repair_valid and len(result.requests) == 2
    assert result.failure_counts["fabricated_reference"] == 1


def test_invalid_decision_never_reaches_action_sink_and_audits_are_secret_safe() -> None:
    reached: list[object] = []
    provider = FakeModelProvider(responses=["not-json", "{}"])
    request = conformance_request("INVESTIGATE").model_copy(
        update={"messages": [ModelMessage(role="user", content="synthetic bearer super-secret")]}
    )
    result = run_conformance_case(
        provider, "INVESTIGATE", ProviderRequestCap(12), request=request, action_sink=reached.append
    )
    assert reached == []
    assert len(result.turn_audits) == 2
    assert "super-secret" not in json.dumps(result.turn_audits)
    assert result.failure_counts["other"] >= 1


def test_absolute_provider_request_cap_counts_repairs() -> None:
    cap = ProviderRequestCap(1)
    result = run_conformance_case(FakeModelProvider(responses=["{}"]), "FINALIZE", cap)
    assert cap.used == 1 and not result.repair_attempted
    assert result.failure_counts["call_cap"] == 1


@pytest.mark.parametrize(
    ("value", "category"),
    [
        ({}, "missing_field"),
        ({"extra": True}, "missing_field"),
        ({"lifecycle_state": "BAD", "assessment": _assessment(), "action": None}, "wrong_enum"),
        (
            {"lifecycle_state": "INVESTIGATE", "assessment": _assessment(), "action": []},
            "wrong_action_shape",
        ),
    ],
)
def test_failure_taxonomy(value: dict[str, object], category: str) -> None:
    assert classify_failure(value, None) == category


def test_neutral_lab_recomputes_metrics_and_enforces_shared_cap(tmp_path: Any) -> None:
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Return the supplied strict protocol JSON.", encoding="utf-8")
    provider = FakeModelProvider(
        responses=[
            _decision(
                "INVESTIGATE",
                {
                    "type": "tool",
                    "name": "inspect_object",
                    "arguments": {"object_id": "object-001"},
                },
            ),
            _decision(
                "RESPOND",
                {
                    "type": "recommendation",
                    "name": "quarantine_object",
                    "arguments": {"object_id": "object-001"},
                },
            ),
            _decision("FINALIZE", None),
        ]
    )
    artifact = run_conformance_lab(provider, ProviderRequestCap(12), prompt_path=prompt)
    assert artifact["lab_passed"]
    assert artifact["metrics"]["provider_requests"] == 3
    assert artifact["independent_recomputation"]["matched"]
