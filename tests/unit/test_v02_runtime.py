"""Security and behavior tests for the additive v0.2 model runtime."""

import json
from io import BytesIO
from typing import Any

import pytest
from pydantic import ValidationError

from bluerange.environment import Environment
from bluerange.experiment import aggregate_metrics, fake_provider, run_experiment
from bluerange.models import AutonomyLevel, ToolCall
from bluerange.models.gateway import (
    FakeModelProvider,
    OpenAICompatibleProvider,
    ProviderError,
    provider_from_config,
)
from bluerange.models.schemas import (
    ExperimentResult,
    ModelDecision,
    ProviderRequest,
    ProviderResponse,
    RuntimeBudgets,
)
from bluerange.scenarios import EvidenceProfile, load_scenario
from bluerange.tools import ToolController


def _experiment(level: AutonomyLevel = AutonomyLevel.A2) -> ExperimentResult:
    return run_experiment(
        "identity-compromise-001",
        [101],
        [level],
        [EvidenceProfile.COMPLETE],
        fake_provider,
    )


def test_fake_experiment_is_paired_reproducible_and_truth_isolated() -> None:
    first = _experiment()
    second = _experiment()
    assert [run.result.semantic_fingerprint for run in first.runs] == [
        run.result.semantic_fingerprint for run in second.runs
    ]
    assert {run.kind for run in first.runs} == {"attack", "benign"}
    assert first.runtime_version == "0.2.0"
    assert first.metrics.attack_detection == first.metrics.benign_specificity == 1
    audits = [audit.model_dump(mode="json") for run in first.runs for audit in run.model_audits]

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | {item for nested in value.values() for item in keys(nested)}
        if isinstance(value, list):
            return {item for nested in value for item in keys(nested)}
        return set()

    private = {
        "ground_truth",
        "control",
        "compromised_identity",
        "expected_answer",
        "instance_fingerprint",
        "final_score",
    }
    assert not private & keys(audits)
    private_values = {run.result.instance_fingerprint.lower() for run in first.runs} | {
        str(run.result.final_score).lower() for run in first.runs
    }

    def metadata_strings(value: object, *, observation: bool = False) -> set[str]:
        if isinstance(value, dict):
            return {
                item
                for key, nested in value.items()
                for item in metadata_strings(
                    nested, observation=observation or key == "observations"
                )
            }
        if isinstance(value, list):
            return {
                item
                for nested in value
                for item in metadata_strings(nested, observation=observation)
            }
        if isinstance(value, str) and not observation:
            return {value.lower()}
        return set()

    assert not private_values & metadata_strings(audits)
    forbidden_metadata_values = {"attack", "benign", "control"}
    for run in first.runs:
        assert not forbidden_metadata_values & set(run.run_id.lower().split("-"))
        for audit in run.model_audits:
            assert not forbidden_metadata_values & set(audit.run_id.lower().split("-"))
            assert audit.run_id == run.run_id
            public = json.loads(audit.model_input.messages[-1].content)
            assert not private & keys(public)
            serialized_metadata = metadata_strings(
                {key: value for key, value in public.items() if key != "observations"}
            )
            assert not private_values & serialized_metadata


def test_autonomy_boundary_records_a1_and_executes_a2_revoke() -> None:
    a1 = _experiment(AutonomyLevel.A1).runs[0]
    a2 = _experiment(AutonomyLevel.A2).runs[0]
    recommendation = next(a for a in a1.model_audits if a.response_action == "revoke_session")
    assert recommendation.permitted is None
    assert recommendation.denial_reason == "recommendation recorded; not executed"
    assert recommendation.tool_result == {
        "success": False,
        "data": {},
        "error": "recommendation recorded; not executed",
    }
    assert [record.tool for record in a1.result.tool_history] == ["get_active_sessions"]
    assert not any(action.success for action in a1.result.actions)
    assert any(action.tool == "revoke_session" and action.success for action in a2.result.actions)


@pytest.mark.parametrize("level", list(AutonomyLevel))
@pytest.mark.parametrize("tool", ["get_active_sessions", "disable_identity"])
def test_recommendations_never_invoke_controller_or_mutate(level: AutonomyLevel, tool: str) -> None:
    def recommend(request: ProviderRequest, _index: int) -> str:
        public = json.loads(request.messages[-1].content)
        subject = public["observations"][0]["events"][0]["identity_id"]
        arguments = {"identity_id": subject}
        return _decision(
            subject,
            public["observations"][0]["events"][0]["detail"],
            {"type": "recommendation", "name": tool, "arguments": arguments},
        )

    experiment = run_experiment(
        "identity-compromise-001",
        [101],
        [level],
        [EvidenceProfile.COMPLETE],
        lambda: FakeModelProvider(script=recommend),
        RuntimeBudgets(model_turns=1, investigation_calls=1, response_actions=1),
    )
    for run in experiment.runs:
        audit = run.model_audits[0]
        assert audit.permitted is None
        assert audit.denial_reason == "recommendation recorded; not executed"
        assert not run.result.tool_history
        assert not run.result.actions


@pytest.mark.parametrize(
    ("level", "success"),
    [(AutonomyLevel.A2, False), (AutonomyLevel.A3, True)],
)
def test_disable_identity_request_obeys_direct_runtime_authorization(
    level: AutonomyLevel, success: bool
) -> None:
    def disable(request: ProviderRequest, _index: int) -> str:
        public = json.loads(request.messages[-1].content)
        event = public["observations"][0]["events"][0]
        return _decision(
            event["identity_id"],
            event["detail"],
            {
                "type": "tool",
                "name": "disable_identity",
                "arguments": {"identity_id": event["identity_id"]},
            },
        )

    attack = run_experiment(
        "identity-compromise-001",
        [101],
        [level],
        [EvidenceProfile.COMPLETE],
        lambda: FakeModelProvider(script=disable),
        RuntimeBudgets(model_turns=1, investigation_calls=0, response_actions=1),
    ).runs[0]
    assert len(attack.result.tool_history) == 1
    assert attack.result.tool_history[0].tool == "disable_identity"
    assert attack.result.tool_history[0].success is success
    assert attack.model_audits[0].permitted is success
    assert bool(attack.result.actions and attack.result.actions[0].success) is success


def test_unknown_model_tool_fails_schema_boundary_without_controller_invocation() -> None:
    def malformed(request: ProviderRequest, _index: int) -> str:
        public = json.loads(request.messages[-1].content)
        event = public["observations"][0]["events"][0]
        return _decision(
            event["identity_id"],
            event["detail"],
            {"type": "tool", "name": "shell", "arguments": {"cmd": "id"}},
        )

    for run in run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A3],
        [EvidenceProfile.COMPLETE],
        lambda: FakeModelProvider(script=malformed),
        RuntimeBudgets(model_turns=1),
    ).runs:
        assert run.model_audits[0].malformed_error == "ValidationError: model output rejected"
        assert run.model_audits[0].parsed_request is None
        assert not run.result.tool_history


def test_scenario_disallowed_known_tool_is_denied_and_a0_denies_every_tool() -> None:
    scenario = load_scenario("scenarios/identity_compromise").model_copy(
        update={"permitted_tools": ["search_logs"]}
    )
    env = Environment(scenario)
    a3 = ToolController(env, AutonomyLevel.A3, "agent")
    denied = a3.invoke(
        ToolCall(name="disable_identity", arguments={"identity_id": "alice"}), step=1
    )
    assert not denied.success
    assert a3.history[0].denial_reason == "prohibited tool"
    assert not env.identities["alice"].disabled

    a0 = ToolController(env, AutonomyLevel.A0, "agent")
    denied_a0 = a0.invoke(ToolCall(name="search_logs", arguments={"query": "alice"}), step=1)
    assert not denied_a0.success
    assert a0.history[0].denial_reason == "A0 permits no tool execution"


def test_malformed_extra_and_unbounded_outputs_fail_closed() -> None:
    with pytest.raises(ValidationError):
        ModelDecision.model_validate(
            {"assessment": {}, "next_action": {"type": "shell"}, "reason": "x"}
        )
    valid = json.loads(
        fake_provider()
        .complete(
            ProviderRequest.model_validate(
                {
                    "messages": [
                        {
                            "role": "user",
                            "content": json.dumps(
                                {
                                    "observations": [
                                        {
                                            "events": [
                                                {
                                                    "identity_id": "x",
                                                    "detail": "without a business justification",
                                                }
                                            ]
                                        }
                                    ],
                                    "own_tool_results": [],
                                    "autonomy": "A2",
                                }
                            ),
                        }
                    ],
                    "tools": [],
                    "timeout_seconds": 1,
                }
            )
        )
        .raw
    )
    valid["extra"] = True
    with pytest.raises(ValidationError):
        ModelDecision.model_validate(valid)
    valid.pop("extra")
    valid["reason"] = "x" * 2001
    with pytest.raises(ValidationError):
        ModelDecision.model_validate(valid)


def test_independent_budgets_and_complete_audits() -> None:
    result = run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A2],
        [EvidenceProfile.COMPLETE],
        fake_provider,
        RuntimeBudgets(model_turns=3, investigation_calls=0, response_actions=0),
    )
    attack = result.runs[0]
    assert len(attack.model_audits) <= 3
    assert attack.model_audits[0].denial_reason == "independent budget exhausted"
    assert not attack.result.tool_history
    assert all(audit.model_input.messages and audit.run_id for audit in attack.model_audits)


def test_provider_errors_do_not_disclose_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_without_network(*_args: object, **_kwargs: object) -> None:
        raise OSError("transport included super-secret")

    monkeypatch.setattr("urllib.request.urlopen", fail_without_network)
    provider = OpenAICompatibleProvider("model", "http://127.0.0.1:1", "super-secret", 0.01)
    request = ProviderRequest(
        messages=[{"role": "user", "content": "hello"}], tools=[], timeout_seconds=0.01
    )
    with pytest.raises(ProviderError) as caught:
        provider.complete(request)
    assert "super-secret" not in str(caught.value)


def test_provider_failure_creates_complete_safe_audit() -> None:
    class FailingProvider:
        provider_id = "failing"
        model_id = "failure-model"

        def complete(self, request: ProviderRequest) -> ProviderResponse:
            raise ProviderError("raw provider response and super-secret")

    result = run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A2],
        [EvidenceProfile.COMPLETE],
        FailingProvider,
    )
    for run in result.runs:
        assert len(run.model_audits) == 1
        audit = run.model_audits[0]
        assert audit.model_input.messages
        assert audit.malformed_error is None
        assert audit.provider_error == "ProviderError: provider request failed"
        assert audit.parsed_request is None
        assert audit.tool_result is None
        serialized = json.dumps(audit.model_dump(mode="json"))
        assert "super-secret" not in serialized
        assert "raw provider response" not in serialized


def _decision(
    subject: str, fact: str, action: dict[str, Any], disposition: str = "COMPROMISE"
) -> str:
    return json.dumps(
        {
            "assessment": {
                "attack_suspected": disposition == "COMPROMISE",
                "confidence": 0.9,
                "subject_identity_id": subject,
                "summary": f"Observable activity for {subject}.",
                "evidence": [fact],
                "disposition": disposition,
            },
            "next_action": action,
            "reason": "Observable evidence only.",
        }
    )


def test_metrics_use_evaluator_components_not_confident_model_claims() -> None:
    def wrong_script(request: ProviderRequest, index: int) -> str:
        public = json.loads(request.messages[-1].content)
        events = [event for obs in public["observations"] for event in obs["events"]]
        innocent = next(
            event for event in events if "without a business justification" not in event["detail"]
        )
        if index == 0:
            return _decision(
                innocent["identity_id"],
                innocent["detail"],
                {
                    "type": "tool",
                    "name": "get_active_sessions",
                    "arguments": {"identity_id": innocent["identity_id"]},
                },
            )
        sessions = public["own_tool_results"][-1].get("data", {}).get("sessions", [])
        if index == 1 and sessions:
            return _decision(
                innocent["identity_id"],
                innocent["detail"],
                {
                    "type": "tool",
                    "name": "revoke_session",
                    "arguments": {"session_id": sessions[0]["id"]},
                },
            )
        return _decision(
            innocent["identity_id"],
            innocent["detail"],
            {"type": "final", "response": "Done."},
        )

    result = run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A3],
        [EvidenceProfile.COMPLETE],
        lambda: FakeModelProvider(script=wrong_script),
    )
    attack = next(run for run in result.runs if run.kind == "attack")
    assert attack.result.disposition.value == "COMPROMISE"
    assert any(action.success for action in attack.result.actions)
    assert result.metrics.attack_detection == 0
    assert result.metrics.correct_attack_containment == 0


def test_correct_evaluator_target_action_counts_and_aggregates_recompute() -> None:
    experiment = _experiment(AutonomyLevel.A2)
    attack = next(run for run in experiment.runs if run.kind == "attack")
    detection = next(c for c in attack.result.score_breakdown if c.component == "detection")
    containment = next(c for c in attack.result.score_breakdown if c.component == "containment")
    assert detection.awarded > 0
    assert containment.awarded > 0
    assert experiment.metrics.attack_detection == 1
    assert experiment.metrics.correct_attack_containment == 1
    assert experiment.metrics == aggregate_metrics(experiment.runs)


def test_successful_benign_containment_is_false_positive_not_specificity() -> None:
    def contain_script(request: ProviderRequest, index: int) -> str:
        public = json.loads(request.messages[-1].content)
        events = [event for obs in public["observations"] for event in obs["events"]]
        subject = events[0]["identity_id"]
        fact = events[0]["detail"]
        if index == 0:
            return _decision(
                subject,
                fact,
                {
                    "type": "tool",
                    "name": "get_active_sessions",
                    "arguments": {"identity_id": subject},
                },
            )
        sessions = public["own_tool_results"][-1].get("data", {}).get("sessions", [])
        if index == 1 and sessions:
            return _decision(
                subject,
                fact,
                {
                    "type": "tool",
                    "name": "revoke_session",
                    "arguments": {"session_id": sessions[0]["id"]},
                },
            )
        return _decision(subject, fact, {"type": "final", "response": "Done."})

    result = run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A3],
        [EvidenceProfile.COMPLETE],
        lambda: FakeModelProvider(script=contain_script),
    )
    benign = next(run for run in result.runs if run.kind == "benign")
    assert any(action.success for action in benign.result.actions)
    assert result.metrics.false_positive_containment == 1
    assert result.metrics.benign_specificity == 0


def test_fake_evidence_is_observable_and_owned_by_assessed_identity() -> None:
    experiment = _experiment(AutonomyLevel.A2)
    for run in experiment.runs:
        observations = json.loads(run.model_audits[0].model_input.messages[-1].content)[
            "observations"
        ]
        events = [event for observation in observations for event in observation["events"]]
        facts_by_identity = {
            identity: {event["detail"] for event in events if event["identity_id"] == identity}
            for identity in {event["identity_id"] for event in events}
        }
        final = run.model_audits[-1].final_assessment
        assert final is not None
        assert final.subject_identity_id is not None
        assert set(final.evidence) <= facts_by_identity[final.subject_identity_id]


def test_http_transport_delivers_exact_protocol_and_tool_schemas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class Response(BytesIO):
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def urlopen(request: Any, timeout: float) -> Response:
        captured["body"] = json.loads(request.data)
        captured["headers"] = dict(request.header_items())
        payload = {
            "choices": [
                {
                    "message": {
                        "content": _decision("alice", "fact", {"type": "final", "response": "done"})
                    }
                }
            ]
        }
        return Response(json.dumps(payload).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    provider = OpenAICompatibleProvider("model", "http://local", "super-secret", 1)
    request = _experiment().runs[0].model_audits[0].model_input
    response = provider.complete(request)
    assert isinstance(response, ProviderResponse)
    body = captured["body"]
    serialized = json.dumps(body)
    assert body["response_format"]["type"] == "json_schema"
    assert body["response_format"]["json_schema"]["schema"] == ModelDecision.model_json_schema()
    assert body["tools"]
    assert all(tool["function"]["parameters"].get("properties") for tool in body["tools"])
    assert "recommendation" in body["messages"][0]["content"]
    assert "externally authorized" in body["messages"][0]["content"]
    assert "super-secret" not in serialized
    assert captured["headers"]["Authorization"] == "Bearer super-secret"


def test_ollama_config_transport_is_keyless_strict_and_uses_effective_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class Response(BytesIO):
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def urlopen(request: Any, timeout: float) -> Response:
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data)
        captured["headers"] = dict(request.header_items())
        captured["timeout"] = timeout
        payload = {
            "model": "llama3.1",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": _decision(
                            "alice", "observable fact", {"type": "final", "response": "done"}
                        ),
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
        }
        return Response(json.dumps(payload).encode())

    monkeypatch.delenv("BLUERANGE_API_KEY", raising=False)
    monkeypatch.delenv("BLUERANGE_MODEL_BASE_URL", raising=False)
    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    provider = provider_from_config(provider="ollama", model="llama3.1", timeout=10)
    request = (
        _experiment()
        .runs[0]
        .model_audits[0]
        .model_input.model_copy(update={"timeout_seconds": 2.5})
    )
    response = provider.complete(request)
    assert captured["url"] == "http://localhost:11434/v1/chat/completions"
    assert captured["timeout"] == 2.5
    assert captured["body"]["response_format"] == {"type": "json_object"}
    assert captured["body"]["tools"]
    assert "ModelDecision JSON Schema" in captured["body"]["messages"][0]["content"]
    assert "Authorization" not in captured["headers"]
    assert response.usage.total_tokens == 5
    assert ModelDecision.model_validate_json(response.raw).next_action.type == "final"


def test_provider_timeout_uses_stricter_provider_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, float] = {}

    class Response(BytesIO):
        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def urlopen(_request: Any, timeout: float) -> Response:
        captured["timeout"] = timeout
        payload = {
            "choices": [
                {
                    "message": {
                        "content": _decision("alice", "fact", {"type": "final", "response": "done"})
                    }
                }
            ]
        }
        return Response(json.dumps(payload).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    provider = OpenAICompatibleProvider("model", "http://local", timeout=1.25)
    provider.complete(
        ProviderRequest(
            messages=[{"role": "user", "content": "hello"}],
            tools=[],
            timeout_seconds=30,
        )
    )
    assert captured["timeout"] == 1.25


@pytest.mark.parametrize(
    ("level", "executable", "non_executable"),
    [
        (AutonomyLevel.A0, set(), {"get_active_sessions", "revoke_session"}),
        (AutonomyLevel.A1, {"get_active_sessions"}, {"revoke_session", "disable_identity"}),
        (AutonomyLevel.A2, {"get_active_sessions", "revoke_session"}, {"disable_identity"}),
    ],
)
def test_prompt_distinguishes_requestable_and_executable_tools(
    level: AutonomyLevel, executable: set[str], non_executable: set[str]
) -> None:
    public = json.loads(_experiment(level).runs[0].model_audits[0].model_input.messages[-1].content)
    assert executable <= set(public["currently_executable_tools"])
    assert non_executable <= set(public["requestable_tools"]) - set(
        public["currently_executable_tools"]
    )
    assert public["authorization_policy"]


def test_model_turn_budget_is_exact_and_includes_current_turn() -> None:
    result = run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A2],
        [EvidenceProfile.COMPLETE],
        fake_provider,
        RuntimeBudgets(model_turns=1, investigation_calls=8, response_actions=2),
    )
    assert all(len(run.model_audits) == 1 for run in result.runs)
    assert all(run.model_audits[0].remaining_budget.model_turns == 1 for run in result.runs)


def test_investigation_exhaustion_does_not_invoke_controller() -> None:
    result = run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A2],
        [EvidenceProfile.COMPLETE],
        fake_provider,
        RuntimeBudgets(model_turns=3, investigation_calls=0, response_actions=2),
    )
    attack = next(run for run in result.runs if run.kind == "attack")
    assert attack.model_audits[0].denial_reason == "independent budget exhausted"
    assert not any(record.tool == "get_active_sessions" for record in attack.result.tool_history)


def test_response_exhaustion_is_denied_without_controller_or_success() -> None:
    result = run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A2],
        [EvidenceProfile.COMPLETE],
        fake_provider,
        RuntimeBudgets(model_turns=3, investigation_calls=1, response_actions=0),
    )
    attack = next(run for run in result.runs if run.kind == "attack")
    denied = next(
        audit for audit in attack.model_audits if audit.response_action == "revoke_session"
    )
    assert denied.denial_reason == "independent budget exhausted"
    assert denied.tool_result == {
        "success": False,
        "data": {},
        "error": "independent budget exhausted",
    }
    assert [record.tool for record in attack.result.tool_history] == ["get_active_sessions"]
    assert not attack.result.actions


def test_experiment_prompt_and_sampling_are_delivered_exactly() -> None:
    seen: list[ProviderRequest] = []

    def capture(request: ProviderRequest, index: int) -> str:
        seen.append(request)
        return fake_provider().script(request, index)  # type: ignore[misc]

    prompt = "frozen defender prompt\n"
    run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A2],
        [EvidenceProfile.COMPLETE],
        lambda: FakeModelProvider(script=capture),
        RuntimeBudgets(model_turns=1),
        system_prompt=prompt,
        temperature=0.2,
        top_p=0.9,
        model_seed=17,
    )
    assert seen
    assert all(request.messages[0].content == prompt for request in seen)
    assert {(r.temperature, r.top_p, r.seed) for r in seen} == {(0.2, 0.9, 17)}


def test_malformed_raw_output_and_provider_error_are_distinct() -> None:
    malformed = run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A2],
        [EvidenceProfile.COMPLETE],
        lambda: FakeModelProvider(responses=["not json"]),
        RuntimeBudgets(model_turns=1),
    ).runs[0].model_audits[0]
    assert malformed.raw_response == "not json"
    assert malformed.malformed_error is not None
    assert malformed.provider_error is None

    class FailedProvider:
        provider_id = "ollama"
        model_id = "qwen3:14b-q4_K_M"

        def complete(self, request: ProviderRequest) -> ProviderResponse:
            raise ProviderError("model endpoint request failed (TimeoutError)")

    failed = run_experiment(
        "identity-compromise-001",
        [101],
        [AutonomyLevel.A2],
        [EvidenceProfile.COMPLETE],
        FailedProvider,
        RuntimeBudgets(model_turns=1),
    ).runs[0].model_audits[0]
    assert failed.raw_response is None
    assert failed.malformed_error is None
    assert failed.provider_error == "ProviderError: provider request failed"
