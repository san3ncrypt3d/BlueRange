"""Experiment 002R compatibility tests, authored before implementation."""

import json
import socket
import urllib.error
from email.message import Message
from io import BytesIO
from typing import Any, cast

import pytest

from bluerange.experiment002 import V2Decision
from bluerange.experiment002r import validate_v2_output
from bluerange.models.gateway import (
    OpenAICompatibleProvider,
    OutputMode,
    ProviderError,
    provider_from_config,
)
from bluerange.models.schemas import ModelMessage, ProviderRequest


def _request() -> ProviderRequest:
    return ProviderRequest(
        messages=[ModelMessage(role="user", content="return the protocol object")],
        tools=[],
        timeout_seconds=1,
        response_schema=V2Decision.model_json_schema(),
        audit_run_id="opaque-run",
        audit_turn=1,
        repair_eligible=True,
    )


def _valid(ref: str = "event-001") -> str:
    return json.dumps(
        {
            "lifecycle_state": "FINALIZE",
            "assessment": {
                "disposition": "COMPROMISE",
                "subject": "identity-1",
                "confidence": 0.9,
                "evidence_refs": [ref],
                "incident_summary": "Suspicious activity observed.",
                "recommended_response": "Review and contain.",
                "performed_response": None,
                "remaining_uncertainty": "None material.",
            },
            "action": None,
        }
    )


@pytest.mark.parametrize(
    ("raw", "category"),
    [
        ("not-json", "PROTOCOL_FAILURE"),
        (json.dumps({}), "PROTOCOL_FAILURE"),
        (_valid().replace("FINALIZE", "UNKNOWN"), "LIFECYCLE_FAILURE"),
        (_valid("event-999"), "PROTOCOL_FAILURE"),
        (_valid().replace('"action": null', '"action": {"type":"tool","name":"bad_tool","arguments":{}}').replace("FINALIZE", "INVESTIGATE"), "MODEL_OUTPUT_FAILURE"),
        (_valid().replace('"action": null', '"action": {"type":"tool","name":"inspect_identity","arguments":{"bad":1}}').replace("FINALIZE", "INVESTIGATE"), "MODEL_OUTPUT_FAILURE"),
    ],
)
def test_invalid_outputs_fail_closed(raw: str, category: str) -> None:
    parsed, failure = validate_v2_output(
        raw,
        {"event-001": {"step": 1, "identity_id": "identity-1", "detail": "observable"}},
    )
    assert parsed is None
    assert failure is not None and failure.category == category


def test_valid_json_object_passes_full_unchanged_v2_schema() -> None:
    parsed, failure = validate_v2_output(
        _valid(),
        {"event-001": {"step": 1, "identity_id": "identity-1", "detail": "observable"}},
    )
    assert failure is None
    assert parsed is not None and parsed.lifecycle_state == "FINALIZE"


def test_capability_selection_does_not_globally_downgrade() -> None:
    ollama = cast(OpenAICompatibleProvider, provider_from_config("ollama", "model"))
    strict = cast(OpenAICompatibleProvider, provider_from_config("openai-compatible", "model"))
    assert ollama.output_mode is OutputMode.JSON_OBJECT
    assert strict.output_mode is OutputMode.STRICT_JSON_SCHEMA


class _Response(BytesIO):
    status = 200

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_json_object_transport_and_success_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def urlopen(request: Any, timeout: float) -> _Response:
        captured["body"] = json.loads(request.data)
        return _Response(json.dumps({"choices": [{"message": {"content": _valid()}}], "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}}).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    provider = OpenAICompatibleProvider("model", "http://local", structured_output=OutputMode.JSON_OBJECT)
    response = provider.complete(_request())
    assert captured["body"]["response_format"] == {"type": "json_object"}
    assert response.usage.total_tokens == 5
    audit = provider.audits[-1]
    assert audit.generation_began and audit.http_status == 200
    assert audit.latency_ms > 0 and audit.error_category is None
    assert audit.output_mode is OutputMode.JSON_OBJECT


@pytest.mark.parametrize(
    ("raised", "status"),
    [
        (urllib.error.HTTPError("http://local", 400, "bad", Message(), None), 400),
        (TimeoutError("secret timeout detail"), None),
        (urllib.error.URLError(socket.gaierror("secret host detail")), None),
    ],
)
def test_provider_failures_have_safe_nonzero_audits(
    monkeypatch: pytest.MonkeyPatch, raised: BaseException, status: int | None
) -> None:
    def urlopen(_request: Any, timeout: float) -> _Response:
        raise raised

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    provider = OpenAICompatibleProvider("model", "http://local", api_key="super-secret")
    with pytest.raises(ProviderError) as caught:
        provider.complete(_request())
    audit = caught.value.audit
    assert audit is not None
    serialized = audit.model_dump_json()
    assert audit.error_category == "PROVIDER_FAILURE"
    assert audit.http_status == status
    assert audit.latency_ms > 0 and not audit.generation_began
    assert "super-secret" not in serialized and "secret host detail" not in serialized


def test_schema_only_repair_is_limited_to_one_attempt() -> None:
    from bluerange.experiment002r import schema_only_repair

    calls: list[ProviderRequest] = []

    class Provider:
        provider_id = "fake"
        model_id = "fake"

        def complete(self, request: ProviderRequest):  # type: ignore[no-untyped-def]
            from bluerange.models.schemas import ProviderResponse, TokenUsage

            calls.append(request)
            raw = "{}" if len(calls) == 1 else _valid()
            return ProviderResponse(raw=raw, provider_id="fake", model_id="fake", usage=TokenUsage(total_tokens=1), latency_ms=1)

    parsed, repaired, failure = schema_only_repair(
        Provider(),
        _request(),
        {"event-001": {"step": 1, "identity_id": "identity-1", "detail": "observable"}},
    )
    assert parsed is not None and repaired and failure is None and len(calls) == 2
    repair_payload = json.loads(calls[1].messages[-1].content)
    assert set(repair_payload) == {"SCHEMA_REPAIR"}


def test_failed_schema_only_repair_stops_after_second_call() -> None:
    from bluerange.experiment002r import schema_only_repair
    from bluerange.models.schemas import ProviderResponse

    class Provider:
        provider_id = "fake"
        model_id = "fake"
        calls = 0

        def complete(self, request: ProviderRequest) -> ProviderResponse:
            self.calls += 1
            return ProviderResponse(raw="{}", provider_id="fake", model_id="fake", latency_ms=1)

    provider = Provider()
    parsed, repaired, failure = schema_only_repair(provider, _request(), {})
    assert parsed is None and not repaired and failure is not None
    assert provider.calls == 2
