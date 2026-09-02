"""Deterministic Anthropic provider integration tests (no network)."""

import json
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from bluerange.models.gateway import (
    AnthropicProvider,
    OutputMode,
    ProviderError,
    provider_from_config,
)
from bluerange.models.schemas import (
    ModelDecision,
    ModelMessage,
    ProviderRequest,
    ToolRequest,
)
from bluerange.tools.base import ARGUMENT_MODELS

FAKE_KEY = "sk-ant-api03-FAKE-BLUERANGE-DO-NOT-USE"
VALID = json.dumps(
    {
        "assessment": {
            "attack_suspected": False,
            "confidence": 0.9,
            "subject_identity_id": None,
            "summary": "No attack.",
            "evidence": [],
            "disposition": "BENIGN",
        },
        "next_action": {"type": "final", "response": "Finished."},
        "reason": "Evidence is benign.",
    }
)


class Messages:
    def __init__(self, response: object = None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.kwargs: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> object:
        self.kwargs = kwargs
        if self.error:
            raise self.error
        return self.response


class Client:
    def __init__(self, messages: Messages):
        self.messages = messages


def envelope(raw: str = VALID, *, blocks: list[object] | None = None) -> object:
    return SimpleNamespace(
        id="msg_safe-123",
        content=blocks if blocks is not None else [SimpleNamespace(type="text", text=raw)],
        usage=SimpleNamespace(input_tokens=12, output_tokens=7),
    )


def request(*, repair: bool = False) -> ProviderRequest:
    return ProviderRequest(
        messages=[
            ModelMessage(role="system", content="protocol"),
            ModelMessage(role="user", content="public"),
        ],
        tools=[],
        timeout_seconds=5,
        response_schema=ModelDecision.model_json_schema(),
        audit_run_id="run-123",
        audit_turn=2,
        repair_eligible=repair,
    )


def test_success_uses_text_json_without_constrained_output_and_neutral_defaults() -> None:
    messages = Messages(envelope())
    provider = AnthropicProvider("claude-sonnet-5", api_key=FAKE_KEY, client=Client(messages))
    response = provider.complete(request(repair=True))
    assert ModelDecision.model_validate_json(response.raw)
    assert response.model_id == "claude-sonnet-5"
    assert response.usage.model_dump() == {
        "prompt_tokens": 12,
        "completion_tokens": 7,
        "total_tokens": 19,
    }
    assert messages.kwargs["model"] == "claude-sonnet-5"
    forbidden = {"output_config", "temperature", "top_p", "top_k", "seed", "thinking", "effort"}
    assert forbidden.isdisjoint(messages.kwargs)
    audit = provider.audits[-1]
    assert (audit.run_id, audit.turn, audit.request_id) == ("run-123", 2, "msg_safe-123")
    assert audit.output_mode is OutputMode.ANTHROPIC_TEXT_JSON
    assert audit.repair_eligible and audit.generation_began


@pytest.mark.parametrize("raw", ["not-json", "```json\n{}\n```", '{"assessment": {}}'])
def test_delivered_invalid_model_output_is_not_provider_error(raw: str) -> None:
    provider = AnthropicProvider(
        "claude-sonnet-5", api_key=FAKE_KEY, client=Client(Messages(envelope(raw)))
    )
    assert provider.complete(request(repair=True)).raw == raw
    audit = provider.audits[-1]
    assert audit.error_category is None
    assert audit.repair_eligible


@pytest.mark.parametrize(
    ("error", "category", "status"),
    [
        (TimeoutError("FAKE secret detail"), "TIMEOUT", None),
        (ConnectionError("FAKE secret detail"), "CONNECTION", None),
        (
            type("AuthenticationError", (Exception,), {"status_code": 401})("detail"),
            "AUTHENTICATION",
            401,
        ),
        (type("RateLimitError", (Exception,), {"status_code": 429})("detail"), "RATE_LIMIT", 429),
        (type("OverloadedError", (Exception,), {"status_code": 529})("detail"), "OVERLOADED", 529),
        (type("APIStatusError", (Exception,), {"status_code": 500})("detail"), "SERVER", 500),
    ],
)
def test_safe_provider_error_mapping(error: Exception, category: str, status: int | None) -> None:
    provider = AnthropicProvider(
        "claude-sonnet-5", api_key=FAKE_KEY, client=Client(Messages(error=error))
    )
    with pytest.raises(ProviderError) as caught:
        provider.complete(request())
    audit = caught.value.audit
    assert audit is not None
    serialized = json.dumps(audit.model_dump(mode="json"))
    assert audit.error_category == category
    assert audit.http_status == status
    assert audit.output_mode is OutputMode.ANTHROPIC_TEXT_JSON
    assert "secret detail" not in serialized + str(caught.value)


@pytest.mark.parametrize(
    "response",
    [
        SimpleNamespace(id="msg-1", content=[], usage=None),
        envelope(blocks=[SimpleNamespace(type="thinking", thinking="private")]),
        envelope(
            blocks=[
                SimpleNamespace(type="text", text="{}"),
                SimpleNamespace(type="text", text="{}"),
            ]
        ),
    ],
)
def test_invalid_or_ambiguous_envelope_fails_safely(response: object) -> None:
    provider = AnthropicProvider(
        "claude-sonnet-5", api_key=FAKE_KEY, client=Client(Messages(response))
    )
    with pytest.raises(ProviderError) as caught:
        provider.complete(request())
    assert caught.value.audit is not None
    assert caught.value.audit.error_category == "INVALID_RESPONSE"
    assert caught.value.audit.output_mode is OutputMode.ANTHROPIC_TEXT_JSON


def test_factory_is_lazy_and_missing_key_fails_only_on_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = provider_from_config("anthropic", "claude-sonnet-5")
    assert isinstance(provider, AnthropicProvider)
    with pytest.raises(ProviderError, match="credential is not configured") as caught:
        provider.complete(request())
    assert "ANTHROPIC_API_KEY" not in str(caught.value)


def test_fake_secret_absent_from_all_serialized_artifacts() -> None:
    messages = Messages(envelope())
    provider = AnthropicProvider("claude-sonnet-5", api_key=FAKE_KEY, client=Client(messages))
    response = provider.complete(request())
    artifacts = json.dumps(
        {
            "response": response.model_dump(mode="json"),
            "audits": [a.model_dump(mode="json") for a in provider.audits],
        }
    )
    assert FAKE_KEY not in artifacts
    assert FAKE_KEY not in json.dumps(messages.kwargs)


def test_safe_api_diagnostics_are_allowlisted_bounded_and_scrubbed() -> None:
    embedded_key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"
    authorization = "Bearer should-never-persist"
    request_body = "request-body-should-never-persist"
    response_body = "response-body-should-never-persist"
    exception_repr = "exception-repr-should-never-persist"
    nested_value = "nested-value-should-never-persist"

    class BadRequestError(Exception):
        status_code = 400
        request_id = "req_safe-observability"
        type = "invalid_request_error"
        message = "Invalid structured output: " + embedded_key + " " + ("x" * 2_000)
        headers = {"authorization": authorization}
        request = request_body
        response = response_body
        body = {"nested": nested_value}

        def __repr__(self) -> str:
            return exception_repr

    provider = AnthropicProvider(
        "claude-sonnet-5", api_key=FAKE_KEY, client=Client(Messages(error=BadRequestError()))
    )
    with pytest.raises(ProviderError) as caught:
        provider.complete(request())

    audit = caught.value.audit
    assert audit is not None
    assert audit.http_status == 400
    assert audit.error_category == "INVALID_REQUEST"
    assert audit.api_error_type == "invalid_request_error"
    assert audit.api_error_message is not None
    assert len(audit.api_error_message) <= 500
    assert "[REDACTED]" in audit.api_error_message
    serialized = json.dumps(audit.model_dump(mode="json"))
    for forbidden in (
        embedded_key,
        authorization,
        request_body,
        response_body,
        exception_repr,
        nested_value,
    ):
        assert forbidden not in serialized
    assert str(caught.value) == "Anthropic provider request failed (INVALID_REQUEST)"


@pytest.mark.parametrize(
    ("name", "status", "category", "api_type"),
    [
        ("AuthenticationError", 401, "AUTHENTICATION", "authentication_error"),
        ("RateLimitError", 429, "RATE_LIMIT", "rate_limit_error"),
        ("OverloadedError", 529, "OVERLOADED", "overloaded_error"),
        ("APIStatusError", 500, "SERVER", "api_error"),
    ],
)
def test_safe_api_diagnostics_preserve_existing_classification(
    name: str, status: int, category: str, api_type: str
) -> None:
    error = type(
        name,
        (Exception,),
        {
            "status_code": status,
            "request_id": "req_safe-classification",
            "type": api_type,
            "message": "Safe provider diagnostic",
        },
    )()
    provider = AnthropicProvider(
        "claude-sonnet-5", api_key=FAKE_KEY, client=Client(Messages(error=error))
    )
    with pytest.raises(ProviderError) as caught:
        provider.complete(request())
    audit = caught.value.audit
    assert audit is not None
    assert audit.error_category == category
    assert audit.api_error_type == api_type
    assert audit.api_error_message == "Safe provider diagnostic"
    assert audit.request_id == "req_safe-classification"


def test_response_schema_remains_internal_and_is_not_transmitted() -> None:
    messages = Messages(envelope())
    provider = AnthropicProvider("claude-sonnet-5", api_key=FAKE_KEY, client=Client(messages))
    provider_request = request()
    authoritative_before = json.dumps(provider_request.response_schema, sort_keys=True)
    provider.complete(provider_request)
    assert "output_config" not in messages.kwargs
    assert json.dumps(provider_request.response_schema, sort_keys=True) == authoritative_before


def test_generic_runtime_request_without_response_schema_uses_text_mode() -> None:
    messages = Messages(envelope())
    provider = AnthropicProvider("claude-sonnet-5", api_key=FAKE_KEY, client=Client(messages))
    provider_request = request().model_copy(update={"response_schema": None})

    assert provider.complete(provider_request).raw == VALID
    assert "output_config" not in messages.kwargs
    assert provider.audits[-1].output_mode is OutputMode.ANTHROPIC_TEXT_JSON


def test_authoritative_open_argument_maps_remain_unchanged() -> None:
    authoritative = ModelDecision.model_json_schema()
    for definition in ("ToolRequest", "Recommendation"):
        arguments = authoritative["$defs"][definition]["properties"]["arguments"]
        assert arguments["type"] == "object"
        assert arguments["additionalProperties"] is True


@pytest.mark.parametrize("arguments", [{"identity_id": "devon"}, {"wrong": "devon"}, {}, {"hallucinated_key": "unchanged"}])
def test_anthropic_preserves_action_argument_maps_exactly(arguments: dict[str, str]) -> None:
    delivered = json.loads(VALID)
    delivered["next_action"] = {"type": "tool", "name": "inspect_identity", "arguments": arguments}
    raw = json.dumps(delivered)
    messages = Messages(envelope(raw))
    provider = AnthropicProvider("claude-sonnet-5", api_key=FAKE_KEY, client=Client(messages))
    response = provider.complete(request())
    assert response.raw == raw
    assert "output_config" not in messages.kwargs
    decision = ModelDecision.model_validate_json(response.raw)
    assert isinstance(decision.next_action, ToolRequest)
    assert decision.next_action.arguments == arguments


def test_unknown_arguments_reach_unchanged_authoritative_tool_validation() -> None:
    delivered = json.loads(VALID)
    delivered["next_action"] = {"type": "tool", "name": "inspect_identity", "arguments": {"wrong": "devon"}}
    provider = AnthropicProvider("claude-sonnet-5", api_key=FAKE_KEY, client=Client(Messages(envelope(json.dumps(delivered)))))
    decision = ModelDecision.model_validate_json(provider.complete(request()).raw)
    assert isinstance(decision.next_action, ToolRequest)
    with pytest.raises(ValidationError):
        ARGUMENT_MODELS[decision.next_action.name].model_validate(decision.next_action.arguments)


def test_valid_json_failing_authoritative_schema_remains_model_behaviour() -> None:
    raw = '{"assessment": {}}'
    provider = AnthropicProvider("claude-sonnet-5", api_key=FAKE_KEY, client=Client(Messages(envelope(raw))))
    response = provider.complete(request())
    assert response.raw == raw
    assert provider.audits[-1].error_category is None
    with pytest.raises(ValidationError):
        ModelDecision.model_validate_json(response.raw)
