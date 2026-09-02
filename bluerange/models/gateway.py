"""Provider-neutral gateway and OpenAI-compatible HTTP provider."""

import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from time import perf_counter
from typing import TYPE_CHECKING, Any, Protocol, cast
from uuid import uuid4

from pydantic import Field

from .legacy import FrozenStrictModel, SafeId
from .schemas import ProviderRequest, ProviderResponse, TokenUsage

if TYPE_CHECKING:
    from anthropic.types import MessageParam


class OutputMode(StrEnum):
    STRICT_JSON_SCHEMA = "STRICT_JSON_SCHEMA"
    JSON_OBJECT = "JSON_OBJECT"
    TEXT_JSON_FALLBACK = "TEXT_JSON_FALLBACK"
    ANTHROPIC_TEXT_JSON = "ANTHROPIC_TEXT_JSON"


class ProviderCallAudit(FrozenStrictModel):
    call_id: SafeId
    run_id: SafeId
    turn: int = Field(ge=1)
    provider_id: SafeId
    model_id: SafeId
    request_timestamp: datetime
    response_timestamp: datetime
    latency_ms: float = Field(gt=0)
    http_status: int | None = None
    sanitized_error: str | None = None
    error_category: str | None = None
    generation_began: bool
    usage: TokenUsage
    output_mode: OutputMode
    repair_eligible: bool
    request_id: SafeId | None = None
    api_error_type: SafeId | None = None
    api_error_message: str | None = Field(default=None, max_length=500)


class ModelProvider(Protocol):
    provider_id: str
    model_id: str

    def complete(self, request: ProviderRequest) -> ProviderResponse: ...


class ProviderError(RuntimeError):
    """Safe provider error which never incorporates credentials or response headers."""

    def __init__(self, message: str, audit: ProviderCallAudit | None = None):
        super().__init__(message)
        self.audit = audit


class AnthropicProvider:
    """Official Anthropic Messages SDK adapter with lazy credential/client setup."""

    provider_id = "anthropic"
    output_mode = OutputMode.ANTHROPIC_TEXT_JSON

    def __init__(
        self,
        model: str,
        api_key: str | None = None,
        timeout: float = 30,
        max_tokens: int = 4096,
        client: Any | None = None,
    ):
        self.model_id = model
        self._api_key = api_key
        self.timeout = timeout
        self.max_tokens = max_tokens
        self._client = client
        self.audits: list[ProviderCallAudit] = []

    @staticmethod
    def _error_details(exc: Exception) -> tuple[str, int | None]:
        status = getattr(exc, "status_code", None)
        name = type(exc).__name__.lower()
        if isinstance(exc, TimeoutError) or "timeout" in name:
            return "TIMEOUT", status
        if isinstance(exc, ConnectionError) or "connection" in name:
            return "CONNECTION", status
        if status == 401 or "authentication" in name:
            return "AUTHENTICATION", status
        if status == 403 or "permission" in name:
            return "PERMISSION", status
        if status == 404 or "notfound" in name:
            return "NOT_FOUND", status
        if status == 429 or "ratelimit" in name:
            return "RATE_LIMIT", status
        if status == 529 or "overloaded" in name:
            return "OVERLOADED", status
        if isinstance(status, int) and status >= 500:
            return "SERVER", status
        return "INVALID_REQUEST", status

    @staticmethod
    def _safe_api_diagnostics(exc: Exception) -> tuple[str | None, str | None]:
        """Extract only bounded scalar diagnostics; never inspect nested SDK data."""
        raw_type = getattr(exc, "type", None)
        if not isinstance(raw_type, str):
            raw_type = getattr(exc, "error_type", None)
        if not isinstance(raw_type, str):
            raw_type = getattr(exc, "code", None)
        api_error_type = (
            raw_type[:128]
            if isinstance(raw_type, str) and re.fullmatch(r"[A-Za-z0-9._:-]+", raw_type[:128])
            else None
        )

        raw_message = getattr(exc, "message", None)
        if not isinstance(raw_message, str) or not raw_message:
            return api_error_type, None
        message = raw_message.replace("\r", " ").replace("\n", " ")
        for pattern in (
            r"sk-ant-[A-Za-z0-9_-]+",
            r"(?i)\bBearer\s+[^\s,;]+",
            r"(?i)\b(?:authorization|x-api-key)\s*[:=]\s*[^\s,;]+",
        ):
            message = re.sub(pattern, "[REDACTED]", message)
        return api_error_type, message[:500]

    def _audit(
        self,
        request: ProviderRequest,
        requested_at: datetime,
        started: float,
        *,
        status: int | None = None,
        error: str | None = None,
        category: str | None = None,
        generation_began: bool = False,
        usage: TokenUsage | None = None,
        request_id: str | None = None,
        api_error_type: str | None = None,
        api_error_message: str | None = None,
    ) -> ProviderCallAudit:
        safe_request_id = request_id if request_id and len(request_id) <= 128 else None
        audit = ProviderCallAudit(
            call_id=f"call-{uuid4().hex}",
            run_id=request.audit_run_id,
            turn=request.audit_turn,
            provider_id=self.provider_id,
            model_id=self.model_id,
            request_timestamp=requested_at,
            response_timestamp=datetime.now(UTC),
            latency_ms=max((perf_counter() - started) * 1000, 0.001),
            http_status=status,
            sanitized_error=error,
            error_category=category,
            generation_began=generation_began,
            usage=usage or TokenUsage(),
            output_mode=self.output_mode,
            repair_eligible=request.repair_eligible,
            request_id=safe_request_id,
            api_error_type=api_error_type,
            api_error_message=api_error_message,
        )
        self.audits.append(audit)
        return audit

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        requested_at = datetime.now(UTC)
        started = perf_counter()
        if self._client is None:
            key = self._api_key or os.getenv("ANTHROPIC_API_KEY")
            if not key:
                audit = self._audit(
                    request,
                    requested_at,
                    started,
                    error="Anthropic credential is not configured",
                    category="CONFIGURATION",
                )
                raise ProviderError(audit.sanitized_error or "provider configuration failed", audit)
            try:
                from anthropic import Anthropic

                self._client = Anthropic(api_key=key, timeout=self.timeout)
            except (ImportError, ValueError, TypeError):
                audit = self._audit(
                    request,
                    requested_at,
                    started,
                    error="Anthropic SDK configuration failed",
                    category="CONFIGURATION",
                )
                raise ProviderError(
                    audit.sanitized_error or "provider configuration failed", audit
                ) from None

        systems = [message.content for message in request.messages if message.role == "system"]
        if request.tools:
            systems.append(
                "BlueRange controlled tool metadata (never provider-native execution): "
                + json.dumps(
                    [tool.model_dump(mode="json") for tool in request.tools], sort_keys=True
                )
            )
        messages = [
            {"role": message.role, "content": message.content}
            for message in request.messages
            if message.role != "system"
        ]
        if any(message["role"] not in {"user", "assistant"} for message in messages):
            audit = self._audit(
                request,
                requested_at,
                started,
                error="Anthropic request contains an unsupported role",
                category="INVALID_REQUEST",
            )
            raise ProviderError(audit.sanitized_error or "invalid provider request", audit)
        try:
            payload = self._client.messages.create(
                model=self.model_id,
                max_tokens=self.max_tokens,
                timeout=min(self.timeout, request.timeout_seconds),
                system="\n\n".join(systems),
                messages=cast("list[MessageParam]", messages),
            )
        except Exception as exc:
            category, status = self._error_details(exc)
            api_error_type, api_error_message = self._safe_api_diagnostics(exc)
            audit = self._audit(
                request,
                requested_at,
                started,
                status=status,
                error=f"Anthropic provider request failed ({category})",
                category=category,
                request_id=getattr(exc, "request_id", None),
                api_error_type=api_error_type,
                api_error_message=api_error_message,
            )
            raise ProviderError(audit.sanitized_error or "provider request failed", audit) from None

        request_id = getattr(payload, "id", None)
        try:
            text_blocks = [
                block for block in payload.content if getattr(block, "type", None) == "text"
            ]
            if len(text_blocks) != 1:
                raise ValueError
            text = getattr(text_blocks[0], "text", None)
            if not isinstance(text, str) or not text:
                raise ValueError
            raw = text
            input_tokens = int(payload.usage.input_tokens)
            output_tokens = int(payload.usage.output_tokens)
            usage = TokenUsage(
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
            )
        except (AttributeError, TypeError, ValueError, OverflowError):
            audit = self._audit(
                request,
                requested_at,
                started,
                error="Anthropic returned an invalid response envelope",
                category="INVALID_RESPONSE",
                generation_began=True,
                request_id=request_id,
            )
            raise ProviderError(audit.sanitized_error or "invalid response", audit) from None
        audit = self._audit(
            request,
            requested_at,
            started,
            status=200,
            generation_began=True,
            usage=usage,
            request_id=request_id,
        )
        return ProviderResponse(
            raw=raw,
            provider_id=self.provider_id,
            model_id=self.model_id,
            usage=usage,
            latency_ms=audit.latency_ms,
        )


class OpenAICompatibleProvider:
    provider_id = "openai-compatible"

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str | None = None,
        timeout: float = 30,
        structured_output: str | OutputMode = OutputMode.STRICT_JSON_SCHEMA,
    ):
        self.model_id = model
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.timeout = timeout
        aliases = {
            "json_schema": OutputMode.STRICT_JSON_SCHEMA,
            "json_object": OutputMode.JSON_OBJECT,
            "text_json": OutputMode.TEXT_JSON_FALLBACK,
        }
        try:
            self.output_mode = aliases.get(structured_output, OutputMode(structured_output))
        except ValueError:
            raise ValueError("unsupported structured output capability") from None
        self.structured_output = self.output_mode.value
        self.audits: list[ProviderCallAudit] = []

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        from .schemas import ModelDecision

        schema = request.response_schema or ModelDecision.model_json_schema()

        response_format = (
            {
                "type": "json_schema",
                "json_schema": {
                    "name": "bluerange_model_decision",
                    "strict": True,
                    "schema": schema,
                },
            }
            if self.output_mode is OutputMode.STRICT_JSON_SCHEMA
            else {"type": "json_object"}
            if self.output_mode is OutputMode.JSON_OBJECT
            else None
        )
        native_tools = (
            {
                "tools": [
                    {
                        "type": "function",
                        "function": {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.parameters,
                        },
                    }
                    for tool in request.tools
                ],
                "tool_choice": "none",
            }
            if request.tools
            else {}
        )
        body = json.dumps(
            {
                "model": self.model_id,
                "messages": [m.model_dump() for m in request.messages],
                **({"response_format": response_format} if response_format else {}),
                **native_tools,
                "temperature": request.temperature,
                "top_p": request.top_p,
                "seed": request.seed,
            }
        ).encode()
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        requested_at = datetime.now(UTC)
        started = perf_counter()
        status: int | None = None
        try:
            req = urllib.request.Request(f"{self.base_url}/chat/completions", body, headers)
            # Both configuration and an individual request may tighten the bound.
            effective_timeout = min(self.timeout, request.timeout_seconds)
            with urllib.request.urlopen(req, timeout=effective_timeout) as response:
                status = getattr(response, "status", 200)
                payload = json.loads(response.read())
        except (OSError, ValueError, urllib.error.HTTPError) as exc:
            if isinstance(exc, urllib.error.HTTPError):
                status = exc.code
            audit = ProviderCallAudit(
                call_id=f"call-{uuid4().hex}",
                run_id=request.audit_run_id,
                turn=request.audit_turn,
                provider_id=self.provider_id,
                model_id=self.model_id,
                request_timestamp=requested_at,
                response_timestamp=datetime.now(UTC),
                latency_ms=max((perf_counter() - started) * 1000, 0.001),
                http_status=status,
                sanitized_error=f"model endpoint request failed ({type(exc).__name__})",
                error_category="PROVIDER_FAILURE",
                generation_began=False,
                usage=TokenUsage(),
                output_mode=self.output_mode,
                repair_eligible=request.repair_eligible,
            )
            self.audits.append(audit)
            raise ProviderError(audit.sanitized_error or "provider request failed", audit) from None
        try:
            raw = payload["choices"][0]["message"]["content"]
            usage = payload.get("usage", {})
            result = ProviderResponse(
                raw=raw,
                provider_id=self.provider_id,
                model_id=self.model_id,
                usage=TokenUsage(
                    prompt_tokens=usage.get("prompt_tokens", 0),
                    completion_tokens=usage.get("completion_tokens", 0),
                    total_tokens=usage.get("total_tokens", 0),
                ),
                latency_ms=max(round((perf_counter() - started) * 1000, 3), 0.001),
            )
            self.audits.append(
                ProviderCallAudit(
                    call_id=f"call-{uuid4().hex}",
                    run_id=request.audit_run_id,
                    turn=request.audit_turn,
                    provider_id=self.provider_id,
                    model_id=self.model_id,
                    request_timestamp=requested_at,
                    response_timestamp=datetime.now(UTC),
                    latency_ms=result.latency_ms,
                    http_status=status,
                    generation_began=True,
                    usage=result.usage,
                    output_mode=self.output_mode,
                    repair_eligible=request.repair_eligible,
                )
            )
            return result
        except (KeyError, IndexError, TypeError, ValueError):
            audit = ProviderCallAudit(
                call_id=f"call-{uuid4().hex}",
                run_id=request.audit_run_id,
                turn=request.audit_turn,
                provider_id=self.provider_id,
                model_id=self.model_id,
                request_timestamp=requested_at,
                response_timestamp=datetime.now(UTC),
                latency_ms=max((perf_counter() - started) * 1000, 0.001),
                http_status=status,
                sanitized_error="model endpoint returned an invalid response envelope",
                error_category="PROVIDER_FAILURE",
                generation_began=True,
                usage=TokenUsage(),
                output_mode=self.output_mode,
                repair_eligible=request.repair_eligible,
            )
            self.audits.append(audit)
            raise ProviderError(audit.sanitized_error or "invalid response", audit) from None


class FakeModelProvider:
    """Deterministic no-network provider; scripts receive the public request only."""

    provider_id = "fake"
    output_mode = OutputMode.JSON_OBJECT

    def __init__(
        self,
        responses: list[str] | None = None,
        model_id: str = "fake-defender-v1",
        script: Callable[[ProviderRequest, int], str] | None = None,
    ):
        self.model_id = model_id
        self.responses = responses or []
        self.script = script
        self.index = 0

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        index = self.index
        self.index += 1
        raw = self.script(request, index) if self.script else self.responses[index]
        return ProviderResponse(
            raw=raw,
            provider_id=self.provider_id,
            model_id=self.model_id,
            usage=TokenUsage(prompt_tokens=10, completion_tokens=10, total_tokens=20),
            latency_ms=1.0,
        )


def provider_from_config(
    provider: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
    timeout: float | None = None,
) -> ModelProvider:
    selected = provider or os.getenv("BLUERANGE_MODEL_PROVIDER", "openai-compatible")
    selected_model = model or os.getenv("BLUERANGE_MODEL", "")
    if selected == "fake":
        return FakeModelProvider(model_id=selected_model or "fake-defender-v1")
    if selected == "anthropic":
        if not selected_model:
            raise ValueError("model ID is required")
        configured_timeout = timeout or float(os.getenv("BLUERANGE_MODEL_TIMEOUT", "30"))
        return AnthropicProvider(selected_model, timeout=configured_timeout)
    endpoint = (
        base_url
        or os.getenv("BLUERANGE_MODEL_BASE_URL")
        or ("http://localhost:11434/v1" if selected == "ollama" else "https://api.openai.com/v1")
    )
    key = os.getenv("BLUERANGE_API_KEY")
    configured_timeout = timeout or float(os.getenv("BLUERANGE_MODEL_TIMEOUT", "30"))
    if not selected_model:
        raise ValueError("model ID is required")
    structured_output = (
        OutputMode.JSON_OBJECT if selected == "ollama" else OutputMode.STRICT_JSON_SCHEMA
    )
    adapter = OpenAICompatibleProvider(
        selected_model, endpoint, key, configured_timeout, structured_output
    )
    if selected == "ollama":
        adapter.provider_id = "ollama"
    return adapter
