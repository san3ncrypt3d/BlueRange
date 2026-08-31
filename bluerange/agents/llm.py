"""Fail-closed provider-neutral LLM adapter."""

import json
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from bluerange.models import AgentContext, Decision, Observation, StrictModel, ToolCall

from .base import DefenderAgent, ModelProvider


class ModelDecision(StrictModel):
    tool: str
    arguments: dict[str, Any]


class MockModelProvider:
    model_id = "mock"

    def __init__(self, responses: list[str]):
        self.responses = iter(responses)

    def generate(self, prompt: str) -> str:
        return next(self.responses)


class LLMDefenderAgent(DefenderAgent):
    id = "llm"

    def __init__(self, provider: ModelProvider):
        self.provider = provider
        self.context: AgentContext | None = None

    def reset(self, context: AgentContext) -> None:
        self.context = context

    def step(self, observation: Observation, tools: Sequence[str]) -> Decision:
        raw = self.provider.generate(json.dumps({"observation": observation.model_dump(mode="json"), "tools": list(tools)}))
        try:
            parsed = ModelDecision.model_validate_json(raw)
            call = ToolCall(name=parsed.tool, arguments=parsed.arguments)
            return Decision(tool_calls=[call])
        except (ValueError, TypeError, ValidationError):
            return Decision(conclusion="Malformed model output; failed closed with no action.")
