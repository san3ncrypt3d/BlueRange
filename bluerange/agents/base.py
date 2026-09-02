"""Stable defender and model-provider interfaces."""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Protocol

from bluerange.models import AgentContext, Decision, Observation, ToolResult


class DefenderAgent(ABC):
    id = "abstract"

    @abstractmethod
    def reset(self, context: AgentContext) -> None: ...

    @abstractmethod
    def step(self, observation: Observation, tools: Sequence[str]) -> Decision: ...

    def observe(self, observation: Observation) -> None:
        """Receive incremental telemetry in the provider-neutral lifecycle."""
        return None

    def investigate(self, result: ToolResult) -> None:
        """Receive the result of the agent's most recent investigation."""
        return None

    def decide(self, tools: Sequence[str]) -> Decision:
        """Make a lifecycle decision; legacy agents retain ``step`` as their API."""
        raise NotImplementedError

    def act(self, result: ToolResult) -> None:
        """Receive the result of the agent's most recent response request."""
        return None

    def finalize(self) -> Decision:
        """Return a final lifecycle decision."""
        return Decision()


class ModelProvider(Protocol):
    """Compatibility protocol for the original string-only LLM adapter."""

    @property
    def model_id(self) -> str: ...

    def generate(self, prompt: str) -> str: ...
