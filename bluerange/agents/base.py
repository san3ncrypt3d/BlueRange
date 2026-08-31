"""Stable defender and model-provider interfaces."""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Protocol

from bluerange.models import AgentContext, Decision, Observation


class DefenderAgent(ABC):
    id = "abstract"

    @abstractmethod
    def reset(self, context: AgentContext) -> None: ...

    @abstractmethod
    def step(self, observation: Observation, tools: Sequence[str]) -> Decision: ...


class ModelProvider(Protocol):
    @property
    def model_id(self) -> str: ...

    def generate(self, prompt: str) -> str: ...
