"""Environment execution interface."""

from typing import Protocol

from bluerange.models import Observation, ToolResult


class EnvironmentProtocol(Protocol):
    def observe(self, step: int) -> Observation: ...
    def execute(self, name: str, arguments: dict[str, object]) -> ToolResult: ...
