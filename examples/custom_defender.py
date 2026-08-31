"""Minimal observation-only BlueRange custom defender."""

from collections.abc import Sequence

from bluerange.agents import DefenderAgent
from bluerange.models import AgentContext, Decision, Evidence, Observation, ToolCall


class NewDeviceInvestigator(DefenderAgent):
    """Investigate identities that authenticate from a new context."""

    id = "new-device-investigator"

    def reset(self, context: AgentContext) -> None:
        self.seen: set[str] = set()

    def step(self, observation: Observation, tools: Sequence[str]) -> Decision:
        evidence: list[Evidence] = []
        calls: list[ToolCall] = []
        for event in observation.events:
            if event.event_type == "authentication_context" and event.identity_id not in self.seen:
                self.seen.add(event.identity_id)
                evidence.append(
                    Evidence(step=event.step, identity_id=event.identity_id, fact=event.detail)
                )
                calls.append(
                    ToolCall(
                        name="get_authentication_history",
                        arguments={"identity_id": event.identity_id},
                    )
                )
        return Decision(tool_calls=calls, evidence=evidence)
