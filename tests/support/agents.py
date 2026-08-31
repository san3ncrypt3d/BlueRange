"""Adversarial controls that are intentionally absent from production registries."""

import random
from collections.abc import Sequence

from bluerange.agents import DefenderAgent
from bluerange.models import AgentContext, Decision, Disposition, Evidence, Observation, ToolCall
from bluerange.scenarios._evaluator import GroundTruth


class DoNothingAgent(DefenderAgent):
    id = "test-do-nothing"

    def reset(self, context: AgentContext) -> None:
        pass

    def step(self, observation: Observation, tools: Sequence[str]) -> Decision:
        return Decision()


class DisableEverythingAgent(DefenderAgent):
    id = "test-disable-everything"

    def reset(self, context: AgentContext) -> None:
        self.seen: set[str] = set()

    def step(self, observation: Observation, tools: Sequence[str]) -> Decision:
        calls = []
        for event in observation.events:
            if event.identity_id not in self.seen:
                self.seen.add(event.identity_id)
                calls.append(
                    ToolCall(name="disable_identity", arguments={"identity_id": event.identity_id})
                )
        return Decision(tool_calls=calls, conclusion="All observed identities disabled")


class RandomResponderAgent(DefenderAgent):
    id = "test-random-responder"

    def reset(self, context: AgentContext) -> None:
        self.rng = random.Random(context.seed)
        self.seen: set[str] = set()

    def step(self, observation: Observation, tools: Sequence[str]) -> Decision:
        calls = []
        evidence = []
        for event in observation.events:
            if self.rng.random() < 0.45:
                evidence.append(
                    Evidence(step=event.step, identity_id=event.identity_id, fact=event.detail)
                )
            if event.session_id and event.identity_id not in self.seen and self.rng.random() < 0.3:
                self.seen.add(event.identity_id)
                calls.append(
                    ToolCall(name="revoke_session", arguments={"session_id": event.session_id})
                )
        conclusion = "possible compromise" if self.rng.random() < 0.25 else ""
        return Decision(tool_calls=calls, evidence=evidence, conclusion=conclusion)


class OverconfidentAgent(DefenderAgent):
    id = "test-overconfident"

    def reset(self, context: AgentContext) -> None:
        self.acted: set[str] = set()

    def step(self, observation: Observation, tools: Sequence[str]) -> Decision:
        for event in observation.events:
            if (
                event.event_type == "authentication_context"
                and event.session_id
                and event.identity_id not in self.acted
            ):
                self.acted.add(event.identity_id)
                return Decision(
                    tool_calls=[
                        ToolCall(name="revoke_session", arguments={"session_id": event.session_id})
                    ],
                    evidence=[
                        Evidence(step=event.step, identity_id=event.identity_id, fact=event.detail)
                    ],
                    conclusion=f"{event.identity_id} compromised",
                    narrative="One anomaly treated as conclusive.",
                )
        return Decision()


class MinimalInvestigatorAgent(DefenderAgent):
    id = "test-minimal-investigator"

    def reset(self, context: AgentContext) -> None:
        pass

    def step(self, observation: Observation, tools: Sequence[str]) -> Decision:
        evidence = [
            Evidence(step=e.step, identity_id=e.identity_id, fact=e.detail)
            for e in observation.events
            if e.event_type
            in {
                "authentication_context",
                "sensitive_app_access",
                "privilege_activity",
                "suspicious_data_access",
            }
        ]
        calls = [
            ToolCall(name="inspect_identity", arguments={"identity_id": e.identity_id})
            for e in observation.events
            if e.event_type == "authentication_context"
        ]
        return Decision(
            tool_calls=calls,
            evidence=evidence,
            narrative="Suspicious activity investigated; no containment performed.",
        )


class SafeControlAgent(MinimalInvestigatorAgent):
    id = "test-safe-control"

    def step(self, observation: Observation, tools: Sequence[str]) -> Decision:
        decision = super().step(observation, tools)
        if observation.step == 6:
            decision.conclusion = "NO CONFIRMED COMPROMISE"
            decision.disposition = Disposition.BENIGN
            decision.narrative = (
                "Travel, VPN, change, service-account, and audit contexts were verified."
            )
        return decision


class OracleDefender(DefenderAgent):
    id = "test-oracle"

    def __init__(self, truth: GroundTruth) -> None:
        self.truth = truth

    def reset(self, context: AgentContext) -> None:
        self.acted = False

    def step(self, observation: Observation, tools: Sequence[str]) -> Decision:
        if self.truth.compromised_identity is None:
            evidence = [
                Evidence(step=e.step, identity_id=e.identity_id, fact=e.detail)
                for e in observation.events
            ]
            return Decision(
                evidence=evidence,
                conclusion="NO CONFIRMED COMPROMISE",
                disposition=Disposition.BENIGN,
                narrative="All suspicious-looking activity has legitimate context.",
            )
        evidence = [
            Evidence(step=e.step, identity_id=e.identity_id, fact=e.detail)
            for e in observation.events
            if e.identity_id == self.truth.compromised_identity
        ]
        calls = []
        if evidence and not self.acted and observation.step >= 4:
            calls = [
                ToolCall(
                    name="revoke_session",
                    arguments={"session_id": next(iter(self.truth.compromised_sessions))},
                ),
                ToolCall(
                    name="escalate_to_human",
                    arguments={"reason": "Confirmed multi-signal identity compromise"},
                ),
            ]
            self.acted = True
        return Decision(
            tool_calls=calls,
            evidence=evidence,
            conclusion=f"{self.truth.compromised_identity} compromised",
            disposition=Disposition.COMPROMISE,
            narrative="Correlated authentication, application, and privilege evidence supports containment and escalation.",
        )
