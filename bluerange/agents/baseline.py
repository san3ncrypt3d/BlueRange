"""Deterministic benchmark-floor defender."""

from collections.abc import Sequence

from bluerange.models import AgentContext, Decision, Evidence, Observation, ToolCall

from .base import DefenderAgent


class BaselineDefenderAgent(DefenderAgent):
    id = "baseline"

    def reset(self, context: AgentContext) -> None:
        self.context = context
        self.suspicion: dict[str, set[str]] = {}
        self.revoked = False

    def step(self, observation: Observation, tools: Sequence[str]) -> Decision:
        calls: list[ToolCall] = []
        evidence: list[Evidence] = []
        suspicious = {"authentication_context", "sensitive_app_access", "privilege_activity", "suspicious_data_access"}
        for event in observation.events:
            if event.event_type in suspicious:
                self.suspicion.setdefault(event.identity_id, set()).add(event.event_type)
                evidence.append(Evidence(step=event.step, identity_id=event.identity_id, fact=event.detail))
                if len(self.suspicion[event.identity_id]) == 1:
                    calls.extend([
                        ToolCall(name="inspect_identity", arguments={"identity_id": event.identity_id}),
                        ToolCall(name="get_authentication_history", arguments={"identity_id": event.identity_id}),
                    ])
        suspect = next((identity for identity, facts in self.suspicion.items() if len(facts) >= 3), None)
        if suspect and not self.revoked:
            calls.extend([
                ToolCall(name="get_active_sessions", arguments={"identity_id": suspect}),
                ToolCall(name="revoke_session", arguments={"session_id": f"sess-{suspect}"}),
                ToolCall(name="create_incident", arguments={"title": f"Identity compromise: {suspect}", "summary": "Multiple distinct anomalous behaviors; active session revoked."}),
            ])
            self.revoked = True
        conclusion = f"{suspect} compromised; session revoked" if suspect and self.revoked else ""
        # Deliberately concise: the floor baseline does not provide full reconstruction or escalation judgement.
        narrative = "Multiple independent signals met the threshold for proportional session containment." if conclusion else ""
        return Decision(tool_calls=calls, evidence=evidence, conclusion=conclusion, narrative=narrative)
