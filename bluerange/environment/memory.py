"""Deterministic in-memory scenario environment."""

from bluerange.models import Observation, SafeId, SafeText, Scenario, StrictModel, ToolResult


class IdentityState(StrictModel):
    id: SafeId
    display_name: SafeText
    role: SafeText
    critical: bool = False
    disabled: bool = False


class SessionState(StrictModel):
    id: SafeId
    identity_id: SafeId
    active: bool = True


class Environment:
    def __init__(self, scenario: Scenario):
        self.scenario = scenario
        self.identities = {i.id: IdentityState.model_validate(i.model_dump()) for i in scenario.identities}
        self.sessions = {s.id: SessionState.model_validate(s.model_dump()) for s in scenario.sessions}
        self.incidents: list[dict[str, str]] = []
        self.escalations: list[dict[str, str]] = []

    def observe(self, step: int) -> Observation:
        return Observation(step=step, events=[e for e in self.scenario.telemetry if e.step == step])

    def execute(self, name: str, arguments: dict[str, object]) -> ToolResult:
        identity = str(arguments.get("identity_id", ""))
        if name == "search_logs":
            query = str(arguments["query"]).lower()
            events = [e.model_dump(mode="json") for e in self.scenario.telemetry if query in e.model_dump_json().lower()]
            return ToolResult(success=True, data={"events": events})
        if name == "inspect_identity":
            item = self.identities.get(identity)
            return ToolResult(success=item is not None, data=item.model_dump() if item else {}, error=None if item else "identity not found")
        if name == "get_authentication_history":
            events = [e.model_dump(mode="json") for e in self.scenario.telemetry if e.identity_id == identity and e.event_type in {"login", "authentication_context"}]
            return ToolResult(success=True, data={"events": events})
        if name == "get_active_sessions":
            return ToolResult(success=True, data={"sessions": [s.model_dump() for s in self.sessions.values() if s.identity_id == identity and s.active]})
        if name == "get_asset_context":
            return ToolResult(success=True, data={"asset_id": arguments["asset_id"], "classification": "business application"})
        if name == "revoke_session":
            session = self.sessions.get(str(arguments["session_id"]))
            if not session:
                return ToolResult(success=False, error="session not found")
            session.active = False
            return ToolResult(success=True, data={"session_id": session.id, "active": False})
        if name == "disable_identity":
            item = self.identities.get(identity)
            if not item:
                return ToolResult(success=False, error="identity not found")
            item.disabled = True
            return ToolResult(success=True, data={"identity_id": identity, "disabled": True})
        if name == "escalate_to_human":
            self.escalations.append({"reason": str(arguments["reason"])})
            return ToolResult(success=True, data={"recorded": True})
        if name == "create_incident":
            self.incidents.append({"title": str(arguments["title"]), "summary": str(arguments["summary"])})
            return ToolResult(success=True, data={"incident_id": f"INC-{len(self.incidents):04d}"})
        return ToolResult(success=False, error="prohibited tool")
