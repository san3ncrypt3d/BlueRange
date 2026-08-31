"""Validated, authorized and audited tool control plane."""

from datetime import UTC, datetime, timedelta
from time import perf_counter
from typing import Any

from pydantic import BaseModel, ValidationError

from bluerange.environment import Environment
from bluerange.models import AuditRecord, AutonomyLevel, ToolCall, ToolResult
from bluerange.telemetry import log_audit_event

from .investigation import INVESTIGATION, AssetArgs, IdentityArgs, QueryArgs
from .response import RECORDING, EscalateArgs, IncidentArgs, SessionArgs

ARGUMENT_MODELS: dict[str, type[BaseModel]] = {
    "search_logs": QueryArgs, "inspect_identity": IdentityArgs,
    "get_authentication_history": IdentityArgs, "get_active_sessions": IdentityArgs,
    "get_asset_context": AssetArgs, "revoke_session": SessionArgs,
    "disable_identity": IdentityArgs, "escalate_to_human": EscalateArgs,
    "create_incident": IncidentArgs,
}


class ToolController:
    def __init__(self, environment: Environment, autonomy: AutonomyLevel, agent: str, human_approval: bool = False):
        self.environment = environment
        self.autonomy = autonomy
        self.agent = agent
        self.human_approval = human_approval
        self.history: list[AuditRecord] = []

    @property
    def available_tools(self) -> tuple[str, ...]:
        return tuple(ARGUMENT_MODELS)

    def _denial(self, name: str) -> str | None:
        if name not in ARGUMENT_MODELS or name not in self.environment.scenario.permitted_tools:
            return "prohibited tool"
        if self.autonomy == AutonomyLevel.A0:
            return "A0 permits no tool execution"
        if name in INVESTIGATION or name in RECORDING:
            return None
        if self.autonomy == AutonomyLevel.A1:
            return "A1 permits no response actions"
        if name == "disable_identity" and self.autonomy == AutonomyLevel.A2 and not self.human_approval:
            return "A2 identity disablement requires represented human approval"
        return None

    def invoke(self, call: ToolCall, step: int) -> ToolResult:
        started = perf_counter()
        denial = self._denial(call.name)
        clean: dict[str, Any] = {}
        if denial is None:
            try:
                clean = ARGUMENT_MODELS[call.name].model_validate(call.arguments).model_dump()
            except ValidationError:
                denial = "invalid arguments"
        result = ToolResult(success=False, error=denial) if denial else self.environment.execute(call.name, clean)
        redacted = clean if clean else {key: "[invalid]" for key in call.arguments}
        record = AuditRecord(
            timestamp=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=step, microseconds=len(self.history)),
            agent=self.agent, tool=call.name, arguments=redacted,
            result=result.model_dump(mode="json"), success=result.success,
            denial_reason=denial, scenario_step=step,
            latency_ms=round((perf_counter() - started) * 1000, 3),
        )
        self.history.append(record)
        log_audit_event(record.model_dump(mode="json"))
        return result
