"""Shared strict, agent-safe and result models."""

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """Base model which fails closed on unknown input fields."""

    model_config = ConfigDict(extra="forbid")


class FrozenStrictModel(StrictModel):
    """Immutable strict model used for audit and evaluator data."""

    model_config = ConfigDict(extra="forbid", frozen=True)


SafeText = Annotated[str, Field(min_length=1, max_length=500)]
SafeId = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")]


class AutonomyLevel(StrEnum):
    """Supported defender autonomy levels."""

    A0 = "A0"
    A1 = "A1"
    A2 = "A2"
    A3 = "A3"


class Disposition(StrEnum):
    """Typed final assessment used instead of parsing narrative phrases."""

    UNKNOWN = "UNKNOWN"
    COMPROMISE = "COMPROMISE"
    BENIGN = "BENIGN"


ToolName = Literal[
    "search_logs",
    "inspect_identity",
    "get_authentication_history",
    "get_active_sessions",
    "get_asset_context",
    "revoke_session",
    "disable_identity",
    "escalate_to_human",
    "create_incident",
]


class TelemetryEvent(StrictModel):
    step: int = Field(ge=1, le=10_000)
    timestamp: datetime
    event_type: SafeId
    identity_id: SafeId
    source_ip: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    asset_id: SafeId | None = None
    session_id: SafeId | None = None
    detail: SafeText


class IdentityDefinition(StrictModel):
    id: SafeId
    display_name: SafeText
    role: SafeText
    critical: bool = False


class SessionDefinition(StrictModel):
    id: SafeId
    identity_id: SafeId
    active: bool = True


class Scenario(StrictModel):
    schema_version: Literal["1.0"]
    id: SafeId
    version: SafeText
    name: Annotated[str, Field(min_length=1, max_length=120)]
    description: Annotated[str, Field(min_length=1, max_length=1000)]
    seed: int = Field(ge=0)
    max_steps: int = Field(gt=0, le=100)
    identities: list[IdentityDefinition] = Field(min_length=1, max_length=1000)
    sessions: list[SessionDefinition] = Field(max_length=5000)
    permitted_tools: list[ToolName] = Field(min_length=1)
    telemetry: tuple[TelemetryEvent, ...] = ()


class Observation(StrictModel):
    step: int = Field(ge=1)
    events: list[TelemetryEvent]


class AgentContext(StrictModel):
    scenario_id: SafeId
    autonomy: AutonomyLevel
    seed: int = Field(ge=0)


class ToolCall(StrictModel):
    name: ToolName
    arguments: dict[str, Any]


class ToolResult(StrictModel):
    success: bool
    data: dict[str, Any] = Field(default_factory=dict)
    error: Annotated[str, Field(max_length=1000)] | None = None


class Evidence(StrictModel):
    step: int = Field(ge=1)
    identity_id: SafeId
    fact: SafeText


class Decision(StrictModel):
    tool_calls: list[ToolCall] = Field(default_factory=list, max_length=100)
    evidence: list[Evidence] = Field(default_factory=list, max_length=1000)
    conclusion: Annotated[str, Field(max_length=2000)] = ""
    disposition: Disposition = Disposition.UNKNOWN
    narrative: Annotated[str, Field(max_length=10_000)] = ""


class AuditRecord(FrozenStrictModel):
    timestamp: datetime
    agent: SafeId
    tool: Annotated[str, Field(min_length=1, max_length=128)]
    arguments: dict[str, Any]
    result: dict[str, Any]
    success: bool
    denial_reason: Annotated[str, Field(max_length=2000)] | None
    scenario_step: int = Field(ge=1)
    latency_ms: float = Field(ge=0)


class ActionRecord(StrictModel):
    step: int = Field(ge=1)
    tool: SafeId
    target: SafeId
    success: bool


Category = Literal["effectiveness", "safety", "efficiency", "explainability"]


class ScoreComponent(StrictModel):
    category: Category
    component: SafeText
    awarded: float = Field(ge=0)
    maximum: float = Field(gt=0)
    reason: SafeText


class CategorySummary(StrictModel):
    category: Category
    score: float = Field(ge=0)
    maximum: float = Field(gt=0)
    reasons: list[SafeText]


class ScorePenalty(StrictModel):
    code: SafeId
    category: Category
    maximum_component_loss: float = Field(ge=0)
    reason: SafeText


class BenchmarkResult(StrictModel):
    """Canonical grouped result with validated scoring invariants."""

    bluerange_version: SafeText
    scenario_id: SafeId
    scenario_version: SafeText
    scenario_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    instance_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    evidence_profile: Literal["COMPLETE", "PARTIAL", "AMBIGUOUS", "NOISY"]
    agent_id: SafeId
    model_id: SafeId | None
    autonomy: AutonomyLevel
    seed: int = Field(ge=0)
    started_at: datetime
    ended_at: datetime
    semantic_fingerprint: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    tool_history: list[AuditRecord]
    actions: list[ActionRecord]
    evidence: list[Evidence]
    conclusion: Annotated[str, Field(max_length=2000)]
    disposition: Disposition
    narrative: Annotated[str, Field(max_length=10_000)]
    categories: list[CategorySummary]
    score_breakdown: list[ScoreComponent]
    penalties: list[ScorePenalty]
    score_reasons: list[SafeText]
    final_score: float = Field(ge=0, le=100)

    @model_validator(mode="after")
    def validate_score_invariants(self) -> Self:
        expected = {"effectiveness": 45, "safety": 35, "efficiency": 10, "explainability": 10}
        maxima = {item.category: item.maximum for item in self.categories}
        if maxima != expected or sum(maxima.values()) != 100:
            raise ValueError("category maxima are invalid")
        awarded = max(0.0, min(100.0, sum(item.score for item in self.categories)))
        if abs(self.final_score - awarded) > 1e-9:
            raise ValueError("final score must equal the bounded category total")
        semantic = self.model_dump(mode="json")
        semantic.pop("started_at", None)
        semantic.pop("ended_at", None)
        semantic.pop("semantic_fingerprint", None)
        for audit in semantic["tool_history"]:
            audit.pop("timestamp", None)
            audit.pop("latency_ms", None)
        expected_fingerprint = hashlib.sha256(
            json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if self.semantic_fingerprint != expected_fingerprint:
            raise ValueError("semantic fingerprint does not match result content")
        return self
