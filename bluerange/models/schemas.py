"""Strict provider protocol, audit, budget, and experiment schemas."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import Field

from .legacy import (
    AutonomyLevel,
    BenchmarkResult,
    Disposition,
    FrozenStrictModel,
    SafeId,
    StrictModel,
    ToolName,
)

BoundedText = Annotated[str, Field(min_length=1, max_length=2000)]


class ModelMessage(StrictModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: Annotated[str, Field(min_length=1, max_length=50_000)]


class ToolDescriptor(StrictModel):
    name: ToolName
    description: Annotated[str, Field(min_length=1, max_length=500)]
    parameters: dict[str, Any]


class TokenUsage(StrictModel):
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)


class ProviderRequest(StrictModel):
    messages: list[ModelMessage] = Field(min_length=1, max_length=100)
    tools: list[ToolDescriptor] = Field(max_length=20)
    timeout_seconds: float = Field(gt=0, le=600)
    temperature: float = Field(default=0.2, ge=0, le=2)
    top_p: float = Field(default=0.9, gt=0, le=1)
    seed: int = Field(default=17, ge=0)
    response_schema: dict[str, Any] | None = None
    audit_run_id: SafeId = "unassigned"
    audit_turn: int = Field(default=1, ge=1)
    repair_eligible: bool = False


class ProviderResponse(StrictModel):
    raw: Annotated[str, Field(min_length=1, max_length=100_000)]
    provider_id: SafeId
    model_id: SafeId
    usage: TokenUsage = Field(default_factory=TokenUsage)
    latency_ms: float = Field(default=0, ge=0)
    cost: float | None = Field(default=None, ge=0)


class Assessment(StrictModel):
    attack_suspected: bool
    confidence: float = Field(ge=0, le=1)
    subject_identity_id: SafeId | None = None
    summary: BoundedText
    evidence: list[BoundedText] = Field(default_factory=list, max_length=100)
    disposition: Disposition = Disposition.UNKNOWN


class ToolRequest(StrictModel):
    type: Literal["tool"]
    name: ToolName
    arguments: dict[str, Any]


class FinalResponse(StrictModel):
    type: Literal["final"]
    response: BoundedText


class Recommendation(StrictModel):
    type: Literal["recommendation"]
    name: ToolName
    arguments: dict[str, Any]


NextAction = Annotated[ToolRequest | FinalResponse | Recommendation, Field(discriminator="type")]


class ModelDecision(StrictModel):
    assessment: Assessment
    next_action: NextAction
    reason: BoundedText


class RuntimeBudgets(StrictModel):
    model_turns: int = Field(default=12, ge=1, le=100)
    investigation_calls: int = Field(default=8, ge=0, le=100)
    response_actions: int = Field(default=2, ge=0, le=20)


class ValidationStatus(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"


class AuthorizationDecision(StrEnum):
    PERMITTED = "PERMITTED"
    DENIED = "DENIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ExecutionStatus(StrEnum):
    EXECUTED = "EXECUTED"
    NOT_EXECUTED = "NOT_EXECUTED"


class ActionAttemptRecord(FrozenStrictModel):
    """Audit-only representation of a requested action, including unresolved targets."""

    run_id: SafeId
    turn: int = Field(ge=1)
    step: int = Field(ge=1)
    tool: ToolName
    request_type: Literal["tool", "recommendation"]
    original_arguments: dict[str, Any]
    target: SafeId | None = None
    target_field: Literal["session_id", "identity_id"] | None = None
    validation_status: ValidationStatus
    validation_failure: BoundedText | None = None
    authorization_decision: AuthorizationDecision
    denial_reason: BoundedText | None = None
    execution_status: ExecutionStatus
    tool_success: bool | None = None
    safe_failure_category: Literal[
        "none",
        "invalid_arguments",
        "authorization_denied",
        "recommendation_only",
        "tool_failure",
    ]


class RemainingBudgets(FrozenStrictModel):
    model_turns: int = Field(ge=0)
    investigation_calls: int = Field(ge=0)
    response_actions: int = Field(ge=0)


class ModelAuditRecord(FrozenStrictModel):
    run_id: SafeId
    scenario_id: SafeId
    seed: int = Field(ge=0)
    evidence_profile: Literal["COMPLETE", "PARTIAL", "AMBIGUOUS", "NOISY"]
    model_id: SafeId
    provider_id: SafeId
    autonomy: AutonomyLevel
    timestamp: datetime
    model_input: ProviderRequest
    permitted_tools: tuple[ToolName, ...]
    remaining_budget: RemainingBudgets
    parsed_request: dict[str, Any] | None = None
    raw_response: Annotated[str, Field(max_length=100_000)] | None = None
    malformed_error: Annotated[str, Field(max_length=2000)] | None = None
    provider_error: Annotated[str, Field(max_length=2000)] | None = None
    tool_result: dict[str, Any] | None = None
    response_action: ToolName | None = None
    permitted: bool | None = None
    denial_reason: Annotated[str, Field(max_length=2000)] | None = None
    final_assessment: Assessment | None = None
    usage: TokenUsage
    latency_ms: float = Field(ge=0)
    cost: float | None = Field(default=None, ge=0)


class ExperimentMetrics(StrictModel):
    mean_score: float
    median_score: float
    population_stddev: float
    attack_detection: float
    correct_attack_containment: float
    benign_specificity: float
    false_positive_containment: float
    mean_operational_safety: float
    average_tool_calls: float
    total_tokens: int = Field(ge=0)
    total_latency_ms: float = Field(ge=0)
    total_cost: float | None = Field(default=None, ge=0)


class ExperimentRun(StrictModel):
    run_id: SafeId
    kind: Literal["attack", "benign"]
    result: BenchmarkResult
    model_audits: list[ModelAuditRecord]
    action_attempts: list[ActionAttemptRecord] = Field(default_factory=list)


class ExperimentResult(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    runtime_version: Literal["0.2.0"] = "0.2.0"
    scenario_id: SafeId
    provider_id: SafeId
    model_id: SafeId
    profiles: list[Literal["COMPLETE", "PARTIAL", "AMBIGUOUS", "NOISY"]]
    seeds: list[int]
    autonomies: list[AutonomyLevel]
    runs: list[ExperimentRun]
    metrics: ExperimentMetrics
    methodology: Literal["population standard deviation"] = "population standard deviation"
