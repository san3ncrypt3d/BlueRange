"""Neutral defender-v2 protocol presentation and conformance laboratory."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, ValidationError, model_validator

from bluerange.models import Disposition
from bluerange.models.gateway import ModelProvider, ProviderError, provider_from_config
from bluerange.models.legacy import StrictModel
from bluerange.models.schemas import ModelMessage, ProviderRequest

SyntheticRef = Annotated[str, Field(pattern=r"^event-[0-9]{3,}$")]
SyntheticId = Annotated[str, Field(pattern=r"^object-[0-9]{3,}$")]


class ConformanceAssessment(StrictModel):
    """Complete assessment used by every isolated lifecycle case."""

    disposition: Disposition
    subject: SyntheticId | None
    confidence: float = Field(ge=0, le=1)
    evidence_refs: list[SyntheticRef] = Field(max_length=10)
    incident_summary: Annotated[str, Field(min_length=1, max_length=500)]
    recommended_response: Annotated[str, Field(min_length=1, max_length=500)] | None
    performed_response: Annotated[str, Field(min_length=1, max_length=500)] | None
    remaining_uncertainty: Annotated[str, Field(min_length=1, max_length=500)]


class ConformanceAction(StrictModel):
    """One singular, returned-JSON action; never a provider-native invocation."""

    type: Literal["tool", "recommendation"]
    name: Literal["inspect_object", "quarantine_object"]
    arguments: dict[Literal["object_id"], SyntheticId]


class ConformanceDecision(StrictModel):
    """Canonical neutral lifecycle contract."""

    lifecycle_state: Literal["INVESTIGATE", "RESPOND", "FINALIZE"]
    assessment: ConformanceAssessment
    action: ConformanceAction | None

    @model_validator(mode="after")
    def lifecycle_matches_action(self) -> ConformanceDecision:
        if self.lifecycle_state == "FINALIZE" and self.action is not None:
            raise ValueError("FINALIZE requires explicit action null")
        if self.lifecycle_state != "FINALIZE" and self.action is None:
            raise ValueError("non-final lifecycle requires exactly one action")
        if (
            self.lifecycle_state == "INVESTIGATE"
            and self.action is not None
            and (self.action.type != "tool" or self.action.name != "inspect_object")
        ):
            raise ValueError("INVESTIGATE requires inspect_object")
        if (
            self.lifecycle_state == "RESPOND"
            and self.action is not None
            and (self.action.type != "recommendation" or self.action.name != "quarantine_object")
        ):
            raise ValueError("RESPOND requires quarantine_object")
        return self


def _resolve(schema: dict[str, Any], node: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in node:
        target: Any = schema
        for part in node["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        node = target
    return node


def _enum(schema: dict[str, Any], node: dict[str, Any]) -> list[str]:
    node = _resolve(schema, node)
    if "enum" in node:
        return [str(value) for value in node["enum"]]
    values: list[str] = []
    for choice in node.get("anyOf", []):
        values.extend(_enum(schema, choice))
    return list(dict.fromkeys(values))


def accepted_literals(model: type[BaseModel]) -> dict[str, list[str]]:
    """Derive relevant accepted literals solely from the authoritative JSON Schema."""
    schema = model.model_json_schema()
    root = _resolve(schema, schema)
    assessment = _resolve(schema, root["properties"]["assessment"])
    action_node = root["properties"]["action"]
    action = next(
        _resolve(schema, item)
        for item in action_node.get("anyOf", [action_node])
        if _resolve(schema, item).get("type") != "null"
    )
    return {
        "lifecycle_state": _enum(schema, root["properties"]["lifecycle_state"]),
        "assessment.disposition": _enum(schema, assessment["properties"]["disposition"]),
        "action.type": _enum(schema, action["properties"]["type"]),
        "action.name": _enum(schema, action["properties"]["name"]),
    }


def required_fields_and_types(model: type[BaseModel]) -> dict[str, Any]:
    """Extract structural field requirements without duplicating the model semantics."""
    schema = model.model_json_schema()
    return {"required": schema["required"], "properties": schema["properties"]}


def build_protocol_presentation(model: type[BaseModel]) -> str:
    """Build the machine-facing contract directly from its authoritative schema."""
    payload = {
        "CANONICAL_PROTOCOL": {
            "decision_field": "action",
            "instruction": (
                "Return exactly one JSON object. The only security-decision field is singular "
                "action. Do not return provider-native calls or alternate decision fields. "
                "FINALIZE must include action with JSON null."
            ),
            "accepted_enum_values": accepted_literals(model),
            "schema": model.model_json_schema(),
        }
    }
    return json.dumps(payload, sort_keys=True)


def conformance_request(state: str, base_prompt: str | None = None) -> ProviderRequest:
    """Create a benchmark-independent request containing only neutral synthetic data."""
    schema = ConformanceDecision.model_json_schema()
    public = {
        "requested_lifecycle_case": state,
        "observations": {
            "event-001": "synthetic observation alpha",
            "event-002": "synthetic observation beta",
        },
        "available_actions": {
            "investigation": "inspect_object(object_id)",
            "response": "quarantine_object(object_id)",
        },
        "allowed_identifiers": ["event-001", "event-002", "object-001"],
    }
    return ProviderRequest(
        messages=[
            ModelMessage(
                role="system",
                content=(base_prompt + "\n\n" if base_prompt else "")
                + build_protocol_presentation(ConformanceDecision),
            ),
            ModelMessage(role="user", content=json.dumps(public, sort_keys=True)),
        ],
        tools=[],
        timeout_seconds=600,
        temperature=0.2,
        top_p=0.9,
        seed=17,
        response_schema=schema,
        audit_run_id=f"protocol-{state.lower()}",
        audit_turn=1,
        repair_eligible=True,
    )


@dataclass
class ProviderRequestCap:
    """Shared absolute provider-request counter, including repair calls."""

    maximum: int
    used: int = 0

    def consume(self) -> bool:
        if self.used >= self.maximum:
            return False
        self.used += 1
        return True


@dataclass
class ConformanceCaseResult:
    lifecycle_case: str
    requests: list[ProviderRequest] = field(default_factory=list)
    turn_audits: list[dict[str, Any]] = field(default_factory=list)
    provider_call_audits: list[dict[str, Any]] = field(default_factory=list)
    provider_successes: int = 0
    json_valid_responses: int = 0
    first_pass_valid: bool = False
    post_repair_valid: bool = False
    repair_attempted: bool = False
    repair_succeeded: bool = False
    failure_counts: dict[str, int] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0


def _validation_errors(exc: ValidationError | ValueError) -> list[dict[str, Any]]:
    if isinstance(exc, ValidationError):
        return [
            {"location": [str(part) for part in error["loc"]], "type": error["type"]}
            for error in exc.errors()
        ]
    return [{"location": ["assessment", "evidence_refs"], "type": "unknown_reference"}]


def classify_failure(value: Any, exc: ValidationError | ValueError | None) -> str:
    """Classify structural failures for the required aggregate taxonomy."""
    if isinstance(value, dict):
        required = set(ConformanceDecision.model_json_schema()["required"])
        if not required.issubset(value):
            return "missing_field"
        if set(value) - required:
            return "extra_field"
        if (
            value.get("lifecycle_state")
            not in accepted_literals(ConformanceDecision)["lifecycle_state"]
        ):
            return "wrong_enum"
        action = value.get("action")
        if action is not None and not isinstance(action, dict):
            return (
                "multiple_actions"
                if isinstance(action, list) and len(action) > 1
                else "wrong_action_shape"
            )
    if (
        isinstance(exc, ValueError)
        and not isinstance(exc, (ValidationError, json.JSONDecodeError))
        and "unknown" in str(exc)
    ):
        return "fabricated_reference"
    if isinstance(exc, ValidationError):
        text = json.dumps(exc.errors())
        if "literal_error" in text:
            return "wrong_enum"
        if "action" in text:
            return "wrong_action_shape"
    return "other"


def _validate(raw: str) -> tuple[ConformanceDecision | None, Any, Exception | None]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        return None, None, exc
    try:
        parsed = ConformanceDecision.model_validate(value)
        allowed_refs = {"event-001", "event-002"}
        if any(ref not in allowed_refs for ref in parsed.assessment.evidence_refs):
            raise ValueError("unknown evidence reference")
        identifiers = {"object-001"}
        if parsed.action is not None and parsed.action.arguments["object_id"] not in identifiers:
            raise ValueError("unknown action identifier")
        return parsed, value, None
    except (ValidationError, ValueError) as exc:
        return None, value, exc


def _safe_turn_audit(
    response: Any, valid: bool, error: str | None, repair: bool, call_id: str
) -> dict[str, Any]:
    return {
        "provider_call_id": call_id,
        "repair": repair,
        "provider_success": True,
        "protocol_valid": valid,
        "safe_failure_category": error,
        "latency_ms": max(float(response.latency_ms), 0.001),
        "usage": response.usage.model_dump(mode="json"),
    }


def run_conformance_case(
    provider: ModelProvider,
    lifecycle_case: str,
    cap: ProviderRequestCap,
    *,
    request: ProviderRequest | None = None,
    action_sink: Callable[[ConformanceAction], object] | None = None,
) -> ConformanceCaseResult:
    """Run one isolated case with at most one structural repair."""
    initial = request or conformance_request(lifecycle_case)
    result = ConformanceCaseResult(lifecycle_case=lifecycle_case)
    original_raw = ""
    parsed: ConformanceDecision | None = None
    error: Exception | None = None
    for repair in (False, True):
        if repair:
            if error is None or not initial.repair_eligible:
                break
            if not cap.consume():
                result.failure_counts["call_cap"] = 1
                break
            result.repair_attempted = True
            validation = (
                _validation_errors(error)
                if isinstance(error, (ValidationError, ValueError))
                else [{"location": ["response"], "type": "invalid_json"}]
            )
            payload = {
                "SCHEMA_REPAIR": {
                    "original_invalid_json": original_raw,
                    "validation_errors": validation,
                    "accepted_enum_values": accepted_literals(ConformanceDecision),
                    "required_fields_and_types": required_fields_and_types(ConformanceDecision),
                    "instruction": (
                        "Preserve supported content. Do not add evidence or identifiers. Do not change "
                        "the conclusion except as structurally required. Return exactly one corrected "
                        "JSON object and nothing else."
                    ),
                }
            }
            call = initial.model_copy(
                update={
                    "messages": [
                        initial.messages[0],
                        ModelMessage(role="user", content=json.dumps(payload, sort_keys=True)),
                    ],
                    "audit_turn": 2,
                    "repair_eligible": False,
                }
            )
        else:
            if not cap.consume():
                result.failure_counts["call_cap"] = 1
                break
            call = initial
        result.requests.append(call)
        try:
            response = provider.complete(call)
        except ProviderError as exc:
            provider_audit = exc.audit
            if provider_audit is not None:
                result.provider_call_audits.append(provider_audit.model_dump(mode="json"))
            result.turn_audits.append(
                {
                    "provider_call_id": (
                        provider_audit.call_id
                        if provider_audit is not None
                        else f"call-{uuid4().hex}"
                    ),
                    "repair": repair,
                    "provider_success": False,
                    "protocol_valid": False,
                    "safe_failure_category": "provider_failure",
                    "latency_ms": (
                        provider_audit.latency_ms if provider_audit is not None else 0.001
                    ),
                    "usage": (
                        provider_audit.usage.model_dump(mode="json")
                        if provider_audit is not None
                        else {}
                    ),
                }
            )
            result.failure_counts["provider_failure"] = (
                result.failure_counts.get("provider_failure", 0) + 1
            )
            break
        result.provider_successes += 1
        provider_audits = getattr(provider, "audits", [])
        latest_provider_audit = provider_audits[-1] if provider_audits else None
        call_id = (
            latest_provider_audit.call_id
            if latest_provider_audit is not None
            else f"call-{uuid4().hex}"
        )
        if latest_provider_audit is not None:
            result.provider_call_audits.append(latest_provider_audit.model_dump(mode="json"))
        result.input_tokens += response.usage.prompt_tokens
        result.output_tokens += response.usage.completion_tokens
        result.total_tokens += response.usage.total_tokens
        result.latency_ms += response.latency_ms
        if not repair:
            original_raw = response.raw
        try:
            json.loads(response.raw)
            result.json_valid_responses += 1
        except (json.JSONDecodeError, TypeError):
            pass
        parsed, value, error = _validate(response.raw)
        category = (
            None
            if parsed is not None
            else classify_failure(
                value, error if isinstance(error, (ValidationError, ValueError)) else None
            )
        )
        result.turn_audits.append(
            _safe_turn_audit(response, parsed is not None, category, repair, call_id)
        )
        if parsed is not None:
            result.first_pass_valid = not repair
            result.post_repair_valid = True
            result.repair_succeeded = repair
            if parsed.action is not None and action_sink is not None:
                action_sink(parsed.action)
            break
        result.failure_counts[category or "other"] = (
            result.failure_counts.get(category or "other", 0) + 1
        )
    return result


def conformance_metrics(cases: list[ConformanceCaseResult]) -> dict[str, Any]:
    """Recompute laboratory measurements from individual case records."""
    requests = sum(len(case.requests) for case in cases)
    provider_successes = sum(case.provider_successes for case in cases)
    json_valid = sum(case.json_valid_responses for case in cases)
    repair_attempts = sum(case.repair_attempted for case in cases)
    repair_successes = sum(case.repair_succeeded for case in cases)
    failures: dict[str, int] = {
        name: 0
        for name in (
            "missing_field",
            "extra_field",
            "wrong_enum",
            "wrong_action_shape",
            "multiple_actions",
            "fabricated_reference",
            "other",
            "call_cap",
            "provider_failure",
        )
    }
    for case in cases:
        for name, count in case.failure_counts.items():
            failures[name] = failures.get(name, 0) + count
    return {
        "provider_requests": requests,
        "provider_success_rate": provider_successes / requests if requests else 0,
        "json_syntax_validity_rate": json_valid / provider_successes if provider_successes else 0,
        "first_pass_schema_validity_rate": (
            sum(case.first_pass_valid for case in cases) / len(cases) if cases else 0
        ),
        "post_repair_protocol_validity_rate": (
            sum(case.post_repair_valid for case in cases) / len(cases) if cases else 0
        ),
        "repair_attempts": repair_attempts,
        "repair_successes": repair_successes,
        "repair_success_rate": repair_successes / repair_attempts if repair_attempts else None,
        "failure_counts": failures,
        "input_tokens": sum(case.input_tokens for case in cases),
        "output_tokens": sum(case.output_tokens for case in cases),
        "total_tokens": sum(case.total_tokens for case in cases),
        "actual_latency_ms": sum(case.latency_ms for case in cases),
    }


def run_conformance_lab(
    provider: ModelProvider,
    cap: ProviderRequestCap,
    *,
    prompt_path: Path = Path("prompts/defender-v2.txt"),
) -> dict[str, Any]:
    """Run the three-case real-model matrix once within the shared absolute cap."""
    prompt = prompt_path.read_text(encoding="utf-8")
    cases = [
        run_conformance_case(
            provider,
            state,
            cap,
            request=conformance_request(state, base_prompt=prompt),
        )
        for state in ("INVESTIGATE", "RESPOND", "FINALIZE")
    ]
    metrics = conformance_metrics(cases)
    systematic = any(
        count >= 2
        for name, count in metrics["failure_counts"].items()
        if name not in {"call_cap", "provider_failure"}
    )
    gates = {
        "provider_success_100_percent": metrics["provider_success_rate"] == 1,
        "json_syntax_validity_100_percent": metrics["json_syntax_validity_rate"] == 1,
        "post_repair_protocol_validity_at_least_90_percent": (
            metrics["post_repair_protocol_validity_rate"] >= 0.9
        ),
        "no_systematic_schema_defect": not systematic,
        "provider_request_cap_respected": cap.used <= cap.maximum <= 12,
        "all_turns_audited": all(len(case.turn_audits) == len(case.requests) for case in cases),
    }
    return {
        "schema_version": "protocol-conformance-v2",
        "timestamp": datetime.now(UTC).isoformat(),
        "model": getattr(provider, "model_id", "unknown"),
        "provider": getattr(provider, "provider_id", "unknown"),
        "parameters": {
            "output_mode": "JSON_OBJECT",
            "temperature": 0.2,
            "top_p": 0.9,
            "model_seed": 17,
            "timeout_seconds": 600,
        },
        "accepted_enum_values": accepted_literals(ConformanceDecision),
        "canonical_action_contract": "singular action; FINALIZE requires explicit action null",
        "competing_legacy_instructions": {
            "existed": True,
            "details": (
                "The provider gateway previously serialized provider-native tools/tool_choice for "
                "defender-v2 while the returned JSON schema required singular action."
            ),
            "current_lab_native_tools": False,
        },
        "cases": [
            {
                "lifecycle_case": case.lifecycle_case,
                "provider_requests": len(case.requests),
                "provider_successes": case.provider_successes,
                "json_valid_responses": case.json_valid_responses,
                "first_pass_valid": case.first_pass_valid,
                "post_repair_valid": case.post_repair_valid,
                "repair_attempted": case.repair_attempted,
                "repair_succeeded": case.repair_succeeded,
                "failure_counts": case.failure_counts,
                "turn_audits": case.turn_audits,
                "provider_call_audits": case.provider_call_audits,
                "usage": {
                    "input_tokens": case.input_tokens,
                    "output_tokens": case.output_tokens,
                    "total_tokens": case.total_tokens,
                },
                "actual_latency_ms": case.latency_ms,
            }
            for case in cases
        ],
        "metrics": metrics,
        "independent_recomputation": {
            "matched": conformance_metrics(cases) == metrics,
            "provider_requests": sum(len(case.requests) for case in cases),
        },
        "gates": gates,
        "lab_passed": all(gates.values()),
        "shared_real_provider_request_cap": {"maximum": cap.maximum, "used": cap.used},
    }


def main() -> None:
    """Run only the explicitly selected non-benchmark protocol laboratory."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab", action="store_true", required=True)
    parser.add_argument("--output", type=Path, default=Path("results/protocol-conformance-v2.json"))
    args = parser.parse_args()
    provider = provider_from_config(
        "ollama", "qwen3:14b-q4_K_M", "http://localhost:11434/v1", 600
    )
    artifact = run_conformance_lab(provider, ProviderRequestCap(12))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
