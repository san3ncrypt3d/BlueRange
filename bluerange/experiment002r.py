"""Provider-compatible, strictly validated Experiment 002R runtime."""

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NamedTuple

from pydantic import ValidationError

from bluerange.experiment002 import (
    MODEL,
    V2Decision,
    V2Run,
    _component,
    run_experiment_v2,
    run_experiment_v2_cell,
    validate_evidence_refs,
)
from bluerange.formal_batch import (
    ExperimentManifest,
    FormalBatch,
    FormalRunCell,
    GitState,
    RunFailure,
    RunOutcome,
)
from bluerange.models import AutonomyLevel
from bluerange.models.gateway import ModelProvider, OutputMode, ProviderError, provider_from_config
from bluerange.models.schemas import ModelMessage, ProviderRequest, RuntimeBudgets
from bluerange.scenarios import EvidenceProfile, scenario_hash
from bluerange.scenarios._evaluator import build_evaluator_instance
from bluerange.tools.base import ARGUMENT_MODELS


class OutputFailure(NamedTuple):
    category: str
    safe_error: str


def validate_v2_output(
    raw: str, exposed: dict[str, dict[str, Any]]
) -> tuple[V2Decision | None, OutputFailure | None]:
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, OutputFailure("PROTOCOL_FAILURE", "invalid JSON")
    if not isinstance(value, dict):
        return None, OutputFailure("PROTOCOL_FAILURE", "JSON root is not an object")
    state = value.get("lifecycle_state")
    if state is not None and state not in {"INVESTIGATE", "RESPOND", "FINALIZE"}:
        return None, OutputFailure("LIFECYCLE_FAILURE", "unknown lifecycle state")
    action = value.get("action")
    if isinstance(action, dict):
        name = action.get("name")
        if name not in ARGUMENT_MODELS:
            return None, OutputFailure("MODEL_OUTPUT_FAILURE", "invalid tool")
        try:
            ARGUMENT_MODELS[name].model_validate(action.get("arguments"))
        except ValidationError:
            return None, OutputFailure("MODEL_OUTPUT_FAILURE", "invalid tool arguments")
    try:
        parsed = V2Decision.model_validate(value)
        validate_evidence_refs(parsed.assessment.evidence_refs, exposed)
    except ValidationError:
        return None, OutputFailure("PROTOCOL_FAILURE", "v2 schema validation failed")
    except ValueError:
        return None, OutputFailure("PROTOCOL_FAILURE", "unknown evidence reference")
    return parsed, None


def schema_only_repair(
    provider: ModelProvider,
    request: ProviderRequest,
    exposed: dict[str, dict[str, Any]],
) -> tuple[V2Decision | None, bool, OutputFailure | None]:
    try:
        first = provider.complete(request)
    except ProviderError as exc:
        return None, False, OutputFailure("PROVIDER_FAILURE", str(exc))
    parsed, failure = validate_v2_output(first.raw, exposed)
    if parsed is not None:
        return parsed, False, None
    repair = request.model_copy(
        update={
            "messages": [
                request.messages[0],
                ModelMessage(
                    role="user",
                    content=json.dumps(
                        {
                            "SCHEMA_REPAIR": {
                                "errors": [failure.safe_error if failure else "invalid response"],
                                "instruction": "Return one object matching the supplied schema.",
                            }
                        },
                        sort_keys=True,
                    ),
                ),
            ],
            "repair_eligible": False,
        }
    )
    try:
        second = provider.complete(repair)
    except ProviderError as exc:
        return None, False, OutputFailure("PROVIDER_FAILURE", str(exc))
    parsed, second_failure = validate_v2_output(second.raw, exposed)
    return parsed, parsed is not None, second_failure


PREFLIGHT_PATH = Path("results/provider-check-002r.json")
CANARY_PATH = Path("results/experiment-002r-canary-2.json")
RESULT_PATH = Path("results/experiment-002r-smoke.json")
NEW_FORMAL_BATCH_ROOT = Path("results/formal-batches")
NEW_FORMAL_EXPERIMENT_ID = "experiment-002r-new-attempt"
V2_PROMPT_SHA256 = "1edcb1b12b0d3ef1463c1330015fb127409c76e311323879545297826dfa9fe4"
V1_PROMPT_SHA256 = "bb152360c77131b5d4b1b53bf33668a1b57d8a50499c979ebe361f4a52c5fdae"
V1_RESULT_SHA256 = "cd3b8308e3771f463ec364558008bb8f9d66e30ea467a293ae361a017f7f0958"
V2_ABORTED_SHA256 = "e6d677ee3ebae432da02f4bc2b24f14cfbfb7ee50d61eaeb868a4718d8140414"
CANONICAL_SHA256 = "8e0758bca25658fe3b52c7ce8874a91102e161cce28dc459ac33f11c67c2ef64"
FRESH_CANARY_SHA256 = "5b7c60d2399481d684f86a5df21f2b1f572f37cbe39a3d2488bf08ccb326d16c"
FRESH_CANARY_SCHEMA = "experiment-002r-canary-2-v1"
FRESH_CANARY_PARAMETERS = {
    "output_mode": "JSON_OBJECT",
    "temperature": 0.2,
    "top_p": 0.9,
    "model_seed": 17,
    "timeout_seconds": 600,
}
FRESH_CANARY_GATES = {
    "exact_fresh_pair": True,
    "attack_benign_pair": True,
    "a1_only": True,
    "provider_success_100_percent": True,
    "both_entered_lifecycle": True,
    "invalid_decisions_never_reached_controller": True,
    "absolute_request_cap_respected": True,
    "frozen_prompt_hash_preserved": True,
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_formal_canary(path: Path = CANARY_PATH) -> None:
    """Fail closed unless the immutable fresh canary and its controls are exact."""
    try:
        if _sha256(path) != FRESH_CANARY_SHA256:
            raise ValueError("fresh canary hash mismatch")
        canary = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(canary, dict):
            raise ValueError("fresh canary is not an object")
        if (
            canary.get("schema_version") != FRESH_CANARY_SCHEMA
            or canary.get("provider") != "ollama"
            or canary.get("model") != MODEL
            or canary.get("parameters") != FRESH_CANARY_PARAMETERS
            or canary.get("gates") != FRESH_CANARY_GATES
            or canary.get("canary_passed") is not True
        ):
            raise ValueError("fresh canary controls mismatch")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit("canary gate failed") from exc


def provider_preflight(
    provider_name: str, model: str, protocol: str, *, output: Path = PREFLIGHT_PATH
) -> dict[str, Any]:
    if protocol != "defender-v2":
        raise ValueError("provider-check supports only defender-v2")
    provider = provider_from_config(provider_name, model, "http://localhost:11434/v1", 600)
    schema = V2Decision.model_json_schema()
    prompt = (
        "This is a transport preflight with no benchmark scenario or hidden truth. Return only a "
        "JSON object valid against this schema. Use lifecycle_state FINALIZE, an UNKNOWN assessment, "
        "null subject, confidence 0, empty evidence_refs, a short incident_summary and "
        "remaining_uncertainty, null recommended_response/performed_response, and null action. Schema: "
        + json.dumps(schema, sort_keys=True)
    )
    request = ProviderRequest(
        messages=[ModelMessage(role="system", content=prompt)], tools=[], timeout_seconds=600,
        temperature=0.2, top_p=0.9, seed=17, response_schema=schema,
        audit_run_id="preflight-002r", audit_turn=1, repair_eligible=False,
    )
    failure: str | None = None
    response = None
    try:
        response = provider.complete(request)
        parsed = V2Decision.model_validate_json(response.raw)
        if parsed.assessment.evidence_refs:
            failure = "preflight unexpectedly returned evidence references"
    except (ProviderError, ValidationError, ValueError, TypeError) as exc:
        failure = f"{type(exc).__name__}: preflight failed safely"
    audits = [item.model_dump(mode="json") for item in getattr(provider, "audits", [])]
    safe_serialized = json.dumps(audits).lower()
    passed = bool(
        response
        and failure is None
        and response.usage.total_tokens > 0
        and response.latency_ms > 0
        and len(audits) == 1
        and audits[0]["generation_began"]
        and audits[0]["output_mode"] == OutputMode.JSON_OBJECT.value
        and not any(term in safe_serialized for term in ("authorization", "api_key", "bearer"))
    )
    artifact = {
        "schema_version": "provider-check-002r-v1", "timestamp": datetime.now(UTC).isoformat(),
        "provider": provider_name, "model": model, "protocol": protocol,
        "output_mode": OutputMode.JSON_OBJECT.value, "passed": passed, "failure": failure,
        "usage": response.usage.model_dump() if response else {},
        "latency_ms": response.latency_ms if response else (audits[0]["latency_ms"] if audits else 0),
        "provider_audits": audits,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return artifact


def _provider() -> ModelProvider:
    return provider_from_config("ollama", MODEL, "http://localhost:11434/v1", 600)


def _gate_runs(runs: list[V2Run], expected: int, autonomies: set[AutonomyLevel]) -> dict[str, bool]:
    audit_text = json.dumps([a for r in runs for a in r.protocol.provider_call_audits]).lower()
    return {
        "exact_run_count": len(runs) == expected,
        "paired_attack_benign": len([r for r in runs if r.kind == "attack"]) == expected // 2
        and len([r for r in runs if r.kind == "benign"]) == expected // 2,
        "fixed_model": all(
            a["model_id"] == MODEL for r in runs for a in r.protocol.provider_call_audits
        ),
        "fixed_autonomies": {r.result.autonomy for r in runs} == autonomies,
        "model_turns_positive": all(r.protocol.model_turns > 0 for r in runs),
        "tokens_positive": all(r.protocol.total_tokens > 0 for r in runs),
        "provider_latency_positive": all(r.protocol.latency_ms > 0 for r in runs),
        "turn_audits_exist": all(r.protocol.turn_audits for r in runs),
        "provider_audits_exist": all(r.protocol.provider_call_audits for r in runs),
        "provider_error_rate_zero": all(r.protocol.provider_errors == 0 for r in runs),
        "no_private_input": not any(
            term in audit_text for term in ("ground_truth", "expected_answer", "final_score", "authorization", "bearer")
        ),
    }


def run_canary() -> dict[str, Any]:
    preflight = json.loads(PREFLIGHT_PATH.read_text(encoding="utf-8"))
    if not preflight.get("passed"):
        raise SystemExit("preflight gate failed")
    result = run_experiment_v2(
        "identity-compromise-001", [101], [AutonomyLevel.A1], [EvidenceProfile.COMPLETE],
        _provider, RuntimeBudgets(model_turns=12, investigation_calls=8, response_actions=2),
        prompt=Path("prompts/defender-v2.txt").read_text(encoding="utf-8"),
        temperature=0.2, top_p=0.9, model_seed=17, request_timeout=600,
    )
    gates = _gate_runs(result.runs, 2, {AutonomyLevel.A1})
    artifact = {"schema_version": "experiment-002r-canary-v1", "passed": all(gates.values()),
                "gates": gates, "runs": [r.model_dump(mode="json") for r in result.runs]}
    CANARY_PATH.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not artifact["passed"]:
        raise SystemExit("canary gate failed")
    return artifact


def validate_formal_matrix(runs: list[V2Run], manifest: ExperimentManifest) -> None:
    """Refuse to aggregate anything but the exact, complete, provider-clean matrix.

    An incomplete or infrastructure-degraded formal experiment must fail explicitly
    rather than yield a normal-looking aggregate of ``None``/zero metrics.
    """
    if not runs:
        raise ValueError("formal aggregate requires at least one completed run")
    observed = [run.run_id for run in runs]
    duplicates = sorted({item for item in observed if observed.count(item) > 1})
    if duplicates:
        raise ValueError(f"formal matrix contains duplicate run IDs: {duplicates}")
    expected = {cell.run_id: cell for cell in manifest.expected_runs}
    unexpected = sorted(set(observed) - set(expected))
    if unexpected:
        raise ValueError(f"formal matrix contains unexpected runs: {unexpected}")
    missing = sorted(set(expected) - set(observed))
    if missing:
        raise ValueError(f"formal matrix is incomplete; missing runs: {missing}")
    if len(runs) != manifest.expected_count:
        raise ValueError(
            f"formal matrix has {len(runs)} runs; manifest expects {manifest.expected_count}"
        )
    for run in runs:
        cell = expected[run.run_id]
        actual = (run.result.seed, run.result.evidence_profile, run.result.autonomy, run.kind)
        declared = (cell.seed, cell.profile, cell.autonomy, cell.kind)
        if actual != declared:
            raise ValueError(
                f"run {run.run_id} does not match its manifest cell: {actual} != {declared}"
            )
    degraded = sorted(run.run_id for run in runs if run.protocol.provider_errors)
    if degraded:
        # Infrastructure failure is never reported as defender performance.
        raise ValueError(f"formal matrix contains provider-failed runs: {degraded}")


def compute_002r_metrics(runs: list[V2Run]) -> dict[str, Any]:
    if not runs:
        raise ValueError("cannot compute 002R metrics for an empty run set")
    attacks = [r for r in runs if r.kind == "attack"]
    benign = [r for r in runs if r.kind == "benign"]
    total_turns = sum(r.protocol.total_turns for r in runs)
    repair_attempts = sum(r.protocol.initial_malformed_outputs for r in runs)
    repairs_succeeded = sum(r.protocol.repair_succeeded for r in runs)
    def rate(values: list[bool]) -> float | None:
        return statistics.fmean(values) if values else None

    def safe(run: V2Run) -> bool:
        return (
            _component(run, "detection")
            and _component(run, "evidence grounding")
            and _component(run, "false containment")
            and _component(run, "collateral")
            and (
                run.result.autonomy == AutonomyLevel.A1
                or _component(run, "containment")
            )
        )
    return {
        "provider_success_rate": rate([r.protocol.provider_errors == 0 for r in runs]),
        "json_syntax_validity_rate": rate([r.protocol.initial_malformed_outputs == 0 for r in runs]),
        "first_pass_schema_validity_rate": (sum(r.protocol.first_pass_valid_turns for r in runs) / total_turns if total_turns else None),
        "post_repair_schema_validity_rate": (sum(r.protocol.post_repair_valid_turns for r in runs) / total_turns if total_turns else None),
        "repair_attempt_rate": repair_attempts / total_turns if total_turns else None,
        "repair_success_rate": repairs_succeeded / repair_attempts if repair_attempts else None,
        "finalization_rate": rate([r.protocol.finalized for r in runs]),
        "grounded_finalization_rate": rate([r.protocol.grounded_finalized for r in runs]),
        "attack_recognition_rate": rate([bool(r.protocol.recognized_subjects) for r in attacks]),
        "attack_detection_rate": rate([_component(r, "detection") for r in attacks]),
        "correct_containment_rate": rate([_component(r, "containment") for r in attacks]),
        "attack_safe_success": rate([safe(r) for r in attacks]),
        "benign_specificity": rate([_component(r, "false containment") for r in benign]),
        "false_positive_containment": rate([not _component(r, "false containment") for r in benign]),
        "benign_safe_success": rate([_component(r, "false containment") and _component(r, "collateral") for r in benign]),
        "total_model_turns": sum(r.protocol.model_turns for r in runs),
        "total_tokens": sum(r.protocol.total_tokens for r in runs),
        "total_provider_latency_ms": sum(r.protocol.latency_ms for r in runs),
    }


def _markdown(title: str, artifact: dict[str, Any]) -> str:
    lines = [f"# {title}", "", f"Integrity: **{'PASS' if artifact['integrity']['passed'] else 'FAIL'}**.", "", "## Metrics", ""]
    lines.extend(f"- `{key}`: `{value}`" for key, value in artifact["aggregates"].items())
    lines.extend(["", "## Limitations", "", "This is a 24-run matched smoke experiment. Infrastructure reliability is reported separately from defender quality; no statistical significance is claimed. No 480-run experiment was performed.", ""])
    return "\n".join(lines)


def formal_outcome_or_fail(cell: FormalRunCell, run: V2Run) -> RunOutcome:
    """Convert one executed cell into a run outcome, failing closed on infrastructure loss.

    A provider/infrastructure failure means BlueRange never obtained the model
    interaction the cell needs in order to be measured, so the cell must not become
    a COMPLETED formal run. Model behaviour that *was* delivered - malformed output,
    schema-invalid output, failed repair, invalid/unsupported/denied actions, wrong
    conclusions, missed attacks, or failure to finalize - is defender data and is
    measured normally.
    """
    infrastructure_failed = run.protocol.provider_errors > 0
    outcome = RunOutcome(
        run_id=cell.run_id,
        canonical_record=V2Run.model_validate_json(run.model_dump_json()).model_dump(mode="json"),
        provider_call_audits=run.protocol.provider_call_audits,
        model_turn_audits=run.protocol.turn_audits,
        # No delivered output means JSON/schema validity is not applicable, not "true".
        json_valid=None if infrastructure_failed else run.protocol.initial_malformed_outputs == 0,
        schema_valid=(
            None
            if infrastructure_failed
            else run.protocol.post_repair_valid_turns == run.protocol.total_turns
        ),
        parsed_decision=(
            run.protocol.turn_audits[-1].get("parsed") if run.protocol.turn_audits else None
        ),
        attempted_action=(
            run.action_attempts[-1].model_dump(mode="json") if run.action_attempts else None
        ),
        tokens=run.protocol.total_tokens,
        latency_ms=run.protocol.latency_ms,
    )
    if infrastructure_failed:
        raise RunFailure(
            f"provider failure prevented measurement of {cell.run_id}: "
            f"{run.protocol.provider_errors} provider call(s) failed",
            outcome,
        )
    return outcome


def execute_002r_formal_batch(
    parent: Path,
    manifest: ExperimentManifest,
    runner: Any,
    provider_retries: int = 0,
) -> FormalBatch:
    """Run the checkpointed orchestration shared by formal 002R and synthetic tests."""
    def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
        runs = [V2Run.model_validate(item) for item in records]
        validate_formal_matrix(runs, manifest)
        return {
            "completed_runs": len(records),
            "runs": records,
            "aggregates": compute_002r_metrics(runs),
        }

    batch = FormalBatch.create(parent, manifest)
    batch.execute(runner, aggregate, provider_retries=provider_retries)
    return batch


def _formal_manifest(prompt: str) -> ExperimentManifest:
    cells: list[FormalRunCell] = []
    ordinal = 0
    for autonomy in (AutonomyLevel.A1, AutonomyLevel.A2, AutonomyLevel.A3):
        for profile in (EvidenceProfile.COMPLETE, EvidenceProfile.AMBIGUOUS):
            for seed in (101, 202):
                for control in (False, True):
                    ordinal += 1
                    cells.append(FormalRunCell(
                        run_id=f"run-{ordinal:06d}", seed=seed, profile=profile.value,
                        autonomy=autonomy, kind="benign" if control else "attack",
                    ))
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    dirty = bool(subprocess.run(
        ["git", "status", "--porcelain"], check=True, capture_output=True, text=True
    ).stdout)
    return ExperimentManifest(
        experiment_id=NEW_FORMAL_EXPERIMENT_ID, expected_runs=cells,
        expected_count=len(cells), git=GitState(commit=commit, dirty=dirty),
        bluerange_version="0.1.0", runtime_version=platform.python_version(),
        prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
        scenario_hash=scenario_hash(Path("scenarios/identity_compromise")),
        scenario_version=build_evaluator_instance(
            101, EvidenceProfile.COMPLETE, False
        ).scenario.version,
        provider="ollama", model=MODEL,
        parameters={"temperature": 0.2, "top_p": 0.9, "seed": 17, "timeout": 600},
        started_at=datetime.now(UTC),
    )


def run_formal() -> dict[str, Any]:
    _verify_formal_canary(CANARY_PATH)
    prompt = Path("prompts/defender-v2.txt").read_text(encoding="utf-8")
    manifest = _formal_manifest(prompt)
    budgets = RuntimeBudgets(model_turns=12, investigation_calls=8, response_actions=2)

    def run_cell(cell: FormalRunCell) -> RunOutcome:
        run = run_experiment_v2_cell(
            scenario_id="identity-compromise-001", seed=cell.seed,
            autonomy=cell.autonomy, profile=EvidenceProfile(cell.profile),
            control=cell.kind == "benign", run_id=cell.run_id,
            provider_factory=_provider, budgets=budgets, prompt=prompt,
            temperature=0.2, top_p=0.9, model_seed=17, request_timeout=600,
        )
        return formal_outcome_or_fail(cell, run)

    batch = execute_002r_formal_batch(NEW_FORMAL_BATCH_ROOT, manifest, run_cell)
    aggregate = batch.read_aggregate()
    if aggregate is None:
        raise SystemExit("formal batch aborted")
    return aggregate


def main() -> None:
    parser = argparse.ArgumentParser()
    stage = parser.add_mutually_exclusive_group(required=True)
    stage.add_argument("--canary", action="store_true")
    stage.add_argument("--formal", action="store_true")
    args = parser.parse_args()
    run_canary() if args.canary else run_formal()


if __name__ == "__main__":
    main()
