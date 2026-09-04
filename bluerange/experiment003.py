"""Offline preparation and actual-path execution for Experiment 003 Sonnet canaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from bluerange.experiment002 import V2Decision, V2Run, run_experiment_v2_cell
from bluerange.experiment002r import execute_002r_formal_batch, formal_outcome_or_fail
from bluerange.formal_batch import (
    DecisionContractProvenance,
    ExperimentManifest,
    FormalRunCell,
    GitState,
)
from bluerange.models import AutonomyLevel, FrozenStrictModel
from bluerange.models.gateway import AnthropicProvider, ModelProvider, OutputMode
from bluerange.models.schemas import RuntimeBudgets
from bluerange.protocol_conformance import build_protocol_presentation
from bluerange.scenarios import EvidenceProfile, scenario_hash
from bluerange.scenarios._evaluator import build_evaluator_instance

CANARY_LABEL = "NON-FORMAL CANARY"
CANARY_CELL = FormalRunCell(
    run_id="sonnet-canary-000001",
    seed=101,
    profile=EvidenceProfile.COMPLETE.value,
    autonomy=AutonomyLevel.A1,
    kind="attack",
)
PROMPT_PATH = Path("prompts/defender-v2.txt")
SCENARIO_PATH = Path("scenarios/identity_compromise")
CANARY_OUTPUT = Path("results/experiment-003-sonnet-canary.json")


class ExperimentV2Configuration(FrozenStrictModel):
    """Small provider/model treatment configuration layered over frozen V2 machinery."""

    provider: Literal["anthropic", "ollama"]
    model: str = Field(min_length=1, max_length=128)
    output_mode: OutputMode
    timeout_seconds: float = Field(gt=0, le=600)
    max_output_tokens: int | None = Field(default=None, ge=1, le=100_000)
    temperature: float = Field(default=0.2, ge=0, le=2)
    top_p: float = Field(default=0.9, gt=0, le=1)
    model_seed: int = Field(default=17, ge=0)

    @model_validator(mode="after")
    def capability_matches_provider(self) -> ExperimentV2Configuration:
        expected = {
            "anthropic": OutputMode.ANTHROPIC_TEXT_JSON,
            "ollama": OutputMode.JSON_OBJECT,
        }[self.provider]
        if self.output_mode is not expected:
            raise ValueError("configured output mode does not match provider capability")
        if self.provider == "anthropic" and self.max_output_tokens is None:
            raise ValueError("Anthropic requires an explicit max-output-token treatment")
        return self

    def supported_model_parameters(self) -> dict[str, Any]:
        if self.provider == "anthropic":
            return {"max_tokens": self.max_output_tokens}
        return {
            "temperature": self.temperature,
            "top_p": self.top_p,
            "seed": self.model_seed,
        }

    def omitted_provider_parameters(self) -> list[str]:
        return ["temperature", "top_p", "seed"] if self.provider == "anthropic" else []


SONNET_CANARY_CONFIG = ExperimentV2Configuration(
    provider="anthropic",
    model="claude-sonnet-5",
    output_mode=OutputMode.ANTHROPIC_TEXT_JSON,
    timeout_seconds=600,
    max_output_tokens=16384,
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_file(path: Path) -> str:
    return _hash_bytes(path.read_bytes())


def _hash_tree(path: Path) -> str:
    digest = hashlib.sha256()
    for item in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        relative = item.relative_to(path).as_posix().encode("utf-8")
        content = item.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def build_decision_contract_provenance(
    config: ExperimentV2Configuration,
    prompt: str,
) -> DecisionContractProvenance:
    """Hash the complete deterministic static contract used by every V2 turn."""
    schema = V2Decision.model_json_schema()
    presentation = build_protocol_presentation(V2Decision)
    system_contract = prompt + "\n\n" + presentation
    config_record = {
        **config.model_dump(mode="json"),
        "provider_supported_model_parameters": config.supported_model_parameters(),
        "provider_omitted_parameters": config.omitted_provider_parameters(),
    }
    return DecisionContractProvenance(
        defender_prompt_sha256=_hash_bytes(prompt.encode("utf-8")),
        scenario_sha256=scenario_hash(SCENARIO_PATH),
        authoritative_schema_sha256=_hash_bytes(_canonical_bytes(schema)),
        protocol_presentation_sha256=_hash_bytes(presentation.encode("utf-8")),
        static_system_contract_sha256=_hash_bytes(system_contract.encode("utf-8")),
        experiment_configuration_sha256=_hash_bytes(_canonical_bytes(config_record)),
        autonomy_surface_sha256=_hash_file(Path("bluerange/models/legacy.py")),
        scoring_surface_sha256=_hash_tree(Path("bluerange/scoring")),
        evaluator_surface_sha256=_hash_file(Path("bluerange/scenarios/_evaluator.py")),
        protocol_source_sha256=_hash_file(Path("bluerange/protocol_conformance.py")),
        provider=config.provider,
        model=config.model,
        output_mode=config.output_mode.value,
        supported_model_parameters=config.supported_model_parameters(),
    )


def provider_factory(config: ExperimentV2Configuration) -> Callable[[], ModelProvider]:
    """Select transport without changing the V2 runtime or provider-neutral protocol."""
    if config.provider == "anthropic":
        max_tokens = config.max_output_tokens
        assert max_tokens is not None
        return lambda: AnthropicProvider(
            config.model,
            timeout=config.timeout_seconds,
            max_tokens=max_tokens,
        )
    from bluerange.models.gateway import provider_from_config

    return lambda: provider_from_config(
        "ollama",
        config.model,
        "http://localhost:11434/v1",
        config.timeout_seconds,
    )


def prepare_sonnet_canary() -> dict[str, Any]:
    """Build a deterministic, network-free description of the approved next canary."""
    prompt = PROMPT_PATH.read_text(encoding="utf-8")
    contract = build_decision_contract_provenance(SONNET_CANARY_CONFIG, prompt)
    return {
        "schema_version": "experiment-003-canary-plan-v1",
        "label": CANARY_LABEL,
        "formal_evidence": False,
        "external_call_performed": False,
        "execution_path": "bluerange.experiment002.run_experiment_v2_cell",
        "cell": CANARY_CELL.model_dump(mode="json"),
        "provider": SONNET_CANARY_CONFIG.provider,
        "model": SONNET_CANARY_CONFIG.model,
        "output_mode": SONNET_CANARY_CONFIG.output_mode.value,
        "parameters": {
            "provider_supported": SONNET_CANARY_CONFIG.supported_model_parameters(),
            "provider_omitted": SONNET_CANARY_CONFIG.omitted_provider_parameters(),
            "timeout_seconds": SONNET_CANARY_CONFIG.timeout_seconds,
        },
        "budgets": RuntimeBudgets(
            model_turns=12,
            investigation_calls=8,
            response_actions=2,
        ).model_dump(mode="json"),
        "decision_contract": contract.model_dump(mode="json"),
    }


def _safe_canary_observability(run: V2Run, config: ExperimentV2Configuration) -> dict[str, Any]:
    """Project bounded diagnostics while excluding raw model text and model inputs."""
    turn_audits = run.protocol.turn_audits
    provider_audits = run.protocol.provider_call_audits
    first = turn_audits[0] if turn_audits else {}
    schema_errors = [str(item)[:256] for item in first.get("schema_errors", [])][:20]
    json_invalid = any(item.endswith(": json_invalid") for item in schema_errors)
    attempts = [
        {
            "turn": item.turn,
            "tool": item.tool,
            "validation_status": item.validation_status.value,
            "authorization_decision": item.authorization_decision.value,
            "execution_status": item.execution_status.value,
            "safe_failure_category": item.safe_failure_category,
        }
        for item in run.action_attempts
    ]
    return {
        "schema_version": "experiment-003-sonnet-canary-v1",
        "label": CANARY_LABEL,
        "formal_evidence": False,
        "provider_success": bool(provider_audits)
        and run.protocol.provider_errors == 0
        and all(item.get("error_category") is None for item in provider_audits),
        "requested_model": config.model,
        "observed_models": sorted(
            {str(item.get("model_id")) for item in provider_audits if item.get("model_id")}
        ),
        "output_mode": config.output_mode.value,
        "provider_errors": [
            {
                "category": item.get("error_category"),
                "http_status": item.get("http_status"),
                "api_error_type": item.get("api_error_type"),
            }
            for item in provider_audits
            if item.get("error_category") is not None
        ],
        "first_pass_json_syntax_valid": bool(turn_audits) and not json_invalid,
        "first_pass_authoritative_schema_valid": bool(turn_audits)
        and first.get("initial_malformed") is False
        and first.get("parsed") is not None,
        "safe_structural_errors": schema_errors,
        "repair_attempted": run.protocol.repair_attempted,
        "repair_success": run.protocol.repair_succeeded,
        "finalized": run.protocol.finalized,
        "action_attempts": attempts,
        "tool_validation_outcomes": [item["validation_status"] for item in attempts],
        "autonomy_outcomes": [
            {
                "tool": item["tool"],
                "authorization_decision": item["authorization_decision"],
                "execution_status": item["execution_status"],
            }
            for item in attempts
        ],
        "autonomy": run.result.autonomy.value,
        "final_disposition": run.result.disposition.value,
        "token_counts": {
            "input_by_call": run.protocol.input_tokens_by_turn,
            "output_by_call": run.protocol.output_tokens_by_turn,
            "total": run.protocol.total_tokens,
        },
        "latency_ms": run.protocol.latency_ms,
        "safe_failure_categories": run.protocol.failure_categories,
    }


def run_sonnet_canary(output: Path = CANARY_OUTPUT) -> dict[str, Any]:
    """Execute one non-formal canary through the actual V2 benchmark cell path."""
    prompt = PROMPT_PATH.read_text(encoding="utf-8")
    run = run_experiment_v2_cell(
        scenario_id="identity-compromise-001",
        seed=CANARY_CELL.seed,
        autonomy=CANARY_CELL.autonomy,
        profile=EvidenceProfile(CANARY_CELL.profile),
        control=CANARY_CELL.kind == "benign",
        run_id=CANARY_CELL.run_id,
        provider_factory=provider_factory(SONNET_CANARY_CONFIG),
        budgets=RuntimeBudgets(model_turns=12, investigation_calls=8, response_actions=2),
        prompt=prompt,
        temperature=SONNET_CANARY_CONFIG.temperature,
        top_p=SONNET_CANARY_CONFIG.top_p,
        model_seed=SONNET_CANARY_CONFIG.model_seed,
        request_timeout=SONNET_CANARY_CONFIG.timeout_seconds,
    )
    artifact = {
        **_safe_canary_observability(run, SONNET_CANARY_CONFIG),
        "timestamp": datetime.now(UTC).isoformat(),
        "cell": CANARY_CELL.model_dump(mode="json"),
        "decision_contract": build_decision_contract_provenance(
            SONNET_CANARY_CONFIG, prompt
        ).model_dump(mode="json"),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return artifact


def new_formal_manifest(
    *,
    experiment_id: str,
    cells: list[FormalRunCell],
    config: ExperimentV2Configuration,
    prompt: str,
) -> ExperimentManifest:
    """Construct provenance-complete manifests; FormalBatch.create enforces cleanliness."""
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], check=True, capture_output=True, text=True
        ).stdout
    )
    return ExperimentManifest(
        experiment_id=experiment_id,
        expected_runs=cells,
        expected_count=len(cells),
        git=GitState(commit=commit, dirty=dirty),
        bluerange_version="0.1.0",
        runtime_version="experiment-v2-runtime",
        prompt_hash=_hash_bytes(prompt.encode("utf-8")),
        scenario_hash=scenario_hash(SCENARIO_PATH),
        scenario_version=build_evaluator_instance(
            cells[0].seed, EvidenceProfile(cells[0].profile), cells[0].kind == "benign"
        ).scenario.version,
        provider=config.provider,
        model=config.model,
        parameters={
            "output_mode": config.output_mode.value,
            "supported_model_parameters": config.supported_model_parameters(),
            "omitted_provider_parameters": config.omitted_provider_parameters(),
            "timeout_seconds": config.timeout_seconds,
        },
        started_at=datetime.now(UTC),
        provenance_policy="decision-contract-v1",
        decision_contract=build_decision_contract_provenance(config, prompt),
    )


def formal_sonnet_cells() -> list[FormalRunCell]:
    """Return the exact 24-cell matrix matched to historical Experiment 002R."""
    cells: list[FormalRunCell] = []
    ordinal = 0
    for autonomy in (AutonomyLevel.A1, AutonomyLevel.A2, AutonomyLevel.A3):
        for profile in (EvidenceProfile.COMPLETE, EvidenceProfile.AMBIGUOUS):
            for seed in (101, 202):
                for control in (False, True):
                    ordinal += 1
                    cells.append(FormalRunCell(
                        run_id=f"sonnet-003-{ordinal:06d}", seed=seed,
                        profile=profile.value, autonomy=autonomy,
                        kind="benign" if control else "attack",
                    ))
    return cells


def formal_experiment_spec(manifest: ExperimentManifest) -> dict[str, Any]:
    """Return only deterministic scientific identity, excluding execution provenance."""
    return {
        "experiment_id": manifest.experiment_id,
        "design": "Scenario #1 defender-v2 V2Decision 24-cell autonomy/profile/seed/control matrix",
        "expected_runs": [cell.model_dump(mode="json") for cell in manifest.expected_runs],
        "expected_count": manifest.expected_count,
        "provider": manifest.provider,
        "model": manifest.model,
        "output_mode": manifest.parameters["output_mode"],
        "supported_model_parameters": manifest.parameters["supported_model_parameters"],
        "omitted_provider_parameters": manifest.parameters["omitted_provider_parameters"],
        "decision_contract": manifest.decision_contract.model_dump(mode="json") if manifest.decision_contract else None,
        "prompt_hash": manifest.prompt_hash,
        "scenario_hash": manifest.scenario_hash,
        "scenario_version": manifest.scenario_version,
        "provenance_policy": manifest.provenance_policy,
    }


def formal_experiment_spec_hash(manifest: ExperimentManifest) -> str:
    """Hash canonical static experiment identity, never volatile execution metadata."""
    return _hash_bytes(_canonical_bytes(formal_experiment_spec(manifest)))


def _formal_manifest_with_spec_reference(
    prompt: str, cells: list[FormalRunCell], attempt_id: str = "experiment-003-sonnet"
) -> tuple[ExperimentManifest, str]:
    scientific_manifest = new_formal_manifest(
        experiment_id="experiment-003-sonnet", cells=cells,
        config=SONNET_CANARY_CONFIG, prompt=prompt,
    )
    spec_hash = formal_experiment_spec_hash(scientific_manifest)
    manifest = scientific_manifest.model_copy(update={
        "experiment_id": attempt_id,
        "parameters": {**scientific_manifest.parameters, "experiment_spec_hash": spec_hash},
    })
    return manifest, spec_hash


def prepare_formal_sonnet() -> dict[str, Any]:
    """Build the formal manifest offline; this function never constructs a provider."""
    prompt = PROMPT_PATH.read_text(encoding="utf-8")
    cells = formal_sonnet_cells()
    manifest, spec_hash = _formal_manifest_with_spec_reference(prompt, cells)
    return {
        "schema_version": "experiment-003-formal-plan-v1",
        "formal_evidence": True, "external_call_performed": False,
        "experiment_spec": formal_experiment_spec(manifest),
        "experiment_spec_hash": formal_experiment_spec_hash(manifest),
        "matrix": [cell.model_dump(mode="json") for cell in cells],
        "manifest": manifest.model_dump(mode="json"),
        "execution_command": "uv run python -m bluerange.experiment003 --execute-formal",
        "provider_methodological_difference": (
            "Anthropic uses ordinary Messages text JSON transport with max_tokens only; "
            "temperature, top_p, and seed are omitted because unsupported, while V2 "
            "semantics, lifecycle, tools, autonomy, evaluation, and scoring remain frozen."
        ),
    }


def execute_formal_sonnet(attempt_id: str = "experiment-003-sonnet") -> dict[str, Any]:
    """Execute the formal matrix through the shared checkpointed V2 path."""
    prompt = PROMPT_PATH.read_text(encoding="utf-8")
    cells = formal_sonnet_cells()
    manifest, _spec_hash = _formal_manifest_with_spec_reference(prompt, cells, attempt_id)
    batch_root = Path("results/formal-batches")
    attempt_root = batch_root / attempt_id
    if attempt_root.exists():
        raise SystemExit(f"formal execution attempt path already exists: {attempt_root}")
    budgets = RuntimeBudgets(model_turns=12, investigation_calls=8, response_actions=2)

    def run_cell(cell: FormalRunCell) -> Any:
        run = run_experiment_v2_cell(
            scenario_id="identity-compromise-001", seed=cell.seed,
            autonomy=cell.autonomy, profile=EvidenceProfile(cell.profile),
            control=cell.kind == "benign", run_id=cell.run_id,
            provider_factory=provider_factory(SONNET_CANARY_CONFIG), budgets=budgets,
            prompt=prompt, temperature=SONNET_CANARY_CONFIG.temperature,
            top_p=SONNET_CANARY_CONFIG.top_p, model_seed=SONNET_CANARY_CONFIG.model_seed,
            request_timeout=SONNET_CANARY_CONFIG.timeout_seconds,
        )
        return formal_outcome_or_fail(cell, run)

    batch = execute_002r_formal_batch(
        batch_root, manifest, run_cell, provider_retries=2
    )
    aggregate = batch.read_aggregate()
    if aggregate is None:
        raise SystemExit("formal Sonnet batch aborted")
    return aggregate


def main() -> None:
    parser = argparse.ArgumentParser()
    stage = parser.add_mutually_exclusive_group(required=True)
    stage.add_argument("--prepare-canary", action="store_true")
    stage.add_argument("--execute-canary", action="store_true")
    stage.add_argument("--prepare-formal", action="store_true")
    stage.add_argument("--execute-formal", action="store_true")
    parser.add_argument("--attempt-id", default="experiment-003-sonnet")
    args = parser.parse_args()
    if args.prepare_canary:
        print(json.dumps(prepare_sonnet_canary(), indent=2, sort_keys=True))
    elif args.prepare_formal:
        print(json.dumps(prepare_formal_sonnet(), indent=2, sort_keys=True))
    elif args.execute_formal:
        execute_formal_sonnet(args.attempt_id)
    else:
        run_sonnet_canary()


if __name__ == "__main__":
    main()
