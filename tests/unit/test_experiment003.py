"""Offline Experiment 003 configuration, provenance, and canary tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from bluerange.experiment002 import V2Decision
from bluerange.experiment003 import (
    CANARY_CELL,
    SONNET_CANARY_CONFIG,
    _safe_canary_observability,
    build_decision_contract_provenance,
    formal_experiment_spec_hash,
    new_formal_manifest,
    prepare_formal_sonnet,
    prepare_sonnet_canary,
    provider_factory,
    run_sonnet_canary,
)
from bluerange.formal_batch import ExperimentManifest, FormalBatch
from bluerange.models.gateway import AnthropicProvider, OutputMode
from bluerange.protocol_conformance import build_protocol_presentation


def test_offline_canary_plan_uses_formal_v2_contract_without_provider_instantiation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline preparation instantiated Anthropic")

    monkeypatch.setattr("bluerange.experiment003.AnthropicProvider", forbidden)
    plan = prepare_sonnet_canary()
    assert plan["external_call_performed"] is False
    assert plan["formal_evidence"] is False
    assert plan["execution_path"] == "bluerange.experiment002.run_experiment_v2_cell"
    assert plan["cell"] == CANARY_CELL.model_dump(mode="json")
    assert plan["provider"] == "anthropic"
    assert plan["model"] == "claude-sonnet-5"
    assert plan["output_mode"] == "ANTHROPIC_TEXT_JSON"
    assert plan["parameters"]["provider_supported"] == {"max_tokens": 4096}
    assert plan["parameters"]["provider_omitted"] == ["temperature", "top_p", "seed"]


def test_sonnet_provider_configuration_is_capability_accurate() -> None:
    provider = provider_factory(SONNET_CANARY_CONFIG)()
    assert isinstance(provider, AnthropicProvider)
    assert provider.model_id == "claude-sonnet-5"
    assert provider.output_mode is OutputMode.ANTHROPIC_TEXT_JSON
    assert provider.max_tokens == 4096
    assert provider.timeout == 600


def test_complete_static_contract_and_schema_are_hashed_deterministically() -> None:
    prompt = Path("prompts/defender-v2.txt").read_text(encoding="utf-8")
    first = build_decision_contract_provenance(SONNET_CANARY_CONFIG, prompt)
    second = build_decision_contract_provenance(SONNET_CANARY_CONFIG, prompt)
    assert first == second
    assert first.defender_prompt_sha256 == (
        "1edcb1b12b0d3ef1463c1330015fb127409c76e311323879545297826dfa9fe4"
    )
    assert first.provider == "anthropic"
    assert first.model == "claude-sonnet-5"
    assert first.output_mode == "ANTHROPIC_TEXT_JSON"
    assert first.supported_model_parameters == {"max_tokens": 4096}
    assert build_protocol_presentation(V2Decision)
    assert len({
        first.authoritative_schema_sha256,
        first.protocol_presentation_sha256,
        first.static_system_contract_sha256,
    }) == 3



def test_formal_spec_hash_excludes_execution_timestamp_and_tracks_scientific_changes() -> None:
    first = prepare_formal_sonnet()
    second = prepare_formal_sonnet()
    assert first["manifest"]["started_at"] != second["manifest"]["started_at"]
    assert first["experiment_spec_hash"] == second["experiment_spec_hash"]
    manifest = ExperimentManifest.model_validate(first["manifest"])
    changed_git = manifest.model_copy(update={"git": manifest.git.model_copy(update={"commit": "a" * 40, "dirty": True})})
    assert formal_experiment_spec_hash(manifest) == formal_experiment_spec_hash(changed_git)
    assert manifest.git.commit
    assert isinstance(manifest.git.dirty, bool)
    assert manifest.parameters["experiment_spec_hash"] == first["experiment_spec_hash"]
    changed = manifest.model_copy(update={"model": "claude-sonnet-5-changed"})
    assert formal_experiment_spec_hash(manifest) != formal_experiment_spec_hash(changed)
    assert "started_at" not in first["experiment_spec"]


def test_formal_preparation_is_offline_and_exact() -> None:
    plan = prepare_formal_sonnet()
    assert plan["external_call_performed"] is False
    assert plan["manifest"]["expected_count"] == 24
    assert len(plan["matrix"]) == 24
    assert plan["manifest"]["provenance_policy"] == "decision-contract-v1"

def _synthetic_run() -> Any:
    action = SimpleNamespace(
        turn=1,
        tool="inspect_identity",
        validation_status=SimpleNamespace(value="VALID"),
        authorization_decision=SimpleNamespace(value="PERMITTED"),
        execution_status=SimpleNamespace(value="EXECUTED"),
        safe_failure_category="none",
    )
    return SimpleNamespace(
        protocol=SimpleNamespace(
            provider_errors=0,
            provider_call_audits=[
                {
                    "model_id": "claude-sonnet-5",
                    "error_category": None,
                    "http_status": 200,
                    "api_error_type": None,
                }
            ],
            turn_audits=[
                {
                    "schema_errors": [],
                    "initial_malformed": False,
                    "initial_invalid_json": "must-not-persist",
                    "parsed": {"private": "must-not-persist"},
                }
            ],
            first_pass_valid_turns=1,
            repair_attempted=False,
            repair_succeeded=False,
            finalized=True,
            input_tokens_by_turn=[100],
            output_tokens_by_turn=[50],
            total_tokens=150,
            latency_ms=25.0,
            failure_categories=[],
        ),
        action_attempts=[action],
        result=SimpleNamespace(
            autonomy=SimpleNamespace(value="A1"),
            disposition=SimpleNamespace(value="COMPROMISE"),
        ),
    )


def test_canary_execution_calls_actual_cell_path_and_persists_only_bounded_observability(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    def fake_cell(**kwargs: Any) -> Any:
        captured.update(kwargs)
        return _synthetic_run()

    monkeypatch.setattr("bluerange.experiment003.run_experiment_v2_cell", fake_cell)
    output = tmp_path / "canary.json"
    artifact = run_sonnet_canary(output)
    assert captured["seed"] == 101
    assert captured["profile"].value == "COMPLETE"
    assert captured["autonomy"].value == "A1"
    assert captured["control"] is False
    assert captured["prompt"] == Path("prompts/defender-v2.txt").read_text(encoding="utf-8")
    text = output.read_text(encoding="utf-8")
    assert artifact["label"] == "NON-FORMAL CANARY"
    assert artifact["first_pass_json_syntax_valid"] is True
    assert artifact["first_pass_authoritative_schema_valid"] is True
    assert "must-not-persist" not in text
    assert "raw" not in json.dumps(artifact).lower()


def test_safe_observability_distinguishes_json_syntax_failure() -> None:
    run = _synthetic_run()
    run.protocol.first_pass_valid_turns = 0
    run.protocol.turn_audits[0]["initial_malformed"] = True
    run.protocol.turn_audits[0]["parsed"] = None
    run.protocol.turn_audits[0]["schema_errors"] = [": json_invalid"]
    observed = _safe_canary_observability(run, SONNET_CANARY_CONFIG)
    assert observed["first_pass_json_syntax_valid"] is False
    assert observed["first_pass_authoritative_schema_valid"] is False
    assert observed["safe_structural_errors"] == [": json_invalid"]


def test_new_formal_manifest_fails_closed_on_dirty_tree(tmp_path: Path) -> None:
    prompt = Path("prompts/defender-v2.txt").read_text(encoding="utf-8")
    manifest = new_formal_manifest(
        experiment_id="experiment-003-test",
        cells=[CANARY_CELL],
        config=SONNET_CANARY_CONFIG,
        prompt=prompt,
    )
    dirty = manifest.model_copy(update={"git": manifest.git.model_copy(update={"dirty": True})})
    with pytest.raises(ValueError, match="clean public Git working tree"):
        FormalBatch.create(tmp_path, dirty)


def test_new_formal_manifest_requires_complete_contract(tmp_path: Path) -> None:
    prompt = Path("prompts/defender-v2.txt").read_text(encoding="utf-8")
    manifest = new_formal_manifest(
        experiment_id="experiment-003-test",
        cells=[CANARY_CELL],
        config=SONNET_CANARY_CONFIG,
        prompt=prompt,
    )
    incomplete = manifest.model_copy(
        update={
            "git": manifest.git.model_copy(update={"dirty": False}),
            "decision_contract": None,
        }
    )
    with pytest.raises(ValueError, match="decision-contract provenance"):
        FormalBatch.create(tmp_path, incomplete)
