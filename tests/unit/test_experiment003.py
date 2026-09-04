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
    PROMPT_PATH,
    SONNET_CANARY_CONFIG,
    _formal_manifest_with_spec_reference,
    _safe_canary_observability,
    build_decision_contract_provenance,
    formal_experiment_spec_hash,
    formal_sonnet_cells,
    new_formal_manifest,
    prepare_formal_sonnet,
    prepare_sonnet_canary,
    provider_factory,
    run_sonnet_canary,
)
from bluerange.formal_batch import ExperimentManifest, FormalBatch
from bluerange.models.gateway import AnthropicProvider, OutputMode, ProviderError
from bluerange.models.schemas import ModelMessage, ProviderRequest
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
    assert plan["parameters"]["provider_supported"] == {"max_tokens": 16384}
    assert plan["parameters"]["provider_omitted"] == ["temperature", "top_p", "seed"]


def test_sonnet_provider_configuration_is_capability_accurate() -> None:
    provider = provider_factory(SONNET_CANARY_CONFIG)()
    assert isinstance(provider, AnthropicProvider)
    assert provider.model_id == "claude-sonnet-5"
    assert provider.output_mode is OutputMode.ANTHROPIC_TEXT_JSON
    assert provider.max_tokens == 16384
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
    assert first.supported_model_parameters == {"max_tokens": 16384}
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


def test_attempt_ids_change_execution_identity_but_not_scientific_identity() -> None:
    prompt = PROMPT_PATH.read_text(encoding="utf-8")
    cells = formal_sonnet_cells()
    first, first_hash = _formal_manifest_with_spec_reference(prompt, cells, "attempt-a")
    second, second_hash = _formal_manifest_with_spec_reference(prompt, cells, "attempt-b")
    assert first.experiment_id != second.experiment_id
    assert first_hash == second_hash
    assert first.parameters["experiment_spec_hash"] == second.parameters["experiment_spec_hash"]
    assert first.experiment_id == "attempt-a"
    assert second.experiment_id == "attempt-b"


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


def _provider_request() -> ProviderRequest:
    return ProviderRequest(messages=[ModelMessage(role="user", content="x")], tools=[], timeout_seconds=30, audit_run_id="test-run")


class _FakeMessages:
    def __init__(self, payload: object) -> None:
        self.payload = payload
        self.calls = 0

    def create(self, **_: object) -> object:
        self.calls += 1
        return self.payload


class _FakeClient:
    def __init__(self, payload: object) -> None:
        self.messages = _FakeMessages(payload)


def test_anthropic_bounded_invalid_response_diagnostics() -> None:
    cases = [
        ("NO_TEXT_BLOCK", [], 0, [], False),
        ("MULTIPLE_TEXT_BLOCKS", [SimpleNamespace(type="text", text="RAW_ALPHA"), SimpleNamespace(type="text", text="RAW_BETA")], 2, ["text", "text"], False),
        ("EMPTY_TEXT", [SimpleNamespace(type="text", text="")], 1, ["text"], True),
        ("INVALID_TEXT_TYPE", [SimpleNamespace(type="text", text=3)], 1, ["text"], True),
        ("MISSING_USAGE", [SimpleNamespace(type="text", text="x")], 1, ["text"], True),
        ("INVALID_INPUT_TOKENS", [SimpleNamespace(type="text", text="x")], 1, ["text"], True),
        ("INVALID_OUTPUT_TOKENS", [SimpleNamespace(type="text", text="x")], 1, ["text"], True),
        ("UNEXPECTED_BLOCK_STRUCTURE", "not-a-list", None, None, None),
    ]
    for code, blocks, count, types, selected in cases:
        usage = SimpleNamespace(input_tokens=1, output_tokens=1)
        if code == "MISSING_USAGE":
            payload = SimpleNamespace(id="msg-test", stop_reason="end_turn", content=blocks)
        elif code == "INVALID_INPUT_TOKENS":
            usage.input_tokens = "bad"
            payload = SimpleNamespace(id="msg-test", stop_reason="end_turn", content=blocks, usage=usage)
        elif code == "INVALID_OUTPUT_TOKENS":
            usage.output_tokens = "bad"
            payload = SimpleNamespace(id="msg-test", stop_reason="end_turn", content=blocks, usage=usage)
        else:
            payload = SimpleNamespace(id="msg-test", stop_reason="end_turn", content=blocks, usage=usage)
        client = _FakeClient(payload)
        with pytest.raises(ProviderError) as exc:
            AnthropicProvider("claude-sonnet-5", client=client).complete(_provider_request())
        audit = exc.value.audit
        assert audit is not None
        assert audit.validation_failure_code == code
        assert audit.content_block_count == count
        assert audit.content_block_types == types
        assert audit.text_block_count == (0 if code == "NO_TEXT_BLOCK" else count if count is not None else None)
        assert audit.selected_text_exists is selected
        assert audit.request_id == "msg-test"
        assert audit.stop_reason == "end_turn"
        assert audit.sanitized_error == "Anthropic returned an invalid response envelope"
        assert client.messages.calls == 1
        assert "RAW_ALPHA" not in audit.model_dump_json()
        assert "RAW_BETA" not in audit.model_dump_json()
        assert "RAW_SECRET" not in audit.model_dump_json()


def test_anthropic_valid_text_and_malformed_json_remain_successful_transport() -> None:
    for text in ["{\"not\": \"the decision schema\"}", "valid text"]:
        payload = SimpleNamespace(id="msg-valid", stop_reason="end_turn", content=[SimpleNamespace(type="text", text=text)], usage=SimpleNamespace(input_tokens=2, output_tokens=3))
        provider = AnthropicProvider("claude-sonnet-5", client=_FakeClient(payload))
        response = provider.complete(_provider_request())
        assert response.raw == text
        assert provider.audits[-1].error_category is None
        assert provider.audits[-1].validation_failure_code is None


def test_anthropic_multiple_blocks_are_rejected_without_concatenation() -> None:
    payload = SimpleNamespace(id="msg-multi", stop_reason="end_turn", content=[SimpleNamespace(type="text", text="left"), SimpleNamespace(type="text", text="right")], usage=SimpleNamespace(input_tokens=1, output_tokens=1))
    with pytest.raises(ProviderError):
        AnthropicProvider("claude-sonnet-5", client=_FakeClient(payload)).complete(_provider_request())
