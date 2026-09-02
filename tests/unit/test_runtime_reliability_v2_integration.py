"""Actual v2/002R-path reliability regressions using deterministic fakes."""

import inspect
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from bluerange.experiment002 import V2Run, run_experiment_v2_cell
from bluerange.experiment002r import (
    _formal_manifest,
    _verify_formal_canary,
    execute_002r_formal_batch,
)
from bluerange.formal_batch import ExperimentManifest, FormalRunCell, GitState, RunOutcome
from bluerange.models import AutonomyLevel
from bluerange.models.gateway import FakeModelProvider
from bluerange.models.schemas import RuntimeBudgets
from bluerange.scenarios import EvidenceProfile, scenario_hash
from bluerange.scenarios._evaluator import build_evaluator_instance

VALID_SESSION = build_evaluator_instance(
    101, EvidenceProfile.COMPLETE, False
).scenario.sessions[0].id


def _response(action: dict[str, Any] | None) -> str:
    return json.dumps({
        "lifecycle_state": "RESPOND" if action else "FINALIZE",
        "assessment": {
            "disposition": "COMPROMISE", "subject": "alice", "confidence": 0.9,
            "evidence_refs": [], "incident_summary": "Synthetic decision.",
            "recommended_response": None, "performed_response": None,
            "remaining_uncertainty": "Synthetic test.",
        },
        "action": action,
    })


@pytest.mark.parametrize(
    ("action", "level", "target", "executed", "failure"),
    [
        ({"type": "tool", "name": "revoke_session", "arguments": {"session_id": VALID_SESSION}}, AutonomyLevel.A3, VALID_SESSION, True, "none"),
        ({"type": "tool", "name": "revoke_session", "arguments": {"session_id": "sess-missing"}}, AutonomyLevel.A3, "sess-missing", True, "tool_failure"),
        ({"type": "tool", "name": "revoke_session", "arguments": {"session_id": "[invalid]"}}, AutonomyLevel.A3, None, False, "invalid_arguments"),
        ({"type": "tool", "name": "revoke_session", "arguments": {}}, AutonomyLevel.A3, None, False, "invalid_arguments"),
        ({"type": "tool", "name": "revoke_session", "arguments": {"identity_id": "alice"}}, AutonomyLevel.A3, None, False, "invalid_arguments"),
        ({"type": "tool", "name": "revoke_session", "arguments": {"session_id": ["sess-alice"]}}, AutonomyLevel.A3, None, False, "invalid_arguments"),
        ({"type": "tool", "name": "disable_identity", "arguments": {"identity_id": "alice"}}, AutonomyLevel.A2, "alice", False, "authorization_denied"),
        ({"type": "tool", "name": "revoke_session", "arguments": {"session_id": "sess-alice"}}, AutonomyLevel.A1, "sess-alice", False, "authorization_denied"),
        ({"type": "recommendation", "name": "revoke_session", "arguments": {"session_id": "sess-alice"}}, AutonomyLevel.A3, "sess-alice", False, "recommendation_only"),
        ({"type": "tool", "name": "disable_identity", "arguments": {"identity_id": "[invalid]"}}, AutonomyLevel.A3, None, False, "invalid_arguments"),
    ],
)
def test_ten_action_cases_cross_v2_canonical_scoring_path(
    action: dict[str, Any], level: AutonomyLevel, target: str | None,
    executed: bool, failure: str,
) -> None:
    def provider() -> FakeModelProvider:
        return FakeModelProvider(responses=[_response(action), _response(None)])
    run = run_experiment_v2_cell(
        scenario_id="identity-compromise-001", seed=101, autonomy=level,
        profile=EvidenceProfile.COMPLETE, control=False, run_id="synthetic-run",
        provider_factory=provider, budgets=RuntimeBudgets(model_turns=2,
        investigation_calls=0, response_actions=1), prompt="synthetic",
    )
    restored = V2Run.model_validate_json(run.model_dump_json())
    attempt = restored.action_attempts[0]
    assert attempt.original_arguments == action["arguments"]
    assert attempt.target == target
    assert (attempt.execution_status == "EXECUTED") is executed
    assert attempt.safe_failure_category == failure
    assert all(item.target != "[invalid]" for item in restored.result.actions)
    if not executed:
        assert not restored.result.actions
    if failure != "none":
        containment = next(x for x in restored.result.score_breakdown if x.component == "containment")
        assert containment.awarded == 0


def _manifest(identifier: str) -> ExperimentManifest:
    cells = [FormalRunCell(run_id=f"cell-{i}", seed=i, profile="COMPLETE",
                           autonomy="A3", kind="attack") for i in range(1, 4)]
    return ExperimentManifest(
        experiment_id=identifier, expected_runs=cells, expected_count=3,
        git=GitState(commit="a" * 40, dirty=True), bluerange_version="test",
        runtime_version="test", prompt_hash="b" * 64, scenario_hash="c" * 64,
        scenario_version="test", provider="fake", model="fake",
        parameters={}, started_at="2026-01-01T00:00:00Z",
    )


def test_actual_002r_orchestration_crash_restart_and_success(tmp_path: Path) -> None:
    invoked: list[str] = []

    def failing(cell: FormalRunCell) -> RunOutcome:
        invoked.append(cell.run_id)
        if cell.run_id == "cell-2":
            raise ValueError("canonical processing failed")
        return RunOutcome(run_id=cell.run_id, canonical_record={"run_id": cell.run_id})

    batch = execute_002r_formal_batch(tmp_path, _manifest("actual-path-fail"), failing)
    assert invoked == ["cell-1", "cell-2"]
    assert [x.status for x in batch.read_status().runs] == ["COMPLETED", "FAILED", "PENDING"]
    assert batch.read_aggregate() is None
    assert batch.open(batch.root).read_status().experiment_status == "ABORTED"

    def successful(cell: FormalRunCell) -> RunOutcome:
        run = run_experiment_v2_cell(
            scenario_id="identity-compromise-001", seed=cell.seed, autonomy=cell.autonomy,
            profile=EvidenceProfile(cell.profile), control=cell.kind == "benign",
            run_id=cell.run_id,
            provider_factory=lambda: FakeModelProvider(responses=[
                _response({"type": "tool", "name": "revoke_session",
                           "arguments": {"session_id": "[invalid]"}}),
                _response(None),
            ]), budgets=RuntimeBudgets(model_turns=2, investigation_calls=0,
                                        response_actions=1), prompt="synthetic",
        )
        return RunOutcome(run_id=cell.run_id,
                          canonical_record=run.model_dump(mode="json"))

    complete = execute_002r_formal_batch(tmp_path, _manifest("actual-path-ok"), successful)
    assert complete.read_status().experiment_status == "COMPLETED"
    assert complete.read_aggregate() is not None
    for cell in complete.manifest.expected_runs:
        restored = V2Run.model_validate(complete.read_completed(cell.run_id).canonical_record)
        assert restored.action_attempts[0].target is None
        assert not restored.result.actions


def test_formal_source_does_not_call_full_matrix_helper() -> None:
    from bluerange.experiment002r import run_formal

    assert "run_experiment_v2(" not in inspect.getsource(run_formal)


def test_formal_manifest_matches_generated_scenario_used_by_cell() -> None:
    instance = build_evaluator_instance(101, EvidenceProfile.COMPLETE, False)

    manifest = _formal_manifest("synthetic prompt")

    assert manifest.scenario_version == instance.scenario.version == "1.1"
    assert manifest.scenario_hash == scenario_hash(Path("scenarios/identity_compromise"))


def test_formal_execution_cannot_start_with_old_failed_canary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bluerange.experiment002r as experiment002r

    started = False

    def forbidden_manifest(_prompt: str) -> ExperimentManifest:
        nonlocal started
        started = True
        raise AssertionError("formal execution started")

    monkeypatch.setattr(experiment002r, "CANARY_PATH", Path("results/experiment-002r-canary.json"))
    monkeypatch.setattr(experiment002r, "_formal_manifest", forbidden_manifest)

    with pytest.raises(SystemExit, match="canary gate failed"):
        experiment002r.run_formal()
    assert not started


def test_formal_pre_run_gate_accepts_only_exact_frozen_fresh_canary(tmp_path: Path) -> None:
    copied = tmp_path / "canary.json"
    shutil.copyfile("results/experiment-002r-canary-2.json", copied)

    _verify_formal_canary(copied)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "wrong-schema"),
        ("gates", {"exact_fresh_pair": False}),
        ("model", "wrong-model"),
        ("parameters", {"temperature": 0.9}),
        ("canary_passed", False),
    ],
)
def test_formal_pre_run_gate_fails_closed_for_altered_fresh_canary(
    tmp_path: Path, field: str, value: Any
) -> None:
    altered = json.loads(Path("results/experiment-002r-canary-2.json").read_text())
    altered[field] = value
    path = tmp_path / "altered-canary.json"
    path.write_text(json.dumps(altered), encoding="utf-8")

    with pytest.raises(SystemExit, match="canary gate failed"):
        _verify_formal_canary(path)


def test_formal_pre_run_gate_fails_closed_when_fresh_canary_absent(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="canary gate failed"):
        _verify_formal_canary(tmp_path / "missing.json")
