"""Atomic checkpoint, fail-stop, and restart tests using synthetic records only."""

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from bluerange.formal_batch import (
    DecisionContractProvenance,
    ExperimentManifest,
    FormalBatch,
    FormalRunCell,
    GitState,
    RunOutcome,
)


def _provenance() -> DecisionContractProvenance:
    return DecisionContractProvenance(
        defender_prompt_sha256="1" * 64,
        scenario_sha256="2" * 64,
        authoritative_schema_sha256="3" * 64,
        protocol_presentation_sha256="4" * 64,
        static_system_contract_sha256="5" * 64,
        experiment_configuration_sha256="6" * 64,
        autonomy_surface_sha256="7" * 64,
        scoring_surface_sha256="8" * 64,
        evaluator_surface_sha256="9" * 64,
        protocol_source_sha256="a" * 64,
        provider="fake",
        model="synthetic",
        output_mode="TEXT_JSON_FALLBACK",
        supported_model_parameters={},
    )


def _manifest(identifier: str = "synthetic-001") -> ExperimentManifest:
    cells = [
        FormalRunCell(run_id=f"run-{number}", seed=number, profile="COMPLETE", autonomy="A2", kind="synthetic")
        for number in range(1, 4)
    ]
    return ExperimentManifest(
        experiment_id=identifier,
        expected_runs=cells,
        expected_count=3,
        git=GitState(commit="a" * 40, dirty=False),
        bluerange_version="0.2.0",
        runtime_version="runtime-reliability-v1",
        prompt_hash="b" * 64,
        scenario_hash="c" * 64,
        scenario_version="synthetic-v1",
        provider="fake",
        model="synthetic",
        parameters={"temperature": 0},
        started_at="2026-01-01T00:00:00Z",
        decision_contract=_provenance(),
    )


def _runner(
    executed: list[str], fail: str | None = None
) -> Callable[[FormalRunCell], RunOutcome]:
    def run(cell: FormalRunCell) -> RunOutcome:
        executed.append(cell.run_id)
        if cell.run_id == fail:
            raise ValueError("synthetic processing failure Authorization: Bearer secret-value")
        return RunOutcome(run_id=cell.run_id, canonical_record={"run_id": cell.run_id, "score": 1})

    return run


def test_failure_is_atomic_fail_stop_and_aborted_survives_restart(tmp_path: Path) -> None:
    executed: list[str] = []
    batch = FormalBatch.create(tmp_path, _manifest())
    batch.execute(_runner(executed, fail="run-2"))
    assert executed == ["run-1", "run-2"]
    assert batch.read_status().experiment_status == "ABORTED"
    assert [item.status for item in batch.read_status().runs] == ["COMPLETED", "FAILED", "PENDING"]
    assert batch.read_aggregate() is None
    completed = batch.read_completed("run-1")
    assert completed.canonical_record == {"run_id": "run-1", "score": 1}
    with pytest.raises(FileExistsError):
        batch.persist_completed(completed)
    forensic = batch.read_forensic("run-2")
    serialized = forensic.model_dump_json().lower()
    assert forensic.safe_failure_category == "runtime_exception"
    assert "secret-value" not in serialized
    assert "bearer" not in serialized
    restarted = FormalBatch.open(tmp_path / "synthetic-001")
    assert restarted.read_status().experiment_status == "ABORTED"
    restarted.execute(_runner([]))
    assert restarted.read_status().experiment_status == "ABORTED"


def test_successful_batch_checkpoint_readback_temp_remnants_and_duplicates(tmp_path: Path) -> None:
    executed: list[str] = []
    batch = FormalBatch.create(tmp_path, _manifest("synthetic-002"))
    batch.execute(_runner(executed))
    assert executed == ["run-1", "run-2", "run-3"]
    assert batch.read_status().experiment_status == "COMPLETED"
    assert all(item.status == "COMPLETED" for item in batch.read_status().runs)
    assert batch.read_aggregate() == {"completed_runs": 3}
    restarted = FormalBatch.open(tmp_path / "synthetic-002")
    assert [restarted.read_completed(f"run-{number}").run_id for number in range(1, 4)] == [
        "run-1",
        "run-2",
        "run-3",
    ]
    remnant = restarted.root / "runs" / ".run-4.json.partial"
    remnant.write_text(json.dumps({"run_id": "run-4"}), encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        restarted.read_completed("run-4")
    with pytest.raises(FileExistsError):
        FormalBatch.create(tmp_path, _manifest("synthetic-002"))


def test_forensics_recursively_remove_secret_fields_and_values(tmp_path: Path) -> None:
    batch = FormalBatch.create(tmp_path, _manifest("synthetic-003"))
    outcome = RunOutcome(
        run_id="run-1",
        canonical_record={"unused": True},
        provider_call_audits=[
            {
                "Authorization": "Bearer abc",
                "nested": {"api_key": "key-123", "message": "token=xyz"},
            }
        ],
    )
    forensic = batch.forensic_from_exception(
        batch.manifest.expected_runs[0], outcome, RuntimeError("password=hunter2")
    )
    text = forensic.model_dump_json().lower()
    for secret in ('"authorization":', "bearer abc", "api_key", "key-123", "token=xyz", "hunter2"):
        assert secret not in text


def test_duplicate_run_ids_fail_closed() -> None:
    data = _manifest("synthetic-004").model_dump()
    data["expected_runs"][1]["run_id"] = "run-1"
    with pytest.raises(ValidationError, match="run IDs must be unique"):
        ExperimentManifest.model_validate(data)
