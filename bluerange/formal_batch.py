"""Atomic, fail-stop persistence for deterministic formal experiment batches."""

import json
import os
import re
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from bluerange.models import AutonomyLevel, FrozenStrictModel, SafeId, StrictModel

RunStatus = Literal["PENDING", "RUNNING", "COMPLETED", "FAILED"]
ExperimentStatus = Literal["INITIALIZING", "RUNNING", "COMPLETED", "ABORTED"]


class GitState(FrozenStrictModel):
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    dirty: bool


class DecisionContractProvenance(FrozenStrictModel):
    """Deterministic freeze of every static surface used by a new experiment."""

    schema_version: Literal["decision-contract-provenance-v1"] = (
        "decision-contract-provenance-v1"
    )
    defender_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scenario_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authoritative_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol_presentation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    static_system_contract_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    experiment_configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    autonomy_surface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scoring_surface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluator_surface_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider: SafeId
    model: SafeId
    output_mode: SafeId
    supported_model_parameters: dict[str, Any]


class FormalRunCell(FrozenStrictModel):
    run_id: SafeId
    seed: int = Field(ge=0)
    profile: SafeId
    autonomy: AutonomyLevel
    kind: SafeId


class ExperimentManifest(FrozenStrictModel):
    experiment_id: SafeId
    expected_runs: list[FormalRunCell] = Field(min_length=1)
    expected_count: int = Field(ge=1)
    git: GitState
    bluerange_version: str = Field(min_length=1, max_length=128)
    runtime_version: str = Field(min_length=1, max_length=128)
    prompt_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scenario_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scenario_version: str = Field(min_length=1, max_length=128)
    provider: SafeId
    model: SafeId
    parameters: dict[str, Any]
    started_at: datetime
    provenance_policy: Literal["legacy-002r", "decision-contract-v1"] = "legacy-002r"
    decision_contract: DecisionContractProvenance | None = None

    @model_validator(mode="after")
    def unique_run_ids(self) -> "ExperimentManifest":
        run_ids = [cell.run_id for cell in self.expected_runs]
        if len(run_ids) != len(set(run_ids)):
            raise ValueError("manifest run IDs must be unique")
        if self.expected_count != len(self.expected_runs):
            raise ValueError("manifest expected count must match its run matrix")
        return self


class RunState(StrictModel):
    run_id: SafeId
    status: RunStatus


class BatchStatus(StrictModel):
    experiment_id: SafeId
    experiment_status: ExperimentStatus
    runs: list[RunState]
    abort_reason: str | None = Field(default=None, max_length=2000)


class RunOutcome(StrictModel):
    run_id: SafeId
    canonical_record: dict[str, Any]
    provider_call_audits: list[dict[str, Any]] = Field(default_factory=list)
    model_turn_audits: list[dict[str, Any]] = Field(default_factory=list)
    json_valid: bool | None = None
    schema_valid: bool | None = None
    parsed_decision: dict[str, Any] | None = None
    attempted_action: dict[str, Any] | None = None
    validation_failure: str | None = None
    authorization_decision: str | None = None
    tool_execution_status: str | None = None
    tokens: int = Field(default=0, ge=0)
    latency_ms: float = Field(default=0, ge=0)


class RunFailure(RuntimeError):
    """A run-level failure carrying evidence gathered before the failure was detected.

    ``outcome`` lets a runner hand back provider and turn audits it had already
    collected, so forensics are never empty merely because the failure was raised
    instead of returned.
    """

    def __init__(self, message: str, outcome: "RunOutcome | None" = None):
        super().__init__(message)
        self.outcome = outcome


class CompletedRun(FrozenStrictModel):
    run_id: SafeId
    canonical_record: dict[str, Any]


class ForensicRecord(FrozenStrictModel):
    run_id: SafeId
    experimental_cell: FormalRunCell
    provider_call_audits: list[dict[str, Any]]
    model_turn_audits: list[dict[str, Any]]
    json_valid: bool | None
    schema_valid: bool | None
    parsed_decision: dict[str, Any] | None
    attempted_action: dict[str, Any] | None
    validation_failure: str | None
    authorization_decision: str | None
    tool_execution_status: str | None
    safe_failure_category: Literal["runtime_exception"]
    tokens: int = Field(ge=0)
    latency_ms: float = Field(ge=0)
    exception_category: SafeId
    sanitized_message: str = Field(min_length=1, max_length=2000)


_SECRET_KEYS = re.compile(
    r"^(?:authorization|api[-_]?key|access[-_]?token|refresh[-_]?token|password|credential|secret)$",
    re.IGNORECASE,
)
_SECRET_VALUES = re.compile(
    r"(?i)(?:authorization\s*:\s*)?(?:bearer\s+|api[-_]?key\s*[:=]\s*|token\s*[:=]\s*|password\s*[:=]\s*)\S+"
)


_MESSAGE_LIMIT = 2000


def _bounded(text: str, limit: int = _MESSAGE_LIMIT) -> str:
    """Fit arbitrary diagnostic text into a recordable bound without ever failing."""
    collapsed = text if text.strip() else ""
    if len(collapsed) <= limit:
        return collapsed or "runtime exception"
    marker = f"... [truncated {len(collapsed) - limit} characters]"
    return collapsed[: max(1, limit - len(marker))] + marker


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _sanitize(nested)
            for key, nested in value.items()
            if not _SECRET_KEYS.search(str(key))
        }
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize(item) for item in value)
    if isinstance(value, str):
        return _SECRET_VALUES.sub("[REDACTED]", value)
    return value


def _encoded(model: FrozenStrictModel | StrictModel | dict[str, Any]) -> bytes:
    value = model.model_dump(mode="json") if isinstance(model, (FrozenStrictModel, StrictModel)) else model
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        pass


def _atomic_replace(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_create(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        temporary.unlink()
        _fsync_directory(path.parent)
    except FileExistsError:
        raise FileExistsError(f"immutable checkpoint already exists: {path}") from None
    finally:
        if temporary.exists():
            temporary.unlink()


class FormalBatch:
    """A restart-readable experiment directory with immutable run checkpoints."""

    def __init__(self, root: Path, manifest: ExperimentManifest):
        self.root = root
        self.manifest = manifest

    @classmethod
    def create(cls, parent: Path, manifest: ExperimentManifest) -> "FormalBatch":
        if manifest.provenance_policy == "decision-contract-v1":
            if manifest.git.dirty:
                raise ValueError("new formal experiments require a clean public Git working tree")
            if manifest.decision_contract is None:
                raise ValueError(
                    "new formal experiments require complete decision-contract provenance"
                )
        root = parent / manifest.experiment_id
        root.mkdir(parents=True, exist_ok=True)
        _atomic_create(root / "manifest.json", _encoded(manifest))
        batch = cls(root, manifest)
        batch._write_status(
            BatchStatus(
                experiment_id=manifest.experiment_id,
                experiment_status="INITIALIZING",
                runs=[RunState(run_id=cell.run_id, status="PENDING") for cell in manifest.expected_runs],
            )
        )
        return batch

    @classmethod
    def open(cls, root: Path) -> "FormalBatch":
        manifest = ExperimentManifest.model_validate_json((root / "manifest.json").read_text())
        return cls(root, manifest)

    def _write_status(self, status: BatchStatus) -> None:
        _atomic_replace(self.root / "status.json", _encoded(status))

    def read_status(self) -> BatchStatus:
        return BatchStatus.model_validate_json((self.root / "status.json").read_text())

    def persist_completed(self, completed: CompletedRun) -> None:
        CompletedRun.model_validate(completed.model_dump())
        _atomic_create(self.root / "runs" / f"{completed.run_id}.json", _encoded(completed))

    def read_completed(self, run_id: str) -> CompletedRun:
        return CompletedRun.model_validate_json((self.root / "runs" / f"{run_id}.json").read_text())

    def read_forensic(self, run_id: str) -> ForensicRecord:
        return ForensicRecord.model_validate_json((self.root / "forensics" / f"{run_id}.json").read_text())

    def read_aggregate(self) -> dict[str, Any] | None:
        path = self.root / "aggregate.json"
        return json.loads(path.read_text()) if path.exists() else None

    def forensic_from_exception(
        self, cell: FormalRunCell, outcome: RunOutcome, exception: Exception
    ) -> ForensicRecord:
        """Build a recordable forensic record for any exception, without ever raising."""
        message = _bounded(str(_sanitize(str(exception))))
        category = type(exception).__name__
        try:
            sanitized = _sanitize(outcome.model_dump(mode="json"))
            return ForensicRecord(
                run_id=cell.run_id,
                experimental_cell=cell,
                provider_call_audits=sanitized["provider_call_audits"],
                model_turn_audits=sanitized["model_turn_audits"],
                json_valid=outcome.json_valid,
                schema_valid=outcome.schema_valid,
                parsed_decision=sanitized["parsed_decision"],
                attempted_action=sanitized["attempted_action"],
                validation_failure=sanitized["validation_failure"],
                authorization_decision=sanitized["authorization_decision"],
                tool_execution_status=sanitized["tool_execution_status"],
                safe_failure_category="runtime_exception",
                tokens=outcome.tokens,
                latency_ms=outcome.latency_ms,
                exception_category=category,
                sanitized_message=message,
            )
        except Exception as forensic_exception:
            # The forensic path itself must never be the reason evidence is lost.
            return ForensicRecord(
                run_id=cell.run_id,
                experimental_cell=cell,
                provider_call_audits=[],
                model_turn_audits=[],
                json_valid=None,
                schema_valid=None,
                parsed_decision=None,
                attempted_action=None,
                validation_failure=None,
                authorization_decision=None,
                tool_execution_status=None,
                safe_failure_category="runtime_exception",
                tokens=0,
                latency_ms=0,
                exception_category=category,
                sanitized_message=_bounded(
                    f"{message} [degraded forensic record: "
                    f"{type(forensic_exception).__name__}]"
                ),
            )

    def _record_failure(
        self, cell: FormalRunCell, outcome: RunOutcome, exception: Exception
    ) -> None:
        """Persist failure forensics on a best-effort basis; never raise to the caller."""
        try:
            forensic = self.forensic_from_exception(cell, outcome, exception)
            _atomic_create(self.root / "forensics" / f"{cell.run_id}.json", _encoded(forensic))
        except Exception:
            return

    def execute(
        self,
        runner: Callable[[FormalRunCell], RunOutcome],
        aggregate_builder: Callable[[list[dict[str, Any]]], dict[str, Any]] | None = None,
    ) -> None:
        status = self.read_status()
        if status.experiment_status in {"ABORTED", "COMPLETED"}:
            return
        if status.experiment_status == "RUNNING":
            # A batch already marked RUNNING was interrupted. Never silently resume it:
            # re-running a cell would either collide with or mislabel its checkpoint.
            self._abort(status, "batch was already RUNNING; interrupted batches are never resumed")
            return
        status.experiment_status = "RUNNING"
        self._write_status(status)
        for index, cell in enumerate(self.manifest.expected_runs):
            state = status.runs[index]
            state.status = "RUNNING"
            self._write_status(status)
            outcome = RunOutcome(run_id=cell.run_id, canonical_record={})
            try:
                outcome = runner(cell)
                if outcome.run_id != cell.run_id:
                    raise ValueError("runner returned a mismatched run ID")
                completed = CompletedRun(run_id=cell.run_id, canonical_record=outcome.canonical_record)
                self.persist_completed(completed)
            except Exception as exc:
                # A runner may attach the evidence it had already gathered.
                carried = getattr(exc, "outcome", None)
                evidence = carried if isinstance(carried, RunOutcome) else outcome
                self._record_failure(cell, evidence, exc)
                state.status = "FAILED"
                self._abort(status, f"{type(exc).__name__} during {cell.run_id}")
                return
            state.status = "COMPLETED"
            self._write_status(status)
        try:
            records = [
                self.read_completed(cell.run_id).canonical_record
                for cell in self.manifest.expected_runs
            ]
            aggregate = (
                aggregate_builder(records)
                if aggregate_builder is not None
                else {"completed_runs": len(status.runs)}
            )
            encoded = _encoded(aggregate)
        except Exception as exc:
            # Completed checkpoints stay intact, but an experiment whose aggregate could
            # not be produced is incomplete and must never be reported as COMPLETED.
            self._abort(status, f"{type(exc).__name__} during aggregation")
            return
        _atomic_create(self.root / "aggregate.json", encoded)
        status.experiment_status = "COMPLETED"
        self._write_status(status)

    def _abort(self, status: BatchStatus, reason: str) -> None:
        status.experiment_status = "ABORTED"
        status.abort_reason = _bounded(str(_sanitize(reason)))
        self._write_status(status)
