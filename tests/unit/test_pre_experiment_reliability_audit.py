"""Pre-experiment reliability audit regressions using deterministic fakes only.

Every test here runs without a provider, a network call, or a real model. The
invariant under test throughout is that arbitrary model-controlled input may be
rejected, denied or classified as malformed, but must never leave BlueRange
unable to record what happened.
"""

import json
import math
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from bluerange.experiment import aggregate_metrics
from bluerange.experiment002 import V2Run, run_experiment_v2_cell
from bluerange.experiment002r import execute_002r_formal_batch
from bluerange.formal_batch import (
    BatchStatus,
    CompletedRun,
    ExperimentManifest,
    FormalBatch,
    FormalRunCell,
    GitState,
    RunOutcome,
    _bounded,
    _encoded,
)
from bluerange.models import AutonomyLevel, BenchmarkResult
from bluerange.models.gateway import FakeModelProvider
from bluerange.models.schemas import RuntimeBudgets
from bluerange.scenarios import EvidenceProfile
from bluerange.scenarios._evaluator import build_evaluator_instance

INSTANCE = build_evaluator_instance(101, EvidenceProfile.COMPLETE, False)
SUBJECT = INSTANCE.truth.compromised_identity
VALID_SESSION = sorted(INSTANCE.truth.compromised_sessions)[0]


def _manifest(
    identifier: str, count: int = 3, autonomy: AutonomyLevel = AutonomyLevel.A3
) -> ExperimentManifest:
    cells = [
        FormalRunCell(
            run_id=f"cell-{number}",
            seed=101,
            profile="COMPLETE",
            autonomy=autonomy,
            kind="attack" if number % 2 else "benign",
        )
        for number in range(1, count + 1)
    ]
    return ExperimentManifest(
        experiment_id=identifier,
        expected_runs=cells,
        expected_count=count,
        git=GitState(commit="a" * 40, dirty=True),
        bluerange_version="0.1.0",
        runtime_version="audit",
        prompt_hash="b" * 64,
        scenario_hash="c" * 64,
        scenario_version="audit-v1",
        provider="fake",
        model="fake",
        parameters={},
        started_at=datetime.now(UTC),
    )


def _decision(
    state: str,
    action: dict[str, Any] | None,
    *,
    disposition: str = "COMPROMISE",
    subject: str | None = SUBJECT,
) -> str:
    return json.dumps(
        {
            "lifecycle_state": state,
            "assessment": {
                "disposition": disposition,
                "subject": subject,
                "confidence": 0.9,
                "evidence_refs": [],
                "incident_summary": "Synthetic audit decision.",
                "recommended_response": None,
                "performed_response": None,
                "remaining_uncertainty": "Synthetic audit.",
            },
            "action": action,
        }
    )


def _cell_run(
    responses: list[str],
    *,
    autonomy: AutonomyLevel = AutonomyLevel.A3,
    response_actions: int = 2,
    run_id: str = "run-000001",
    seed: int = 101,
    control: bool = False,
    provider: Any = None,
) -> V2Run:
    return run_experiment_v2_cell(
        scenario_id="identity-compromise-001",
        seed=seed,
        autonomy=autonomy,
        profile=EvidenceProfile.COMPLETE,
        control=control,
        run_id=run_id,
        provider_factory=(
            provider
            if provider is not None
            else lambda: FakeModelProvider(responses=responses, model_id="fake")
        ),
        budgets=RuntimeBudgets(
            model_turns=max(1, len(responses)),
            investigation_calls=8,
            response_actions=response_actions,
        ),
        prompt="synthetic audit prompt",
        request_timeout=30,
    )


# --- 1. The error-reporting path must never itself be unrecordable -------------------


def test_forensic_record_survives_an_oversized_exception_message(tmp_path: Path) -> None:
    batch = FormalBatch.create(tmp_path, _manifest("forensic-long"))
    cell = batch.manifest.expected_runs[0]
    outcome = RunOutcome(run_id=cell.run_id, canonical_record={})
    forensic = batch.forensic_from_exception(cell, outcome, ValueError("x" * 5000))
    assert len(forensic.sanitized_message) <= 2000
    assert "truncated" in forensic.sanitized_message
    assert forensic.exception_category == "ValueError"


def test_forensic_record_survives_a_real_canonical_validation_error(tmp_path: Path) -> None:
    batch = FormalBatch.create(tmp_path, _manifest("forensic-canonical"))
    cell = batch.manifest.expected_runs[0]
    try:
        BenchmarkResult.model_validate({})
    except Exception as exc:  # noqa: BLE001 - the realistic abort-time exception
        assert len(str(exc)) > 2000
        forensic = batch.forensic_from_exception(
            cell, RunOutcome(run_id=cell.run_id, canonical_record={}), exc
        )
    assert forensic.exception_category == "ValidationError"
    assert len(forensic.sanitized_message) <= 2000


def test_bounded_never_produces_an_unrecordable_message() -> None:
    for text in ("", "   ", "short", "y" * 10_000):
        bounded = _bounded(text)
        assert 1 <= len(bounded) <= 2000


def test_degraded_forensic_record_still_redacts_secrets(tmp_path: Path) -> None:
    batch = FormalBatch.create(tmp_path, _manifest("forensic-secret"))
    cell = batch.manifest.expected_runs[0]
    forensic = batch.forensic_from_exception(
        cell,
        RunOutcome(run_id=cell.run_id, canonical_record={}),
        RuntimeError("Authorization: Bearer super-secret-value " + "z" * 4000),
    )
    text = forensic.model_dump_json().lower()
    assert "super-secret-value" not in text
    assert "bearer" not in text


# --- 2. Batch crash safety with a realistic failure ----------------------------------


def test_realistic_canonical_failure_aborts_without_losing_evidence(tmp_path: Path) -> None:
    invoked: list[str] = []

    def runner(cell: FormalRunCell) -> RunOutcome:
        invoked.append(cell.run_id)
        if cell.run_id == "cell-2":
            BenchmarkResult.model_validate({})
        return RunOutcome(
            run_id=cell.run_id,
            canonical_record={"run_id": cell.run_id},
            provider_call_audits=[{"call_id": "c1"}],
            model_turn_audits=[{"turn": 1}],
        )

    batch = FormalBatch.create(tmp_path, _manifest("realistic-crash"))
    batch.execute(runner)  # must not propagate
    status = batch.read_status()
    assert invoked == ["cell-1", "cell-2"]
    assert status.experiment_status == "ABORTED"
    assert [item.status for item in status.runs] == ["COMPLETED", "FAILED", "PENDING"]
    assert batch.read_completed("cell-1").canonical_record == {"run_id": "cell-1"}
    assert batch.read_forensic("cell-2").exception_category == "ValidationError"
    assert batch.read_aggregate() is None
    assert status.abort_reason is not None


def test_interrupted_running_batch_is_never_resumed_or_mislabelled(tmp_path: Path) -> None:
    batch = FormalBatch.create(tmp_path, _manifest("interrupted"))
    status = batch.read_status()
    status.experiment_status = "RUNNING"
    status.runs[0].status = "COMPLETED"
    batch._write_status(status)
    batch.persist_completed(CompletedRun(run_id="cell-1", canonical_record={"run_id": "cell-1"}))

    executed: list[str] = []

    def runner(cell: FormalRunCell) -> RunOutcome:
        executed.append(cell.run_id)
        return RunOutcome(run_id=cell.run_id, canonical_record={"run_id": cell.run_id})

    FormalBatch.open(batch.root).execute(runner)
    after = batch.read_status()
    assert executed == []  # no cell is ever re-run
    assert after.experiment_status == "ABORTED"
    assert after.runs[0].status == "COMPLETED"  # completed run is not relabelled FAILED
    assert batch.read_completed("cell-1").canonical_record == {"run_id": "cell-1"}
    assert batch.read_aggregate() is None


def test_aggregation_failure_aborts_instead_of_reporting_completed(tmp_path: Path) -> None:
    def runner(cell: FormalRunCell) -> RunOutcome:
        return RunOutcome(run_id=cell.run_id, canonical_record={"run_id": cell.run_id})

    def builder(records: list[dict[str, Any]]) -> dict[str, Any]:
        raise ValueError("aggregation failed")

    batch = FormalBatch.create(tmp_path, _manifest("aggregation-fail"))
    batch.execute(runner, builder)
    status = batch.read_status()
    assert status.experiment_status == "ABORTED"
    assert all(item.status == "COMPLETED" for item in status.runs)
    assert batch.read_aggregate() is None
    assert FormalBatch.open(batch.root).read_status().experiment_status == "ABORTED"


def test_persisted_artifacts_reject_non_finite_numbers() -> None:
    for value in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError):
            _encoded({"metric": value})


def test_status_readback_tolerates_records_without_an_abort_reason() -> None:
    restored = BatchStatus.model_validate(
        {"experiment_id": "legacy", "experiment_status": "COMPLETED", "runs": []}
    )
    assert restored.abort_reason is None


# --- 3. Attempts stopped before the controller are never recorded as executed --------


def test_budget_exhausted_repeat_is_not_recorded_as_executed() -> None:
    revoke = {"type": "tool", "name": "revoke_session", "arguments": {"session_id": VALID_SESSION}}
    run = _cell_run(
        [_decision("RESPOND", revoke), _decision("RESPOND", revoke), _decision("FINALIZE", None)],
        response_actions=1,
    )
    first, second = run.action_attempts[0], run.action_attempts[1]
    assert first.execution_status == "EXECUTED"
    assert second.execution_status == "NOT_EXECUTED"
    assert second.authorization_decision == "DENIED"
    assert second.safe_failure_category == "authorization_denied"
    assert second.tool_success is None
    assert second.denial_reason == "independent budget exhausted"
    # The controller was invoked exactly once, so exactly one action is canonical.
    assert [record.tool for record in run.result.tool_history] == ["revoke_session"]
    assert len(run.result.actions) == 1
    assert run.result.actions[0].success is True


def test_recorded_executions_never_exceed_authorized_controller_invocations() -> None:
    revoke = {"type": "tool", "name": "revoke_session", "arguments": {"session_id": VALID_SESSION}}
    disable = {"type": "tool", "name": "disable_identity", "arguments": {"identity_id": SUBJECT}}
    for autonomy in (AutonomyLevel.A1, AutonomyLevel.A2, AutonomyLevel.A3):
        run = _cell_run(
            [
                _decision("RESPOND", revoke),
                _decision("RESPOND", disable),
                _decision("RESPOND", revoke),
                _decision("FINALIZE", None),
            ],
            autonomy=autonomy,
            response_actions=2,
        )
        executed = [a for a in run.action_attempts if a.execution_status == "EXECUTED"]
        authorized = [h for h in run.result.tool_history if h.denial_reason is None]
        assert len(executed) == len(authorized)
        for attempt in run.action_attempts:
            if attempt.execution_status == "NOT_EXECUTED":
                assert attempt.tool_success is None


# --- 4. Aggregation refuses to score an incomplete experiment ------------------------


def test_aggregation_refuses_empty_matrix() -> None:
    with pytest.raises(ValueError, match="no completed runs"):
        aggregate_metrics([])


# --- 5. Fuzz / property boundary testing over model-controlled fields ----------------

_HOSTILE_TARGETS: tuple[Any, ...] = (
    "",
    " ",
    "[invalid]",
    "unknown",
    "none",
    "null",
    "a" * 5000,
    "sess- ",
    "../../etc/passwd",
    "sess-<script>",
    0,
    -1,
    1.5,
    True,
    None,
    [],
    {},
    ["sess-alice"],
    {"id": "sess-alice"},
    "SESS-ALICE",
)
_HOSTILE_KEYS = ("session_id", "identity_id", "sessionId", "target", "", "query")
_TOOLS = (
    "revoke_session",
    "disable_identity",
    "escalate_to_human",
    "create_incident",
    "inspect_identity",
    "search_logs",
)
# The correct argument key for each tool, so the corpus also reaches the executed,
# denied and recommendation branches instead of only invalid-argument rejection.
_CORRECT_KEY = {
    "revoke_session": "session_id",
    "disable_identity": "identity_id",
    "inspect_identity": "identity_id",
    "search_logs": "query",
    "escalate_to_human": "reason",
    "create_incident": "title",
}
_WELL_FORMED: tuple[Any, ...] = (VALID_SESSION, SUBJECT, "sess-does-not-exist", "no-such-identity")


def _hostile_actions(count: int) -> list[tuple[dict[str, Any], AutonomyLevel]]:
    rng = random.Random(20260831)
    cases: list[tuple[dict[str, Any], AutonomyLevel]] = []
    for index in range(count):
        name = _TOOLS[index % len(_TOOLS)]
        arguments: dict[str, Any] = {}
        if rng.random() < 0.5:
            # Well-formed enough to pass the strict tool schema and reach authorization.
            arguments[_CORRECT_KEY[name]] = rng.choice(_WELL_FORMED)
            if name == "create_incident":
                arguments["summary"] = "synthetic"
        else:
            # Hostile shape: wrong keys, wrong types, sentinels, or nothing at all.
            for _ in range(rng.randint(0, 2)):
                arguments[rng.choice(_HOSTILE_KEYS)] = rng.choice(_HOSTILE_TARGETS)
        cases.append(
            (
                {
                    "type": rng.choice(["tool", "recommendation"]),
                    "name": name,
                    "arguments": arguments,
                },
                rng.choice([AutonomyLevel.A1, AutonomyLevel.A2, AutonomyLevel.A3]),
            )
        )
    return cases


@pytest.mark.parametrize(("action", "autonomy"), _hostile_actions(60))
def test_hostile_action_fields_never_break_canonical_recording(
    action: dict[str, Any], autonomy: AutonomyLevel
) -> None:
    """Arbitrary model-controlled action input must still yield a serializable run."""
    state = "INVESTIGATE" if action["name"] in {"inspect_identity", "search_logs"} else "RESPOND"
    if state == "INVESTIGATE":
        action = {**action, "type": "tool"}
    run = _cell_run([_decision(state, action), _decision("FINALIZE", None)], autonomy=autonomy)
    restored = V2Run.model_validate_json(run.model_dump_json())
    assert restored.result.semantic_fingerprint == run.result.semantic_fingerprint
    for attempt in restored.action_attempts:
        if attempt.validation_status == "INVALID":
            assert attempt.execution_status == "NOT_EXECUTED"
            assert attempt.target is None
    # An unresolved or invalid target never becomes a canonical action.
    assert all(record.target for record in restored.result.actions)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not json at all",
        "{",
        "[]",
        "null",
        "123",
        '{"lifecycle_state": "TAKEOVER", "assessment": {}, "action": null}',
        '{"lifecycle_state": "FINALIZE"}',
        '{"lifecycle_state": "FINALIZE", "assessment": {"disposition": "COMPROMISE"},'
        ' "action": {"type": "tool", "name": "rm_rf", "arguments": {}}}',
        '{"lifecycle_state": "RESPOND", "assessment": {"disposition": "MAYBE", "subject": null,'
        ' "confidence": 5, "evidence_refs": ["event-999"], "incident_summary": "x",'
        ' "remaining_uncertainty": "y"}, "action": null}',
    ],
)
def test_malformed_model_output_still_produces_a_serializable_run(raw: str) -> None:
    run = _cell_run([raw, raw])
    restored = V2Run.model_validate_json(run.model_dump_json())
    assert restored.protocol.total_turns >= 1
    assert not restored.result.actions
    assert json.loads(run.model_dump_json())


def test_fabricated_evidence_reference_is_rejected_without_crashing() -> None:
    fabricated = json.dumps(
        {
            "lifecycle_state": "FINALIZE",
            "assessment": {
                "disposition": "COMPROMISE",
                "subject": SUBJECT,
                "confidence": 1.0,
                "evidence_refs": ["event-999"],
                "incident_summary": "Fabricated.",
                "recommended_response": None,
                "performed_response": None,
                "remaining_uncertainty": "None.",
            },
            "action": None,
        }
    )
    run = _cell_run([fabricated, fabricated])
    assert not run.protocol.finalized
    assert V2Run.model_validate_json(run.model_dump_json())


# --- 6. Deterministic synthetic smoke matrix -----------------------------------------


def test_synthetic_smoke_matrix_traverses_the_real_orchestration(tmp_path: Path) -> None:
    """Valid investigate/respond/finalize, invalid, malformed, batch, and readback."""
    scripts: dict[str, list[str]] = {
        "cell-1": [
            _decision(
                "INVESTIGATE",
                {
                    "type": "tool",
                    "name": "get_active_sessions",
                    "arguments": {"identity_id": SUBJECT},
                },
            ),
            _decision(
                "RESPOND",
                {
                    "type": "tool",
                    "name": "revoke_session",
                    "arguments": {"session_id": VALID_SESSION},
                },
            ),
            _decision("FINALIZE", None),
        ],
        "cell-2": [
            _decision(
                "RESPOND",
                {
                    "type": "tool",
                    "name": "revoke_session",
                    "arguments": {"session_id": "[invalid]"},
                },
            ),
            _decision("FINALIZE", None),
        ],
        "cell-3": ["this is not json", _decision("FINALIZE", None)],
    }

    def runner(cell: FormalRunCell) -> RunOutcome:
        run = _cell_run(
            scripts[cell.run_id],
            run_id=cell.run_id,
            seed=cell.seed,
            control=cell.kind == "benign",
        )
        return RunOutcome(
            run_id=cell.run_id,
            canonical_record=V2Run.model_validate_json(run.model_dump_json()).model_dump(
                mode="json"
            ),
            provider_call_audits=run.protocol.provider_call_audits,
            model_turn_audits=run.protocol.turn_audits,
            tokens=run.protocol.total_tokens,
            latency_ms=run.protocol.latency_ms,
        )

    batch = execute_002r_formal_batch(tmp_path, _manifest("smoke-ok"), runner)
    assert batch.read_status().experiment_status == "COMPLETED"
    aggregate = batch.read_aggregate()
    assert aggregate is not None and aggregate["completed_runs"] == 3

    reopened = FormalBatch.open(batch.root)
    restored = {
        cell.run_id: V2Run.model_validate(reopened.read_completed(cell.run_id).canonical_record)
        for cell in batch.manifest.expected_runs
    }
    # Valid investigation, valid response, valid finalization.
    assert restored["cell-1"].protocol.finalized
    assert [a.tool for a in restored["cell-1"].result.actions] == ["revoke_session"]
    # Invalid action: audited, never executed, never a canonical action.
    invalid = restored["cell-2"].action_attempts[0]
    assert invalid.validation_status == "INVALID"
    assert invalid.target is None
    assert not restored["cell-2"].result.actions
    # Malformed decision: recorded as a protocol failure and still serializable.
    assert restored["cell-3"].protocol.initial_malformed_outputs >= 1
    assert not restored["cell-3"].result.actions


def test_synthetic_smoke_matrix_crashed_batch_preserves_completed_runs(tmp_path: Path) -> None:
    def runner(cell: FormalRunCell) -> RunOutcome:
        if cell.run_id == "cell-2":
            raise RuntimeError("synthetic mid-batch runtime failure")
        run = _cell_run(
            [_decision("FINALIZE", None)],
            run_id=cell.run_id,
            seed=cell.seed,
            control=cell.kind == "benign",
        )
        return RunOutcome(
            run_id=cell.run_id,
            canonical_record=V2Run.model_validate_json(run.model_dump_json()).model_dump(
                mode="json"
            ),
        )

    batch = execute_002r_formal_batch(tmp_path, _manifest("smoke-crash"), runner)
    status = batch.read_status()
    assert status.experiment_status == "ABORTED"
    assert [item.status for item in status.runs] == ["COMPLETED", "FAILED", "PENDING"]
    assert batch.read_aggregate() is None
    assert V2Run.model_validate(batch.read_completed("cell-1").canonical_record)
    with pytest.raises(FileNotFoundError):
        batch.read_completed("cell-3")


# =====================================================================================
# Gap-closure pass: formal-matrix validation, persistence injection, provider failure,
# audit correlation, and seeded security-boundary canaries.
# =====================================================================================

from datetime import timedelta  # noqa: E402

from bluerange.experiment002r import (  # noqa: E402
    compute_002r_metrics,
    validate_formal_matrix,
)
from bluerange.formal_batch import _atomic_create, _sanitize  # noqa: E402
from bluerange.models.gateway import (  # noqa: E402
    OutputMode,
    ProviderCallAudit,
    ProviderError,
)
from bluerange.models.schemas import ProviderRequest, ProviderResponse, TokenUsage  # noqa: E402

SECRET_CANARY = "BLUERANGE-CANARY-SECRET-9d41"
TRUTH_CANARY = INSTANCE.truth.attack_steps  # evaluator-only; absent from telemetry
EVALUATOR_ONLY_KEYS = (
    "compromised_identity",
    "legitimate_identities",
    "critical_identities",
    "compromised_sessions",
    "legitimate_sessions",
    "critical_sessions",
    "attack_steps",
    "attacker_final_objective_step",
    "ground_truth",
)


class AuditingFakeProvider:
    """Deterministic provider that records audits exactly as the HTTP adapter does."""

    provider_id = "fake-auditing"

    def __init__(self, responses: list[str], model_id: str = "fake") -> None:
        self.model_id = model_id
        self.responses = responses
        self.index = 0
        self.audits: list[ProviderCallAudit] = []

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        index = self.index
        self.index += 1
        raw = self.responses[index]
        stamp = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=index)
        usage = TokenUsage(prompt_tokens=7, completion_tokens=5, total_tokens=12)
        self.audits.append(
            ProviderCallAudit(
                call_id=f"call-{request.audit_run_id}-{request.audit_turn}-{index}",
                run_id=request.audit_run_id,
                turn=request.audit_turn,
                provider_id=self.provider_id,
                model_id=self.model_id,
                request_timestamp=stamp,
                response_timestamp=stamp + timedelta(milliseconds=5),
                latency_ms=5.0,
                generation_began=True,
                usage=usage,
                output_mode=OutputMode.JSON_OBJECT,
                repair_eligible=request.repair_eligible,
            )
        )
        return ProviderResponse(
            raw=raw, provider_id=self.provider_id, model_id=self.model_id,
            usage=usage, latency_ms=5.0,
        )


class FailingProvider:
    """Deterministic provider that always fails safely, carrying a sanitized audit."""

    provider_id = "fake-failing"

    def __init__(self, model_id: str = "fake") -> None:
        self.model_id = model_id
        self.audits: list[ProviderCallAudit] = []
        self.calls = 0

    def complete(self, request: ProviderRequest) -> ProviderResponse:
        self.calls += 1
        stamp = datetime(2026, 1, 1, tzinfo=UTC)
        audit = ProviderCallAudit(
            call_id=f"call-fail-{request.audit_run_id}-{request.audit_turn}-{self.calls}",
            run_id=request.audit_run_id,
            turn=request.audit_turn,
            provider_id=self.provider_id,
            model_id=self.model_id,
            request_timestamp=stamp,
            response_timestamp=stamp + timedelta(milliseconds=1),
            latency_ms=1.0,
            http_status=500,
            sanitized_error="model endpoint request failed (URLError)",
            error_category="PROVIDER_FAILURE",
            generation_began=False,
            usage=TokenUsage(),
            output_mode=OutputMode.JSON_OBJECT,
            repair_eligible=request.repair_eligible,
        )
        self.audits.append(audit)
        raise ProviderError(audit.sanitized_error or "provider failed", audit)


def _matched_manifest(identifier: str, count: int = 2) -> ExperimentManifest:
    manifest = _manifest(identifier, count)
    return manifest


def _run_for_cell(cell: FormalRunCell, responses: list[str], provider: Any = None) -> V2Run:
    return _cell_run(
        responses,
        autonomy=cell.autonomy,
        run_id=cell.run_id,
        seed=cell.seed,
        control=cell.kind == "benign",
        provider=provider,
    )


# --- Gap 1: formal aggregate refuses anything but the exact complete matrix ----------


def test_compute_002r_metrics_refuses_an_empty_run_set() -> None:
    with pytest.raises(ValueError, match="empty run set"):
        compute_002r_metrics([])


def _matrix_runs(manifest: ExperimentManifest) -> list[V2Run]:
    return [_run_for_cell(cell, [_decision("FINALIZE", None)]) for cell in manifest.expected_runs]


def test_validate_formal_matrix_accepts_the_exact_complete_matrix() -> None:
    manifest = _manifest("matrix-ok", 2)
    validate_formal_matrix(_matrix_runs(manifest), manifest)


def test_validate_formal_matrix_refuses_empty_partial_duplicate_and_unexpected() -> None:
    manifest = _manifest("matrix-bad", 2)
    runs = _matrix_runs(manifest)

    with pytest.raises(ValueError, match="at least one completed run"):
        validate_formal_matrix([], manifest)

    with pytest.raises(ValueError, match="incomplete; missing runs"):
        validate_formal_matrix(runs[:1], manifest)

    duplicated = [runs[0], runs[0].model_copy(deep=True)]
    with pytest.raises(ValueError, match="duplicate run IDs"):
        validate_formal_matrix(duplicated, manifest)

    stranger = runs[0].model_copy(deep=True, update={"run_id": "cell-99"})
    with pytest.raises(ValueError, match="unexpected runs"):
        validate_formal_matrix([*runs, stranger], manifest)


def test_validate_formal_matrix_refuses_a_run_that_does_not_match_its_cell() -> None:
    manifest = _manifest("matrix-mismatch", 2)
    runs = _matrix_runs(manifest)
    swapped = runs[0].model_copy(deep=True, update={"kind": "benign"})
    with pytest.raises(ValueError, match="does not match its manifest cell"):
        validate_formal_matrix([swapped, runs[1]], manifest)


def test_validate_formal_matrix_refuses_provider_degraded_runs() -> None:
    manifest = _manifest("matrix-degraded", 2)
    runs = _matrix_runs(manifest)
    degraded = runs[0].model_copy(deep=True)
    degraded.protocol.provider_errors = 1
    with pytest.raises(ValueError, match="provider-failed runs"):
        validate_formal_matrix([degraded, runs[1]], manifest)


def test_incomplete_formal_matrix_produces_no_aggregate_end_to_end(tmp_path: Path) -> None:
    """A runner that returns a cell-mismatched run must abort, not publish metrics."""
    manifest = _manifest("aggregate-refused", 2)

    def runner(cell: FormalRunCell) -> RunOutcome:
        # Always builds an attack run, so the benign cell will not match its manifest.
        run = _cell_run(
            [_decision("FINALIZE", None)],
            autonomy=cell.autonomy, run_id=cell.run_id, seed=cell.seed, control=False,
        )
        return RunOutcome(
            run_id=cell.run_id,
            canonical_record=V2Run.model_validate_json(run.model_dump_json()).model_dump(
                mode="json"
            ),
        )

    batch = execute_002r_formal_batch(tmp_path, manifest, runner)
    status = batch.read_status()
    assert status.experiment_status == "ABORTED"
    assert batch.read_aggregate() is None
    assert status.abort_reason is not None and "aggregation" in status.abort_reason
    # Completed checkpoints are still preserved for forensic review.
    assert batch.read_completed("cell-1").canonical_record


# --- Gap 2: failure injected into persistence itself --------------------------------


def test_failure_inside_atomic_create_leaves_no_checkpoint_or_remnant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    batch = FormalBatch.create(tmp_path, _manifest("persist-inner", 2))

    def broken_link(source: Any, target: Any, **kwargs: Any) -> None:
        raise OSError("synthetic disk failure during link")

    monkeypatch.setattr("bluerange.formal_batch.os.link", broken_link)
    with pytest.raises(OSError, match="synthetic disk failure"):
        batch.persist_completed(CompletedRun(run_id="cell-1", canonical_record={"a": 1}))
    monkeypatch.undo()

    runs_dir = batch.root / "runs"
    assert not (runs_dir / "cell-1.json").exists()
    assert list(runs_dir.glob("*")) == []  # the temporary file was cleaned up
    with pytest.raises(FileNotFoundError):
        batch.read_completed("cell-1")


def test_persistence_failure_aborts_the_batch_without_false_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    invoked: list[str] = []
    manifest = _manifest("persist-fail", 3)
    batch = FormalBatch.create(tmp_path, manifest)

    def selective(path: Path, content: bytes) -> None:
        if path.name == "cell-2.json":
            raise OSError("synthetic persistence failure")
        _atomic_create(path, content)

    def runner(cell: FormalRunCell) -> RunOutcome:
        invoked.append(cell.run_id)
        return RunOutcome(run_id=cell.run_id, canonical_record={"run_id": cell.run_id})

    monkeypatch.setattr("bluerange.formal_batch._atomic_create", selective)
    batch.execute(runner)
    monkeypatch.undo()

    status = batch.read_status()
    assert invoked == ["cell-1", "cell-2"]           # cell-3 never executes
    assert status.experiment_status == "ABORTED"
    assert [item.status for item in status.runs] == ["COMPLETED", "FAILED", "PENDING"]
    assert batch.read_completed("cell-1").canonical_record == {"run_id": "cell-1"}
    with pytest.raises(FileNotFoundError):
        batch.read_completed("cell-2")               # no partial checkpoint counts as COMPLETED
    with pytest.raises(FileNotFoundError):
        batch.read_completed("cell-3")
    assert batch.read_aggregate() is None
    assert not list((batch.root / "runs").glob(".*"))  # no temp remnants
    # Restart preserves the aborted state and never promotes it.
    restarted = FormalBatch.open(batch.root)
    restarted.execute(runner)
    assert restarted.read_status().experiment_status == "ABORTED"
    assert invoked == ["cell-1", "cell-2"]


def test_temp_remnant_cannot_masquerade_as_a_canonical_record(tmp_path: Path) -> None:
    batch = FormalBatch.create(tmp_path, _manifest("remnant", 2))
    runs_dir = batch.root / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    (runs_dir / ".cell-1.json.tmp").write_text(
        json.dumps({"run_id": "cell-1", "canonical_record": {"forged": True}}), encoding="utf-8"
    )
    with pytest.raises(FileNotFoundError):
        batch.read_completed("cell-1")


# --- Gap 3: provider failure driven through the real v2 path ------------------------


def test_provider_failure_is_audited_and_never_fabricates_a_decision() -> None:
    provider = FailingProvider()
    run = _cell_run([], provider=lambda: provider)

    assert provider.calls >= 1
    assert run.protocol.provider_errors >= 1
    assert "PROVIDER_FAILURE" in run.protocol.failure_categories
    # The provider-call audit survives even though no response was produced.
    assert run.protocol.provider_call_audits
    assert all(a["run_id"] == run.run_id for a in run.protocol.provider_call_audits)
    assert all(a["error_category"] == "PROVIDER_FAILURE" for a in run.protocol.provider_call_audits)
    # A turn audit still exists and records the safe failure classification.
    assert run.protocol.turn_audits
    last = run.protocol.turn_audits[-1]
    assert last["parsed"] is None                       # no fabricated model decision
    assert last["safe_failure_category"] == "PROVIDER_FAILURE"
    assert not last["repair_attempted"]                 # transport failure is not a repair case
    # Nothing executed and nothing was contained.
    assert not run.action_attempts
    assert not run.result.tool_history
    assert not run.result.actions
    assert not run.protocol.finalized
    containment = next(
        item for item in run.result.score_breakdown if item.component == "containment"
    )
    assert containment.awarded == 0
    # Canonical representation stays serializable and round-trips.
    assert V2Run.model_validate_json(run.model_dump_json())


def test_provider_failed_run_is_never_aggregated_as_defender_performance(
    tmp_path: Path,
) -> None:
    """Infrastructure failure must not be published as a normal benchmark aggregate."""
    manifest = _manifest("provider-degraded", 2)

    def runner(cell: FormalRunCell) -> RunOutcome:
        run = _run_for_cell(cell, [], provider=lambda: FailingProvider())
        return RunOutcome(
            run_id=cell.run_id,
            canonical_record=V2Run.model_validate_json(run.model_dump_json()).model_dump(
                mode="json"
            ),
            provider_call_audits=run.protocol.provider_call_audits,
            model_turn_audits=run.protocol.turn_audits,
        )

    batch = execute_002r_formal_batch(tmp_path, manifest, runner)
    assert batch.read_status().experiment_status == "ABORTED"
    assert batch.read_aggregate() is None
    # Every provider-failed run is still preserved as evidence.
    for cell in manifest.expected_runs:
        assert V2Run.model_validate(batch.read_completed(cell.run_id).canonical_record)


def test_provider_failure_forensics_remain_serializable(tmp_path: Path) -> None:
    batch = FormalBatch.create(tmp_path, _manifest("provider-forensic", 2))
    cell = batch.manifest.expected_runs[0]
    run = _run_for_cell(cell, [], provider=lambda: FailingProvider())
    outcome = RunOutcome(
        run_id=cell.run_id,
        canonical_record={},
        provider_call_audits=run.protocol.provider_call_audits,
        model_turn_audits=run.protocol.turn_audits,
    )
    forensic = batch.forensic_from_exception(cell, outcome, ProviderError("provider failed"))
    assert forensic.exception_category == "ProviderError"
    assert forensic.provider_call_audits
    assert json.loads(forensic.model_dump_json())


# --- Gap 4: executable audit correlation across every layer -------------------------


def _assert_run_is_internally_correlated(run: V2Run, cell: FormalRunCell) -> None:
    assert run.run_id == cell.run_id
    assert run.kind == cell.kind
    assert run.result.seed == cell.seed
    assert run.result.autonomy == cell.autonomy

    call_ids = [audit["call_id"] for audit in run.protocol.provider_call_audits]
    assert len(call_ids) == len(set(call_ids)), "provider call IDs must be unique within a run"
    for audit in run.protocol.provider_call_audits:
        assert audit["run_id"] == run.run_id, "a provider call cannot migrate to another run"
        assert 1 <= audit["turn"] <= run.protocol.total_turns

    for attempt in run.action_attempts:
        assert attempt.run_id == run.run_id, "an attempt cannot migrate to another run"
        assert 1 <= attempt.turn <= run.protocol.total_turns
        assert run.protocol.turn_audits[attempt.turn - 1] is not None

    # Every turn audit's nested provider calls are ordered, and only later ones are repairs.
    for audit in run.protocol.turn_audits:
        flags = [call["repair"] for call in audit["provider_calls"]]
        assert flags == sorted(flags), "a repair call cannot precede its initial call"
        if flags:
            assert flags[0] is False

    # Executed attempts correspond one-to-one with authorized controller audits.
    executed = [a for a in run.action_attempts if a.execution_status == "EXECUTED"]
    authorized = [h for h in run.result.tool_history if h.denial_reason is None]
    assert len(executed) == len(authorized)
    for attempt in executed:
        assert any(h.tool == attempt.tool for h in authorized)


def test_audit_layers_correlate_on_a_successful_batch(tmp_path: Path) -> None:
    manifest = _manifest("correlate-ok", 2)
    revoke = {"type": "tool", "name": "revoke_session", "arguments": {"session_id": VALID_SESSION}}
    # Turn 1 is malformed to force a repair, so repair correlation is exercised too.
    script = ["{ not json", _decision("RESPOND", revoke), _decision("FINALIZE", None)]

    def runner(cell: FormalRunCell) -> RunOutcome:
        run = _run_for_cell(cell, script, provider=lambda: AuditingFakeProvider(script))
        return RunOutcome(
            run_id=cell.run_id,
            canonical_record=V2Run.model_validate_json(run.model_dump_json()).model_dump(
                mode="json"
            ),
            provider_call_audits=run.protocol.provider_call_audits,
            model_turn_audits=run.protocol.turn_audits,
        )

    batch = execute_002r_formal_batch(tmp_path, manifest, runner)
    assert batch.read_status().experiment_status == "COMPLETED"

    seen_call_ids: set[str] = set()
    for cell in manifest.expected_runs:
        run = V2Run.model_validate(batch.read_completed(cell.run_id).canonical_record)
        _assert_run_is_internally_correlated(run, cell)
        assert run.protocol.repair_attempted and run.protocol.repair_audits
        ids = {audit["call_id"] for audit in run.protocol.provider_call_audits}
        assert not (ids & seen_call_ids), "call IDs must not be shared across runs"
        seen_call_ids |= ids

    # Manifest correlation: exactly the declared cells were checkpointed.
    persisted = sorted(path.stem for path in (batch.root / "runs").glob("*.json"))
    assert persisted == sorted(cell.run_id for cell in manifest.expected_runs)


def test_audit_layers_correlate_on_a_failed_run(tmp_path: Path) -> None:
    manifest = _manifest("correlate-fail", 3)
    batch = FormalBatch.create(tmp_path, manifest)

    def runner(cell: FormalRunCell) -> RunOutcome:
        run = _run_for_cell(cell, [_decision("FINALIZE", None)])
        outcome = RunOutcome(
            run_id=cell.run_id,
            canonical_record=V2Run.model_validate_json(run.model_dump_json()).model_dump(
                mode="json"
            ),
            provider_call_audits=run.protocol.provider_call_audits,
            model_turn_audits=run.protocol.turn_audits,
        )
        if cell.run_id == "cell-2":
            raise ValueError("synthetic failure after the run produced audits")
        return outcome

    batch.execute(runner)
    forensic = batch.read_forensic("cell-2")
    # The forensic record correlates to exactly the failing cell, not a neighbour.
    assert forensic.run_id == "cell-2"
    assert forensic.experimental_cell == manifest.expected_runs[1]
    assert forensic.experimental_cell.run_id != manifest.expected_runs[0].run_id
    completed = V2Run.model_validate(batch.read_completed("cell-1").canonical_record)
    assert completed.run_id == "cell-1"
    _assert_run_is_internally_correlated(completed, manifest.expected_runs[0])


# --- Gap 5: seeded security-boundary canaries ---------------------------------------


def _serialized_forms(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, default=str)


def test_persisted_checkpoints_never_expose_evaluator_only_truth(tmp_path: Path) -> None:
    manifest = _manifest("truth-canary", 2)
    revoke = {"type": "tool", "name": "revoke_session", "arguments": {"session_id": VALID_SESSION}}
    script = [_decision("RESPOND", revoke), _decision("FINALIZE", None)]

    def runner(cell: FormalRunCell) -> RunOutcome:
        run = _run_for_cell(cell, script)
        return RunOutcome(
            run_id=cell.run_id,
            canonical_record=V2Run.model_validate_json(run.model_dump_json()).model_dump(
                mode="json"
            ),
            provider_call_audits=run.protocol.provider_call_audits,
            model_turn_audits=run.protocol.turn_audits,
        )

    batch = execute_002r_formal_batch(tmp_path, manifest, runner)
    for cell in manifest.expected_runs:
        text = _serialized_forms(batch.read_completed(cell.run_id).canonical_record)
        # Value-level canaries: evaluator-only attack-step labels never appear.
        for canary in TRUTH_CANARY:
            assert canary not in text, f"evaluator-only value leaked: {canary!r}"
        # Structure-level canaries: no evaluator-only field ever appears.
        for key in EVALUATOR_ONLY_KEYS:
            assert f'"{key}"' not in text, f"evaluator-only field leaked: {key}"


def test_forensic_records_expose_neither_truth_nor_scores(tmp_path: Path) -> None:
    manifest = _manifest("forensic-canary", 2)
    batch = FormalBatch.create(tmp_path, manifest)
    cell = manifest.expected_runs[0]
    run = _run_for_cell(cell, [_decision("FINALIZE", None)])
    canonical = V2Run.model_validate_json(run.model_dump_json()).model_dump(mode="json")
    outcome = RunOutcome(
        run_id=cell.run_id,
        canonical_record=canonical,  # deliberately populated; must not reach forensics
        provider_call_audits=run.protocol.provider_call_audits,
        model_turn_audits=run.protocol.turn_audits,
    )
    forensic = batch.forensic_from_exception(cell, outcome, ValueError("synthetic"))
    text = forensic.model_dump_json()
    for canary in TRUTH_CANARY:
        assert canary not in text
    for key in (*EVALUATOR_ONLY_KEYS, "final_score", "score_breakdown", "canonical_record"):
        assert f'"{key}"' not in text, f"forensic record exposed {key}"


def test_seeded_credentials_are_redacted_from_forensic_records(tmp_path: Path) -> None:
    """Realistic credential shapes are removed by key and by value, at any depth."""
    batch = FormalBatch.create(tmp_path, _manifest("secret-canary", 2))
    cell = batch.manifest.expected_runs[0]
    outcome = RunOutcome(
        run_id=cell.run_id,
        canonical_record={},
        provider_call_audits=[
            {
                "Authorization": f"Bearer {SECRET_CANARY}",
                "nested": {
                    "api_key": SECRET_CANARY,
                    "deep": [{"message": f"api_key={SECRET_CANARY}"}],
                },
            }
        ],
        model_turn_audits=[{"detail": {"inner": [{"note": f"Bearer {SECRET_CANARY}"}]}}],
    )
    forensic = batch.forensic_from_exception(
        cell, outcome, RuntimeError(f"failed with Authorization: Bearer {SECRET_CANARY}")
    )
    text = forensic.model_dump_json()
    assert SECRET_CANARY not in text
    assert "bearer" not in text.lower()
    _atomic_create(batch.root / "forensics" / f"{cell.run_id}.json", _encoded(forensic))
    assert SECRET_CANARY not in (batch.root / "forensics" / f"{cell.run_id}.json").read_text()


def test_known_limit_bare_credentials_under_innocuous_keys_are_not_value_redacted() -> None:
    """Pins the documented LOW finding so the boundary is explicit, not assumed.

    ``_sanitize`` removes credentials by field name and by recognized value prefix.
    A bare token under an innocuous key is NOT value-redacted. No live code path
    places a credential there, but the limitation is asserted rather than implied.
    """
    assert SECRET_CANARY not in str(_sanitize({"api_key": SECRET_CANARY}))
    assert SECRET_CANARY not in str(_sanitize({"note": f"Bearer {SECRET_CANARY}"}))
    assert SECRET_CANARY in str(_sanitize({"note": SECRET_CANARY}))
    assert SECRET_CANARY in str(_sanitize({"items": [{"detail": SECRET_CANARY}]}))


# =====================================================================================
# H-2 correction: infrastructure failure fails the run; bad model behaviour does not.
# =====================================================================================

from bluerange.experiment002r import formal_outcome_or_fail  # noqa: E402
from bluerange.formal_batch import RunFailure  # noqa: E402

BAD_ACTION_ARGS = {"type": "tool", "name": "revoke_session", "arguments": {"session_id": "[bad id]"}}
UNSUPPORTED_ACTION = {"type": "tool", "name": "rm_rf", "arguments": {}}
DENIED_ACTION = {"type": "tool", "name": "revoke_session", "arguments": {"session_id": VALID_SESSION}}
INVESTIGATE_ACTION = {
    "type": "tool", "name": "inspect_identity", "arguments": {"identity_id": SUBJECT},
}

# Every case below is delivered by a provider that responded successfully. These are
# defender data and must stay measurable, however bad they are.
MODEL_BEHAVIOUR_CASES: list[tuple[str, list[str], AutonomyLevel]] = [
    ("malformed_json", ["{ not json", "still not json"], AutonomyLevel.A3),
    (
        "schema_invalid",
        [json.dumps({"lifecycle_state": "FINALIZE"}), json.dumps({"nope": True})],
        AutonomyLevel.A3,
    ),
    ("failed_schema_repair", ["{ broken", json.dumps({"lifecycle_state": "NOPE"})], AutonomyLevel.A3),
    ("successful_schema_repair", ["{ broken", _decision("FINALIZE", None)], AutonomyLevel.A3),
    (
        "invalid_action_arguments",
        [_decision("RESPOND", BAD_ACTION_ARGS), _decision("FINALIZE", None)],
        AutonomyLevel.A3,
    ),
    (
        "unsupported_action",
        [_decision("RESPOND", UNSUPPORTED_ACTION), _decision("FINALIZE", None)],
        AutonomyLevel.A3,
    ),
    (
        "denied_action",
        [_decision("RESPOND", DENIED_ACTION), _decision("FINALIZE", None)],
        AutonomyLevel.A1,
    ),
    (
        "missed_attack",
        [_decision("FINALIZE", None, disposition="BENIGN", subject=None)],
        AutonomyLevel.A3,
    ),
    (
        "never_finalizes",
        [_decision("INVESTIGATE", INVESTIGATE_ACTION)] * 3,
        AutonomyLevel.A3,
    ),
]


def _formal_runner(
    responses: list[str], provider: Any = None, invoked: list[str] | None = None
) -> Any:
    def runner(cell: FormalRunCell) -> RunOutcome:
        if invoked is not None:
            invoked.append(cell.run_id)
        run = _run_for_cell(cell, responses, provider=provider)
        return formal_outcome_or_fail(cell, run)

    return runner


# --- Side 1: provider/infrastructure failure must fail the cell ----------------------


def test_provider_failure_fails_the_cell_and_aborts_the_formal_batch(tmp_path: Path) -> None:
    manifest = _manifest("infra-failstop", 3)
    invoked: list[str] = []
    providers: list[FailingProvider] = []

    def make_failing() -> FailingProvider:
        provider = FailingProvider()
        providers.append(provider)
        return provider

    def runner(cell: FormalRunCell) -> RunOutcome:
        invoked.append(cell.run_id)
        if cell.run_id == "cell-2":
            run = _run_for_cell(cell, [], provider=make_failing)
        else:
            run = _run_for_cell(cell, [_decision("FINALIZE", None)])
        return formal_outcome_or_fail(cell, run)

    batch = execute_002r_formal_batch(tmp_path, manifest, runner)
    status = batch.read_status()

    # The infrastructure-failed cell is FAILED, never COMPLETED.
    assert [item.status for item in status.runs] == ["COMPLETED", "FAILED", "PENDING"]
    assert status.experiment_status == "ABORTED"
    assert invoked == ["cell-1", "cell-2"]          # later cells never execute
    assert batch.read_aggregate() is None           # no aggregate
    assert len(providers) == 1                      # no automatic retry
    assert providers[0].calls == 1

    # Prior completed runs are preserved and still readable.
    assert V2Run.model_validate(batch.read_completed("cell-1").canonical_record)
    with pytest.raises(FileNotFoundError):
        batch.read_completed("cell-2")
    with pytest.raises(FileNotFoundError):
        batch.read_completed("cell-3")

    # Sanitized forensic evidence preserves provider and turn audits.
    forensic = batch.read_forensic("cell-2")
    assert forensic.exception_category == "RunFailure"
    assert forensic.provider_call_audits
    assert all(a["run_id"] == "cell-2" for a in forensic.provider_call_audits)
    assert all(a["error_category"] == "PROVIDER_FAILURE" for a in forensic.provider_call_audits)
    assert forensic.model_turn_audits
    assert forensic.model_turn_audits[-1]["safe_failure_category"] == "PROVIDER_FAILURE"
    # Infrastructure failure is not reported as model output validity.
    assert forensic.json_valid is None
    assert forensic.schema_valid is None
    assert "provider failure prevented measurement" in forensic.sanitized_message

    # Restart preserves the aborted state and does not retry.
    FormalBatch.open(batch.root).execute(runner)
    assert batch.read_status().experiment_status == "ABORTED"
    assert invoked == ["cell-1", "cell-2"]


def test_formal_outcome_or_fail_raises_only_for_infrastructure_failure() -> None:
    cell = _manifest("unit-criterion", 1).expected_runs[0]
    degraded = _run_for_cell(cell, [], provider=lambda: FailingProvider())
    with pytest.raises(RunFailure, match="provider failure prevented measurement"):
        formal_outcome_or_fail(cell, degraded)

    delivered = _run_for_cell(cell, ["{ not json", "still not json"])
    outcome = formal_outcome_or_fail(cell, delivered)
    assert outcome.run_id == cell.run_id
    assert outcome.json_valid is False        # measured model behaviour, not infrastructure
    assert outcome.schema_valid is False


# --- Side 2: delivered-but-bad model behaviour stays a measurable COMPLETED run ------


@pytest.mark.parametrize(("label", "responses", "autonomy"), MODEL_BEHAVIOUR_CASES)
def test_bad_model_behaviour_remains_a_completed_measurable_run(
    tmp_path: Path, label: str, responses: list[str], autonomy: AutonomyLevel
) -> None:
    manifest = _manifest(f"model-behaviour-{label}", 1, autonomy=autonomy)
    batch = execute_002r_formal_batch(tmp_path, manifest, _formal_runner(responses))
    status = batch.read_status()

    assert status.experiment_status == "COMPLETED", f"{label} was misclassified as a failure"
    assert [item.status for item in status.runs] == ["COMPLETED"]
    assert status.abort_reason is None
    aggregate = batch.read_aggregate()
    assert aggregate is not None and aggregate["completed_runs"] == 1
    forensics = batch.root / "forensics"
    assert not forensics.exists() or not list(forensics.glob("*"))

    run = V2Run.model_validate(batch.read_completed("cell-1").canonical_record)
    assert run.protocol.provider_errors == 0, "delivered model behaviour is not a provider failure"
    assert "PROVIDER_FAILURE" not in run.protocol.failure_categories
    assert run.protocol.total_turns >= 1
    # The run remains a scored defender measurement under unchanged protocol semantics.
    assert run.result.final_score >= 0
    assert run.result.score_breakdown


def test_bad_model_behaviour_and_infrastructure_failure_are_distinguishable() -> None:
    """The two classes must never collapse into one another."""
    cell = _manifest("distinguish", 1).expected_runs[0]

    for _label, responses, autonomy in MODEL_BEHAVIOUR_CASES:
        run = _cell_run(responses, autonomy=autonomy, run_id=cell.run_id)
        assert run.protocol.provider_errors == 0
        formal_outcome_or_fail(cell, run)  # must not raise

    degraded = _run_for_cell(cell, [], provider=lambda: FailingProvider())
    assert degraded.protocol.provider_errors > 0
    with pytest.raises(RunFailure):
        formal_outcome_or_fail(cell, degraded)
