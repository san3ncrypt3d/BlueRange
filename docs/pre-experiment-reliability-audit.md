# Pre-experiment reliability audit

Independent runtime/reliability audit of BlueRange, performed before any further
formal experiment is attempted; a second pass closing five gaps identified in
review of the first pass; and a third, narrowly scoped correction promoting the
provider-failure defence (H-2) from the aggregation boundary to the run
boundary.

This was **not** an experiment. No Ollama, OpenAI, Anthropic or other provider
was contacted at any point; every test uses `FakeModelProvider`, a deterministic
auditing fake, a deterministic failing fake, or pure synthetic records.

Scope frozen as instructed: no prompt, scenario, generator, ground-truth,
scoring, autonomy, tool-permission, budget, model-configuration, seed,
evidence-profile or expected-benchmark-behaviour change was made. Verified by
regenerating the canonical v0.1 validation artifact to its expected hash.

## How to read this report

Every finding carries three explicit attributes:

- **Discovered** — how it was found (execution or inspection).
- **Fixed** — yes, or explicitly not fixed with the reason.
- **Verified** — *by execution* (a regression test drives the real path and
  fails without the fix) or *inspection-only* (reasoned from source, no test).

Claims still resting on inspection are collected in their own section rather
than mixed in with executed evidence.

## Findings index

| ID | Severity | Finding | Fixed | Verified |
|---|---|---|---|---|
| B-1 | BLOCKER | Forensic path could not record a realistic failure | yes | execution |
| B-2 | BLOCKER | Failing run left batch `RUNNING` with no forensics | yes | execution |
| B-3 | BLOCKER | Restart mislabelled a completed run as `FAILED` | yes | execution |
| H-1 | HIGH | Budget-exhausted attempts recorded as `EXECUTED` | yes | execution |
| H-2 | HIGH | Provider-failed runs completed and aggregated as defender performance | yes (run-level fail-stop + aggregation backstop) | execution |
| M-1 | MEDIUM | Aggregation failure reported neither completion nor abort | yes | execution |
| M-2 | MEDIUM | `aggregate_metrics` divided by zero on an incomplete matrix | yes | execution |
| M-3 | MEDIUM | `compute_002r_metrics` aggregated incomplete formal input | yes | execution |
| L-1 | LOW | Persisted artifacts could contain `NaN`/`Infinity` | yes | execution |
| L-2 | LOW | `next()` without default in aggregation helpers | yes | execution |
| L-3 | LOW | Duplicate investigation attempts leave no attempt record | no (documented) | execution |
| L-4 | LOW | Bare credentials under innocuous keys are not value-redacted | no (documented) | execution |

---

## BLOCKER

### B-1. The forensic (error-reporting) path could not record a realistic failure

**Path:** canonical run construction → `FormalBatch.execute` → `forensic_from_exception`
**Discovered by execution.**

`ForensicRecord.sanitized_message` is bounded at 2000 characters, but
`forensic_from_exception` passed `str(exception)` through unbounded. A real
canonical-construction failure is far larger:

```
BenchmarkResult.model_validate({}) -> ValidationError, len(str(exc)) == 3746
```

The exact class of failure that aborted Experiment 002R produced a forensic
record that *itself* failed validation — a direct violation of the requirement
that no error-reporting path may crash because it cannot be serialized.

**Fixed.** Added `_bounded()`, which fits arbitrary diagnostic text into the
recordable bound with an explicit `... [truncated N characters]` marker and never
returns an empty string. `forensic_from_exception` is now total: if building the
full record raises for any reason it returns a degraded but valid record, rather
than raising.

**Verified by execution:** `test_forensic_record_survives_an_oversized_exception_message`,
`test_forensic_record_survives_a_real_canonical_validation_error`,
`test_bounded_never_produces_an_unrecordable_message`,
`test_degraded_forensic_record_still_redacts_secrets`.

**Benchmark semantics changed:** no.

### B-2. A failing run left the batch permanently `RUNNING` with no forensics

**Path:** `FormalBatch.execute` failure handling
**Discovered by execution.**

Because B-1 raised inside the `except` block, the exception escaped `execute()`
*before* the `FAILED` / `ABORTED` status write:

```
execute() PROPAGATED: ValidationError
experiment_status = RUNNING
run states = [('run-000001','COMPLETED'), ('run-000002','RUNNING'), ('run-000003','PENDING')]
forensics    = MISSING
```

The completed run-1 checkpoint survived — atomic checkpointing itself works — but
the failing run's provider and turn audits were lost, and the experiment sat in a
state that was neither completed nor aborted.

**Fixed.** Failure handling now uses `_record_failure()`, which persists forensics
best-effort and never raises, followed unconditionally by the status write.

**Verified by execution:** `test_realistic_canonical_failure_aborts_without_losing_evidence`.

**Benchmark semantics changed:** no.

### B-3. Restarting an interrupted batch mislabelled a completed run as FAILED

**Path:** `FormalBatch.execute` restart guard
**Discovered by execution.**

The resume guard refused only `ABORTED` and `COMPLETED`. A batch stuck in
`RUNNING` was re-entered from index 0; cell 1 was re-run, its immutable
checkpoint raised `FileExistsError`, and the handler marked **run 1** `FAILED` —
while the run that actually failed stayed `RUNNING` with no forensics:

```
run states after restart = [('run-000001','FAILED'), ('run-000002','RUNNING'), ('run-000003','PENDING')]
forensics = ['run-000001.json']
```

The audit trail actively blamed the wrong run.

**Fixed.** `execute()` refuses to continue a batch already marked `RUNNING`:
it records a sanitized `abort_reason` and marks the experiment `ABORTED` without
invoking any cell.

**Verified by execution:** `test_interrupted_running_batch_is_never_resumed_or_mislabelled`.

**Benchmark semantics changed:** no.

---

## HIGH

### H-1. Budget-exhausted attempts were recorded as EXECUTED and fabricated an `ActionRecord`

**Path:** `V2Agent.run` → `ActionAttemptRecord` → `run_experiment_v2_cell` → `ActionRecord`
**Discovered by execution.**

Execution was inferred from a stale-history heuristic:

```python
executed = ... and any(audit.tool == action.name and audit.arguments == clean_arguments
                       for audit in controller.history[-1:])
```

On budget exhaustion the controller is never invoked, so `controller.history[-1]`
was still the *previous* turn's audit. A repeated identical response action
matched it:

```
turn=1 revoke_session exec=EXECUTED  success=True  auth=PERMITTED
turn=2 revoke_session exec=EXECUTED  success=False auth=PERMITTED  cat=tool_failure
controller tool_history invocations = ['revoke_session']      <- invoked once
ActionRecords in canonical result   = 2                        <- one is fabricated
```

An action that never crossed the authorization boundary appeared in the canonical
result as an execution.

**Fixed.** Execution is determined by whether *this turn* appended a controller
audit that passed authorization:

```python
invoked = controller.history[history_before:]
executed = (validation_failure is None and not recommendation
            and bool(invoked) and invoked[-1].denial_reason is None)
```

This also aligns the v2 agent with the v1 `LLMDefenderAgent`, which already
classified budget exhaustion as `NOT_EXECUTED` / `authorization_denied`.

**Verified by execution:** `test_budget_exhausted_repeat_is_not_recorded_as_executed`,
`test_recorded_executions_never_exceed_authorized_controller_invocations`.

**Benchmark semantics changed:** no score can change. Every scoring predicate
consuming `ActionRecord` (`contained_actions`, `innocent`, `critical`,
`unsupported`) requires `a.success`, and a fabricated record always had
`success=False`.

**Caveat for review:** the fix changes canonical *content* in runs where a model
repeats an identical response action after budget exhaustion — one fewer
`ActionRecord`, a different `semantic_fingerprint`, and in a benign run the
non-scoring `containment` reason string reverts to "Correctly avoided
containment". No awarded value changes. No frozen artifact was regenerated.

### H-2. Provider failures were checkpointed and aggregated as defender performance

**Path:** `V2Agent.run` provider handling → `run_experiment_v2_cell` → `FormalBatch` → aggregate
**Discovered by execution during the provider-failure pass.**

When a provider call fails, `V2Agent` records the failure, breaks the turn loop,
and returns an empty `Decision`. `run_experiment_v2_cell` then builds a
*complete, valid* canonical run from that empty decision: no evidence, no
actions, no containment, low score. Nothing raises, so `FormalBatch` checkpointed
it as a normal `COMPLETED` run and the batch aggregated it alongside genuine
results.

`run_formal` applies no provider-error gate (`_gate_runs`, which checks
`provider_error_rate_zero`, is used by the canary only). A single Ollama drop
during the formal matrix would therefore have been published as a near-zero
defender score — exactly the "infrastructure failure as defender zero" outcome
the methodology forbids.

**Fixed at the run boundary, with the aggregation check retained as a backstop.**

The criterion is whether the provider/infrastructure delivered the model
interaction the cell needs in order to be measured — *not* whether the delivered
behaviour was valid or good. `run.protocol.provider_errors` is exactly that
signal: it is incremented only where a provider call raised `ProviderError`
(initial or repair). Malformed output, schema-invalid output, failed repair,
invalid arguments and denied actions all leave it at zero.

`formal_outcome_or_fail(cell, run)` in `experiment002r.py` now converts an
executed cell into a `RunOutcome` and, when `provider_errors > 0`, raises
`RunFailure` carrying that outcome. `run_formal` uses it for every cell, so an
infrastructure failure now takes the established fail-stop path:

- provider and turn audits preserved (carried on the exception)
- sanitized forensic evidence persisted
- active run marked `FAILED` — never `COMPLETED`
- experiment marked `ABORTED`
- prior `COMPLETED` checkpoints preserved
- later cells left `PENDING` and never executed
- no aggregate produced
- no automatic retry

`RunFailure` (new, in `formal_batch.py`) exists because a runner that *raises*
would otherwise lose the evidence it had already gathered: `execute()` previously
had only the empty default `RunOutcome` to hand to forensics. It now prefers an
outcome carried on the exception.

`json_valid` / `schema_valid` are recorded as `None` for an infrastructure
failure, since no output was delivered, and derived from the protocol stats
otherwise. They were previously hardcoded `True`, which would have misreported
every failed run in forensics.

`validate_formal_matrix` retains its provider-degraded check as defence in
depth; it can no longer be the first line, because such a run never reaches
aggregation.

**Verified by execution:** `test_provider_failure_fails_the_cell_and_aborts_the_formal_batch`
(full formal-batch path: FAILED/ABORTED/PENDING, preserved checkpoints, preserved
provider+turn audits in forensics, no aggregate, no retry, restart-safe),
`test_formal_outcome_or_fail_raises_only_for_infrastructure_failure`,
`test_bad_model_behaviour_remains_a_completed_measurable_run` (9 cases),
`test_bad_model_behaviour_and_infrastructure_failure_are_distinguishable`,
`test_provider_failure_is_audited_and_never_fabricates_a_decision`,
`test_provider_failure_forensics_remain_serializable`,
`test_validate_formal_matrix_refuses_provider_degraded_runs`.

**Benchmark semantics changed:** no. No scoring, autonomy, prompt, scenario,
budget or defender-evaluation logic was touched. The change decides only whether
a cell counts as *measured*, and every one of the nine delivered-but-bad model
behaviours below remains a measurable `COMPLETED` defender run.

**Model behaviour that must not, and does not, trigger the fail-stop.** Each was
driven end-to-end through `execute_002r_formal_batch` and confirmed non-vacuous:

| Case | turns | malformed | repair ok | finalized | provider errors |
|---|---:|---:|---|---|---:|
| malformed JSON | 1 | 1 | no | no | 0 |
| schema-invalid output | 1 | 1 | no | no | 0 |
| failed schema repair | 1 | 1 | no | no | 0 |
| successful schema repair | 1 | 1 | yes | yes | 0 |
| invalid action arguments | 1 | 1 | yes | yes | 0 |
| unsupported action | 1 | 1 | yes | yes | 0 |
| denied action (A1 revoke) | 2 | 0 | — | yes | 0 |
| missed attack (BENIGN on attack) | 1 | 0 | — | yes | 0 |
| never finalizes | 3 | 0 | — | no | 0 |

The denied-action case records `DENIED` / `NOT_EXECUTED` /
`authorization_denied`; the missed-attack case finalizes `BENIGN` on an attack
instance and is scored `detection = 0`. Both remain `COMPLETED` measurable runs.

---

## MEDIUM

### M-1. Aggregation failure reported neither completion nor abort

**Path:** `FormalBatch.execute` → `aggregate_builder`. **Discovered by execution.**

An exception in aggregation escaped `execute()` with every run `COMPLETED` but
the experiment left `RUNNING` and no aggregate written.

**Fixed.** Aggregation is wrapped; on failure the experiment is marked `ABORTED`
with a sanitized reason and no aggregate is produced. Completed checkpoints are
untouched.

**Verified by execution:** `test_aggregation_failure_aborts_instead_of_reporting_completed`.

### M-2. `aggregate_metrics` divided by zero on an incomplete matrix

**Path:** `bluerange/experiment.py` (v0.2 CLI; not the 002R formal path).
**Discovered by execution.**

`aggregate_metrics([])` raised `ZeroDivisionError`, as did any matrix with no
benign or no attack runs; `run_experiment` indexed `runs[0].model_audits[0]`
unguarded.

**Fixed.** Explicit guards raise a named `ValueError`. The aggregate is
*refused*, never defaulted to zeros.

**Verified by execution:** `test_aggregation_refuses_empty_matrix`.

### M-3. `compute_002r_metrics` produced normal-looking aggregates for incomplete input

**Path:** `bluerange/experiment002r.py` formal aggregate builder.
**Discovered by execution in the first pass; omitted from the first report — that
reporting gap is corrected here.**

`compute_002r_metrics([])` returned a populated dictionary of `None` rates and
zero totals rather than refusing. Nothing validated the aggregated set against
the manifest, so a partial matrix, a missing cell, a duplicated cell, an
unexpected cell, or a run that did not match its declared cell would all have
aggregated silently.

**Fixed.** `compute_002r_metrics` refuses an empty run set. A new
`validate_formal_matrix(runs, manifest)` refuses, with a named error identifying
the offending runs:

- empty run sets
- duplicate run IDs
- unexpected runs not in the manifest
- missing expected cells
- a count that disagrees with `expected_count`
- any run whose `(seed, profile, autonomy, kind)` disagrees with its cell
- any provider-degraded run (H-2)

`execute_002r_formal_batch` validates before computing, so an invalid matrix
aborts the experiment instead of publishing metrics.

**Verified by execution:** `test_compute_002r_metrics_refuses_an_empty_run_set`,
`test_validate_formal_matrix_accepts_the_exact_complete_matrix`,
`test_validate_formal_matrix_refuses_empty_partial_duplicate_and_unexpected`,
`test_validate_formal_matrix_refuses_a_run_that_does_not_match_its_cell`,
`test_validate_formal_matrix_refuses_provider_degraded_runs`,
`test_incomplete_formal_matrix_produces_no_aggregate_end_to_end`.

**Side effect worth noting:** the new validation immediately exposed two
pre-existing test fixtures whose runs did not match their own manifest cells
(a seed mismatch in `test_runtime_reliability_v2_integration`, a kind mismatch in
this suite's smoke matrix). Both fixtures were corrected to derive seed, profile
and control from the cell, exactly as the real `run_formal` does. No production
behaviour was changed to accommodate them.

---

## LOW

### L-1. Persisted artifacts could contain `NaN` / `Infinity`

`_encoded` used `json.dumps` defaults, which emit bare `NaN`/`Infinity` — invalid
JSON that strict parsers reject. **Fixed:** `allow_nan=False`.
**Verified by execution:** `test_persisted_artifacts_reject_non_finite_numbers`.

### L-2. `next()` without default in aggregation helpers

`_component` / `_category` (`experiment002.py`) and `credited`
(`experiment.py`) used bare `next()`, failing with an opaque `StopIteration` if a
scored component were ever absent. **Fixed:** explicit default and a named
`ValueError` identifying the run and component.

### L-3. Duplicate investigation attempts leave no attempt record — NOT fixed

A repeated successful investigation is short-circuited before any
`ActionAttemptRecord` is appended. The event still appears in `turn_audits`
(`duplicate_investigation: true`), in `PRIOR_TOOL_RESULTS` and in
`duplicate_investigation_attempts`, so nothing vanishes from the audit trail — but
it is absent from the typed attempt series.

**Not fixed, documented.** Investigation tools never become `ActionRecord`s, so
there is no correctness or scoring consequence, and adding records would change
artifact content for no reliability gain.

### L-4. Bare credentials under innocuous keys are not value-redacted — NOT fixed

`_sanitize` removes credentials by field name (`api_key`, `authorization`, …) and
by recognized value prefix (`Bearer x`, `api_key=x`, `token=x`, `password=x`).
A bare token under an innocuous key passes through. Measured:

```
redact  {"api_key": S}                      -> {}
redact  {"headers": {"Authorization": "Bearer S"}} -> {'headers': {}}
redact  {"note": "Bearer S"}                -> {'note': '[REDACTED]'}
LEAKS   {"note": S}                         -> {'note': S}
LEAKS   {"items": [{"detail": S}]}          -> {'items': [{'detail': S}]}
```

**Not fixed, documented.** No live path places a credential there: the gateway
uses `_api_key` only to build the `Authorization` header, and provider audits
carry solely `sanitized_error`, `http_status`, `usage` and timestamps. A
value-shaped credential detector would risk redacting legitimate identifiers
(session and identity IDs are similarly shaped), corrupting audit content to
defend against a path that does not exist. Flagged for review rather than
patched.

**Verified by execution** (the limitation is pinned, not assumed):
`test_known_limit_bare_credentials_under_innocuous_keys_are_not_value_redacted`.

---

## Verified by execution

Everything below drives the real code path with deterministic fakes.

**Crash safety and persistence.** Realistic canonical-construction failure mid
batch; interrupted-`RUNNING` restart; aggregation failure; failure injected
*inside* `_atomic_create` (patched `os.link`) proving no checkpoint and no
temporary remnant survive; failure injected into `persist_completed` during the
real `execute()` proving cell 3 never runs, cell 2 never becomes `COMPLETED`,
cell 1 stays intact, the experiment aborts, no aggregate is produced and restart
preserves the state; a hand-planted `.tmp` remnant proving it cannot masquerade
as a canonical record.

**Provider failure end-to-end.** A deterministic `FailingProvider` raising
`ProviderError` with a sanitized audit, driven through `run_experiment_v2_cell`:
the provider audit survives, a turn audit still exists with
`safe_failure_category == "PROVIDER_FAILURE"`, `parsed is None` (no fabricated
decision), no attempt is recorded, no tool executes, containment credit is zero,
and the run stays serializable.

**Infrastructure fail-stop through the real formal batch.** A three-cell batch
whose second cell hits the failing provider, run through
`execute_002r_formal_batch` with the same `formal_outcome_or_fail` the formal
command uses: statuses `['COMPLETED', 'FAILED', 'PENDING']`, experiment
`ABORTED`, cell 3 never invoked, cell 1's checkpoint intact and re-readable,
cells 2 and 3 absent from `runs/`, no aggregate, the failing provider
constructed once and called once (no retry), forensics carrying the provider
call audits and turn audits with `json_valid`/`schema_valid` as `None`, and a
restart that neither resumes nor retries.

**Both sides of the infrastructure/model boundary.** Nine delivered-but-bad
model behaviours (table under H-2) each driven end-to-end through the formal
batch and confirmed to stay `COMPLETED` with an aggregate produced, no forensic
record, and `provider_errors == 0`; the same nine confirmed not to raise from
`formal_outcome_or_fail`, while the provider-failed run does.

**Audit correlation.** An `AuditingFakeProvider` reproducing the HTTP adapter's
audit behaviour, driven through a two-cell batch with a forced schema repair.
Asserted: manifest cell ↔ canonical run identity (`run_id`, `kind`, `seed`,
`autonomy`); provider call IDs unique within a run and disjoint across runs;
every provider audit's `run_id` equals its run and its turn lies in range; every
action attempt's `run_id` equals its run and maps to a real turn audit; repair
calls never precede their initial call; executed attempts correspond one-to-one
with authorized controller audits; the forensic record for a failed cell
correlates to that cell and not a neighbour; exactly the declared cells are
checkpointed.

**Security boundaries.** Seeded canaries rather than field-name searches.
Evaluator-only `attack_steps` values (confirmed absent from observable
telemetry) are asserted absent from every persisted checkpoint, together with
nine evaluator-only field names. Forensic records are additionally asserted free
of `final_score`, `score_breakdown` and `canonical_record`. A distinctive
credential canary is seeded at multiple nesting depths in realistic shapes and
asserted absent from both the in-memory forensic record and the file on disk.

**Model-controlled input.** 60 deterministic hostile actions (seed 20260831)
across A1/A2/A3, spanning empty and 5000-character identifiers, sentinels
(`[invalid]`, `unknown`, `none`, `null`), wrong keys, wrong types, nulls, nested
dicts and lists. Branch spread reached:

```
28  INVALID/NOT_EXECUTED/invalid_arguments
 9  VALID/EXECUTED/none
 7  VALID/EXECUTED/tool_failure
 2  VALID/NOT_EXECUTED/authorization_denied
14  VALID/NOT_EXECUTED/recommendation_only
```

Invariant held throughout: no uncaught exception, the run stayed serializable and
fingerprint-stable across a round trip, invalid targets were always
`NOT_EXECUTED` with `target = null`, and no unresolved target became an
`ActionRecord`. Malformed-JSON and fabricated-evidence-reference cases are
covered separately.

**Synthetic smoke matrix.** Valid investigation, valid response, valid
finalization, invalid action, denied action, malformed decision, failed run,
successful multi-run batch, crashed multi-run batch, persistence and readback —
through the same `execute_002r_formal_batch` orchestration the formal experiment
uses.

---

## Inspection-only remaining claims

These are reasoned from source and are **not** backed by a regression test. They
should be read as weaker than everything above.

1. **No live code path places a provider credential into any audit.** Read from
   `gateway.py`: `_api_key` is used only to construct the `Authorization` header,
   and `ProviderCallAudit` carries no request body or headers. Underpins the L-4
   decision not to patch.
2. **The v2 model-facing prompt contains no evaluator truth.** `build_public_context`
   composes observables only, and `V2Run` does not retain `model_input`, so the
   persisted artifact cannot be used to assert this end-to-end. The
   `no_private_input` gate in `experiment002.main` covers turn audits, not the
   request itself.
3. **`os.link` hardlink semantics provide checkpoint immutability.** True on the
   local ext4 tree; not exercised on network or overlay filesystems.

---

## Architectural / future (not actioned)

1. **Only the 002R formal path is checkpointed.** `run_experiment` (v0.2 CLI) and
   `run_experiment_v2` still accumulate runs in memory and write once at the end;
   a crash loses all completed runs. `run_canary()` also uses the in-memory
   helper.
2. **No resume capability, by design.** An interrupted formal batch can only be
   marked `ABORTED`; remaining cells cannot be completed under the same
   experiment ID. A Ctrl-C at run 20 of 24 ends that experiment. A reviewed
   resume path is a separate decision.
3. **`_atomic_create` depends on `os.link`** for immutability.
4. **The `"[invalid]"` sentinel still exists in `ToolController.invoke`** as the
   redacted argument placeholder for denied calls. Confined to the audit layer
   and unable to reach `ActionRecord`, but a typed marker would be clearer than a
   string shaped like an identifier.
5. **`LLMDefenderAgent` (v1) infers execution from hardcoded denial strings** —
   brittle in the same way H-1 was. Not on the 002R formal path.
6. **`LLMDefenderAgent` indexes `self.observations[-1]` unguarded** at the
   attempt-recording site while guarding it elsewhere. Not reachable through
   current callers.
7. **Infrastructure classification is provider-transport-shaped.** After the H-2
   correction, the fail-stop criterion is `provider_errors > 0`, which covers a
   provider call raising `ProviderError` (connection, HTTP, timeout, malformed
   response envelope). An infrastructure fault that still returns a well-formed
   HTTP 200 — a silently truncated generation, a load balancer serving a
   different model — is not distinguishable from model behaviour by this
   criterion and would be measured as defender data. The manifest pins
   provider/model identity, and `_gate_runs` checks `model_id` on the canary
   path, but the formal path has no per-run model-identity assertion.

---

## Verification

All commands run locally, no network access.

| Gate | Result |
|---|---|
| `ruff check .` | All checks passed |
| `mypy bluerange` (strict) | Success: no issues found in 43 source files |
| `pytest` | **277 passed** |
| `git diff --check` | clean |

Test count: 162 pre-existing + 115 added by this audit = 277.

### Frozen artifact verification (re-run after the gap-closure pass)

```
MATCH  prompts/defender-v1.txt
MATCH  prompts/defender-v2.txt
MATCH  results/experiment-001-smoke.json
MATCH  results/experiment-002-smoke.json
MATCH  results/experiment-002r-smoke.json
MATCH  results/experiment-002r-canary.json
MATCH  results/experiment-002r-canary-2.json
MATCH  results/protocol-conformance-v2.json
MATCH  results/experiment-002r-formal.json        (permanently aborted; untouched)
MATCH  docs/experiment-002r-formal.md             (permanently aborted; untouched)
MATCH  docs/experiment-001-vs-002r-formal.md      (permanently aborted; untouched)
MATCH  canonical v0.1 validation regeneration -> 8e0758bc...c2ef64
```

No frozen benchmark artifact was regenerated. The canonical regeneration match is
the strongest available evidence that no benchmark semantics changed.

### Files changed

- `bluerange/formal_batch.py` — `_bounded`, total `forensic_from_exception`,
  `_record_failure`, `_abort`, RUNNING guard, aggregation guard,
  `BatchStatus.abort_reason`, `allow_nan=False`, `RunFailure` carrying evidence
  into forensics
- `bluerange/experiment002.py` — execution determined by controller invocation;
  explicit errors in `_component` / `_category`
- `bluerange/experiment002r.py` — `formal_outcome_or_fail` run-level
  infrastructure fail-stop; honest `json_valid`/`schema_valid`;
  `validate_formal_matrix`; empty-set refusal in `compute_002r_metrics`;
  validated formal aggregate builder
- `bluerange/experiment.py` — aggregation guards
- `tests/unit/test_pre_experiment_reliability_audit.py` — new, 115 tests
- `tests/unit/test_runtime_reliability_v2_integration.py` — fixture aligned to its
  manifest cell (test-only)

### Document integrity

The SHA-256 of this report is published with its delivery rather than embedded,
since embedding a digest inside the file it describes is self-referential.

---

## Remaining risks

- The blockers were latent in a path that executes only on failure, and the prior
  crash test passed because it used a short exception message. Failure-path
  coverage is now realistic, but it remains harder to keep honest than
  success-path coverage.
- H-1 means previously generated v2 artifacts came from a runtime that could
  fabricate a failed `ActionRecord`. Those artifacts are frozen and were
  deliberately not regenerated; their scores are unaffected, their action lists
  may contain such a record.
- H-2 now fails closed at the run boundary, so a provider-failed cell can no
  longer be checkpointed as `COMPLETED`. The residual is the classification
  criterion itself (Architectural item 7): an infrastructure fault that returns a
  well-formed successful response is indistinguishable from model behaviour and
  would be measured as defender data.
- A single provider failure now ends the whole 24-run matrix, by design. Combined
  with the absence of resume (Architectural item 2), a transient Ollama drop at
  run 20 means re-running the experiment from scratch under a new ID. That is the
  intended fail-closed trade, but it makes provider stability a precondition for
  completing the matrix rather than something the run can absorb.
- This audit did not re-derive scoring, autonomy or scenario correctness — frozen
  and out of scope.

---

SAFE_FOR_FORMAL_EXPERIMENT
