# Runtime reliability repair 002R

Status: PASS. This was deterministic synthetic runtime engineering only. No benchmark, Qwen, Ollama, real provider, network, commit, push, publication, secret inspection, or aborted-data recovery occurred.

## Final provenance and fresh-canary gate correction

The formal manifest now derives `scenario_version` from a representative generated evaluator
instance used by the formal cells. Its version is `1.1`, and its scenario hash remains the hash
reported by those canonical cell results. A regression test compares both manifest fields with the
actual generated scenario and scenario source used by a representative cell.

The formal pre-run gate now reads only the immutable
`results/experiment-002r-canary-2.json`. Before any manifest or runner work, it verifies the frozen
SHA-256 `5b7c60d2399481d684f86a5df21f2b1f572f37cbe39a3d2488bf08ccb326d16c`,
schema `experiment-002r-canary-2-v1`, provider, model, complete parameter set, complete passing
control-gate set, and `canary_passed: true`. Missing, old, altered, wrong-schema, wrong-control,
wrong-model, wrong-parameter, and non-passing artifacts fail closed. Deterministic tests prove the
old failed canary cannot start formal execution and that only an exact byte copy of the frozen fresh
canary passes the pre-run verifier; no runner or provider is invoked by these tests.

## Actual-path integration correction

The initial repair was incomplete: its typed attempts were wired only into the legacy `run_experiment` path, and `experiment002r.run_formal` still called the all-in-memory `run_experiment_v2` matrix before writing any output. This corrective pass wires `ActionAttemptRecord` directly into `V2Agent`/`V2Run`, introduces `run_experiment_v2_cell`, and makes the matrix helper compose that single-cell primitive. The existing schema-only repair behavior is retained; a semantically invalid initial action is now also preserved as a non-executed typed attempt before the repaired decision continues.

The future `--formal` path now creates an immutable 24-cell manifest under the new, non-aborted identifier `experiment-002r-new-attempt`, then invokes the shared `execute_002r_formal_batch` orchestration one cell at a time. Each `V2Run` is canonically serialized and validated before its immutable checkpoint is published. The aggregate is built only after all 24 checkpoints exist. Neither the permanently aborted formal identifier nor any frozen smoke/formal report is a write target.

Actual-path tests cover all ten action cases through v2 scoring and JSON readback, assert the formal function contains no call to the old full-matrix helper, and exercise the same 002R orchestration with failing and successful three-cell matrices. The `[invalid]` regression crosses that orchestration, checkpoints successfully with a nullable target, creates no scoring action and earns no containment credit.

## Root cause and semantic repair

`ToolController` used the internal string sentinel `"[invalid]"` when controlled-tool argument validation failed. The Experiment 002R result path derived a response target from that audit representation and attempted to construct `ActionRecord(target="[invalid]")`. The unchanged `SafeId` regex correctly rejects brackets, so canonical Pydantic construction raised instead of preserving the failed attempt.

The repair adds an immutable `ActionAttemptRecord` audit type. It retains the original attempted argument object, while its resolvable target is either a validated identifier or `null`. It independently records argument validation, validation failure, authorization decision, denial reason, execution status, tool success and safe failure category. Invalid, denied and recommendation-only attempts never enter the environment and never become scoring actions. Executed response actions with validated targets continue to produce ordinary `ActionRecord`s, including safe tool-level failures for valid but nonexistent targets.

The `ActionRecord` regex and all defender, scenario, generator, evidence, truth, scoring, autonomy, tool-permission, budget, model-decision, provider and protocol behavior remain unchanged. Invalid attempts cannot earn containment credit because only executed, resolved actions enter `ScoreInput.actions`.

## End-to-end TDD results

The RED phase first added full decision → schema validation → authorization → attempted-action audit → scoring → canonical construction → JSON serialization tests and atomic batch tests. Collection failed because the persistence module did not exist. The implementation then made all focused and full-suite tests GREEN.

| Case | Execution | Safe classification | Result |
|---|---|---|---|
| Valid existing target | Executed; ordinary action retained | `none` | PASS |
| Nonexistent valid target | Executed; tool safely failed | `tool_failure` | PASS |
| Malformed target | Not executed | `invalid_arguments` | PASS |
| Missing target | Not executed | `invalid_arguments` | PASS |
| Wrong argument name | Not executed | `invalid_arguments` | PASS |
| Wrong argument type | Not executed | `invalid_arguments` | PASS |
| Denied action | Not executed | `authorization_denied` | PASS |
| Prohibited by autonomy | Not executed | `authorization_denied` | PASS |
| Recommendation | Not executed | `recommendation_only` | PASS |
| Schema-valid decision with semantically invalid arguments | Not executed | `invalid_arguments` | PASS |

Every case preserves the original arguments in the typed audit, constructs a canonical result without crashing, serializes and validates on readback, keeps the safe classification, and prevents incorrect containment credit.

## Atomic checkpoint and status design

`FormalBatch` creates one directory per experiment. `manifest.json` is immutable and exclusively created. It contains the experiment ID, full expected cells/count, Git commit/dirty state, BlueRange/runtime versions, prompt hash, scenario hash/version, provider/model/parameters, seeds/profiles/autonomies and start time. Duplicate experiment or run IDs fail closed.

Each completed canonical record is validated into an immutable typed checkpoint, encoded to a unique same-directory temporary file, flushed and file-fsynced, then exclusively published without overwriting. The containing directory is fsynced where supported. Only after publication does the status become `COMPLETED` and the next run begin. Mutable `status.json` uses the same flush/fsync discipline followed by atomic replacement. Partial temporary remnants do not match completed paths and cannot be read as completed records.

Run status is exactly `PENDING`, `RUNNING`, `COMPLETED` or `FAILED`; experiment status is `INITIALIZING`, `RUNNING`, `COMPLETED` or `ABORTED`. Immutable records are separate from mutable status and are never rewritten.

## Failure, forensics and restart

An unexpected runtime exception atomically writes a sanitized typed forensic record before marking the run `FAILED` and experiment `ABORTED`. It records the run/cell, provider-call and model-turn audits, JSON/schema validity, parsed decision, attempted action, validation failure, authorization decision, execution status, safe category, tokens, latency, exception category and sanitized message. Recursive tests remove secret-named fields and credential-shaped values at arbitrary nesting depth.

The deterministic failing three-run test forced run 2 to raise during result processing. Run 1 remained valid, immutable and readable; run 2 received a `FAILED` forensic checkpoint; run 3 was never invoked and remained `PENDING`; the experiment became `ABORTED`; and no aggregate was created. Reopening and attempting execution retained `ABORTED`. The successful three-run test persisted all records, created the completion aggregate only after all checkpoints, and remained `COMPLETED` after restart/readback.

## Integrity and gates

All frozen hashes matched before and after work:

- `prompts/defender-v1.txt` — `bb152360c77131b5d4b1b53bf33668a1b57d8a50499c979ebe361f4a52c5fdae`
- `prompts/defender-v2.txt` — `1edcb1b12b0d3ef1463c1330015fb127409c76e311323879545297826dfa9fe4`
- `results/experiment-001-smoke.json` — `cd3b8308e3771f463ec364558008bb8f9d66e30ea467a293ae361a017f7f0958`
- `results/experiment-002-smoke.json` — `e6d677ee3ebae432da02f4bc2b24f14cfbfb7ee50d61eaeb868a4718d8140414`
- `results/experiment-002r-smoke.json` — `5dcf5e06f11c7bd74395aa3a4434c170cd298d7e815e4a5ad09dafacf7890ad1`
- `results/experiment-002r-canary.json` — `ed7e0b001a00aab064a19e5c337a35557a1e7bc88db36139e3536a70bfc27521`
- `results/experiment-002r-canary-2.json` — `5b7c60d2399481d684f86a5df21f2b1f572f37cbe39a3d2488bf08ccb326d16c`
- `results/protocol-conformance-v2.json` — `41aa5bfa3f5e4fbfd200b4614b03609c777aec1fbe2a587a66b3e7d3e9c12d1a`
- aborted `results/experiment-002r-formal.json` — `0f5275c2ca29a70cdd9dce2732e2b3e8d9952e110da30edffc62decfc36ee6bc`
- aborted `docs/experiment-002r-formal.md` — `301096936b51b9911635ed013224354c3dc618cb3fc0c46812fd636b8f838e00`
- aborted `docs/experiment-001-vs-002r-formal.md` — `fa0be595466209f3a5549e1e496234858bb406b5ab6c9729d84978d7260dcf6b`
- canonical v0.1 regenerated output — `8e0758bca25658fe3b52c7ce8874a91102e161cce28dc459ac33f11c67c2ef64`

Gates passed: Ruff, strict mypy, full pytest (162 tests), `git diff --check`, canonical v0.1 regeneration/hash, all frozen hash checks, deterministic actual-002R-path crash/restart, deterministic actual-002R-path successful restart, partial-remnant handling, duplicate-ID rejection, changed-file inspection and recursive synthetic secret-field/value scanning.

The Ollama call count was not queried because no repository-local baseline counter was available and service interaction was prohibited. No code path used a real provider; all model behavior was supplied by the deterministic in-process fake provider.

## Changed files and limitations

The final gate correction changed only `bluerange/experiment002r.py`, `tests/unit/test_runtime_reliability_v2_integration.py`, this report and `results/runtime-reliability-repair-002r.json`. Earlier repair and integration files remain as documented by the original report.

The persistence layer was verified with synthetic callbacks only; no new formal experiment was run. Directory fsync is necessarily best-effort on platforms lacking directory-sync support. Aborted Experiment 002R artifacts were neither interpreted nor modified.

READY_FOR_002R_NEW_ATTEMPT
