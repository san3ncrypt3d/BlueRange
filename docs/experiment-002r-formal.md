# BlueRange Experiment 002R Formal — Aborted Run Report

## Status

**ABORTED: systematic benchmark-runtime failure.**

The authorised 24-run matrix began under the frozen configuration, but BlueRange terminated while converting an attempted response action into its canonical `ActionRecord`:

```text
ActionRecord.target rejected the internal sentinel `[invalid]`
```

The sentinel violates the canonical target identifier pattern. This occurred after model generation and protocol handling, during benchmark result construction. It is a runtime serialisation defect, not a provider outage, malformed JSON result, cyber-reasoning finding, or autonomy-policy outcome.

Per the experimental integrity rule, the experiment stopped. It was not repaired or resumed under the same identifier.

## Pre-execution state

- Git HEAD: `01479fe5a6c001fe3a215ed63d8a03e9d9d1aba7`
- BlueRange: `0.1.0`
- Defender: frozen `defender-v2`
- Prompt SHA-256: `1edcb1b12b0d3ef1463c1330015fb127409c76e311323879545297826dfa9fe4`
- Scenario version: `1.1`
- Scenario hash: `e87b96dc51d302ef36662a4f5bbd96978494e82ab42a3326cf5c86fd2c07148c`
- Model: `qwen3:14b-q4_K_M`
- Ollama: `0.31.1`
- Temperature/top-p/model seed: `0.2 / 0.9 / 17`
- Output mode: `JSON_OBJECT`
- Intended matrix: A1/A2/A3 × COMPLETE/AMBIGUOUS × seeds 101/202 × attack/benign = 24

The working tree was already dirty with the previously verified uncommitted v0.2 and experiment files. It was recorded before execution. No code or configuration changed after formal run 1 began.

## Evidence preserved

Ollama's service access log records 15 successful HTTP 200 chat-completion calls during the formal execution window. This confirms that the model/provider path was operating before the runtime crash.

It does **not** establish how many complete benchmark runs finished. The batch runner accumulated records in memory and wrote the canonical result only after the full matrix returned. The process terminated before that write, so zero canonical run records survived. Ollama access logs do not retain the model decisions needed to reconstruct them.

No values have been inferred or manufactured from the request count.

## Metrics

No formal protocol, autonomy, cyber-defence, token or aggregate metrics are reported. The required 24-run matrix did not complete, and partial canonical records were unavailable.

The original result path now contains this immutable aborted-run record rather than a fabricated benchmark result.

## Integrity response

- Systematic infrastructure failure: **yes**
- Stopped immediately after surfaced failure: **yes**
- Repair during experiment: **no**
- Resume under same identifier: **no**
- Mid-experiment tuning: **no**
- Prompt/schema/provider/scenario/scoring/autonomy changes: **no**
- 480-run experiment: **not run**

## Required remediation before another formal attempt

1. Represent denied/invalid action targets with a schema-valid typed value or an explicit optional/denied target representation; never pass `[invalid]` into `ActionRecord`.
2. Add a regression test covering invalid/denied response arguments through complete result construction.
3. Checkpoint each completed formal run atomically so a later infrastructure failure does not erase earlier records.
4. Preserve provider and protocol audits for the failing run before aggregate construction.
5. Give any repaired rerun a new experiment identifier; do not overwrite this aborted record.

## Decision

**RUNTIME_REPAIR_REQUIRED**

The empirical justification is direct: the model endpoint returned successful responses, but BlueRange crashed in its own result-construction path and lost all in-memory run records. Model or autonomy conclusions would therefore be invalid.
