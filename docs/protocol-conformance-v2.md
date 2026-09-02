# Defender-v2 protocol conformance report

## Outcome

The non-benchmark protocol lab **PASSed**. The permitted fresh two-run A1 canary also **PASSed**. Formal Experiment 002R was **NOT RUN** and its authorisation remains **NO** pending a separate user decision. No benchmark score is reported.

The root cause was a combination of generic runtime defects: defender-v2 requests carried provider-native `tools`/`tool_choice` metadata while requiring a returned singular `action` field; runtime presentation did not make that single contract sufficiently machine-readable; schema repair lacked the original invalid object, schema-derived literals and field types, and anti-hallucination constraints; and malformed model turns were added to turn audits only after successful validation. After removing those conflicts and strengthening only generic protocol mechanics, Qwen produced valid first-pass objects in every neutral lab case. The evidence therefore supports runtime presentation plus repair/audit mechanics as the cause, not demonstrated Qwen 14B incapacity.

## Canonical contract

Accepted literals are derived programmatically from the authoritative Pydantic schema:

- `lifecycle_state`: `INVESTIGATE`, `RESPOND`, `FINALIZE`
- `assessment.disposition`: `UNKNOWN`, `COMPROMISE`, `BENIGN`
- `action.type`: `tool`, `recommendation`
- neutral lab `action.name`: `inspect_object`, `quarantine_object`

There is exactly one decision field, singular `action`. `INVESTIGATE` requires one `inspect_object(object_id)` action; `RESPOND` requires one `quarantine_object(object_id)` recommendation; `FINALIZE` means no request but retains the required key as `"action": null`. Missing, extra, plural, multiple, wrongly cased, wrongly shaped, and fabricated-reference forms fail closed.

The unchanged defender-v2 prompt was combined with generated protocol presentation. Defender-v2 requests now send no provider-native function descriptors. Provider-neutral gateway behavior is retained for other callers that intentionally supply native tool descriptors.

## Repair and auditing

At most one repair is permitted. Its payload contains only the original invalid JSON, exact Pydantic-derived error locations/types, schema-derived accepted literals, schema-derived required fields/types, and instructions to preserve supported content, add no evidence or identifiers, avoid changing the conclusion except where structurally required, and return one JSON object only. Existing exposed-reference and tool-argument validation remains authoritative; a new identifier introduced by repair fails.

Every attempted provider call now creates a turn audit before lifecycle entry is considered. Invalid JSON, schema errors, repair attempt/result, safe failure category, provider-call ID, token usage, and actual non-zero latency are retained. Invalid decisions do not reach `ToolController`. Audits omit requests, credentials, authorization headers, and raw provider error details.

## Real non-benchmark lab

The lab used only `event-001: synthetic observation alpha`, `event-002: synthetic observation beta`, `inspect_object(object_id)`, and `quarantine_object(object_id)`. It contained no benchmark scenario, attack/control label, compromised subject, evaluator truth, score, seed, expected answer, or scenario generator.

| Measurement | Actual |
|---|---:|
| Provider requests | 3 |
| Provider success | 100% |
| JSON syntax validity | 100% |
| First-pass schema validity | 100% |
| Post-repair protocol validity | 100% |
| Repair attempts / successes | 0 / 0 |
| Input / output / total tokens | 5,152 / 514 / 5,666 |
| Actual provider latency | 83,168.630 ms |

All failure counts were zero: missing field, extra field, wrong enum, wrong action shape, multiple actions, fabricated reference, provider failure, call cap, and other. Each isolated `INVESTIGATE`, `RESPOND`, and `FINALIZE` case passed on its first response. Independent recomputation from individual provider-call audits matched the recorded metrics. Lab status: **PASS**.

## Fresh A1 canary

Only after the lab passed, one fresh attack/benign A1 pair ran under the frozen Experiment 002R model, prompt, provider mode, parameters, scenario controls, budgets, and seed. It used 3 provider requests, all successful; both runs entered the lifecycle and no invalid decision reached `ToolController`. No repair was needed. Actual canary usage was 9,500 input, 691 output, and 10,191 total tokens with 90,068.259 ms provider latency. Canary status: **PASS**.

The lab and canary used 6 real provider requests in total, including zero repairs, under the absolute cap of 12. No preflight, formal 24-run 002R, or 480-run experiment ran.

## Verification

Commands executed:

```text
.venv/bin/pytest -q tests/unit/test_protocol_conformance.py
.venv/bin/pytest -q tests/unit/test_protocol_conformance.py tests/unit/test_experiment002.py tests/unit/test_experiment002r.py
.venv/bin/ruff check bluerange tests
.venv/bin/mypy bluerange tests
.venv/bin/pytest
git diff --check
sha256sum prompts/defender-v1.txt prompts/defender-v2.txt results/experiment-001-smoke.json results/experiment-002-smoke.json results/experiment-002r-canary.json results/experiment-002r-smoke.json
.venv/bin/python -c 'from bluerange.experiment002 import _canonical_hash; print(_canonical_hash())'
rg -n 'tool_calls|tool_call|next_action|"actions"|"tool"' prompts/defender-v2.txt bluerange/experiment002.py bluerange/experiment002r.py bluerange/protocol_conformance.py bluerange/models/gateway.py
rg -n -i 'authorization|api[_-]?key|bearer|password|secret' results/protocol-conformance-v2.json results/experiment-002r-canary-2.json
.venv/bin/python -m bluerange.protocol_conformance --lab
.venv/bin/python -m bluerange.protocol_canary
```

Final measured gates before real calls were Ruff PASS, strict mypy PASS, full pytest `127 passed`, and `git diff --check` PASS. Frozen hashes matched: defender-v1 `bb152360...fdae`, defender-v2 `1edcb1b1...e4`, Experiment 001 `cd3b8308...0958`, aborted Experiment 002 `e6d677ee...0414`, prior 002R canary `ed7e0b00...521`, prior 002R smoke `5dcf5e06...9ad1`, and canonical v0.1 `8e0758bc...ef64`.

Changed or created for this investigation: `bluerange/protocol_conformance.py`, `bluerange/protocol_canary.py`, `bluerange/models/gateway.py`, `bluerange/experiment002.py`, `tests/unit/test_protocol_conformance.py`, `tests/unit/test_experiment002.py`, this report, `results/protocol-conformance-v2.json`, and `results/experiment-002r-canary-2.json`. The workspace already contained unrelated and uncommitted changes; they were preserved. No commit, push, publish, browsing, secret inspection, outcome tuning, prompt modification, or frozen-artifact modification occurred.

Limitations: the real lab has only three isolated cases and is an engineering gate, not a statistical claim; because all three were first-pass valid, real-model repair behavior was not exercised (deterministic tests cover successful repair, failed repair, new identifiers, and the one-repair ceiling); and the fresh canary is only one pair and cannot support cyber-performance claims.
