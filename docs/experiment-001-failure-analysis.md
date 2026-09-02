# Experiment 001 failure analysis

## Scope and method

This is the mandatory pre-change analysis for Experiment 002. It was created before any defender-v2 prompt, runtime, schema, test, or implementation change. The source was the 24 immutable individual run records in `results/experiment-001-smoke.json` (SHA-256 `cd3b8308e3771f463ec364558008bb8f9d66e30ea467a293ae361a017f7f0958`). No run was replayed.

A run was unsuccessful when its recorded evaluator-grounded `safe_success` value was false. Twenty of 24 runs were unsuccessful. Each unsuccessful run was reviewed turn by turn using its preserved raw response, parsed request, validation error, tool result, final assessment, evaluator score breakdown, and authorization result. Categories are non-exclusive: the counts below deliberately overlap. A malformed last turn is both a protocol failure and, when it prevents completion, a lifecycle failure. A missing evaluator-grounded final assessment is a grounding failure even when a correct intermediate hypothesis existed.

The review used these operational rules:

- **PROTOCOL_FAILURE**: at least one response failed the declared schema or supplied an invalid/unusable action or evidence representation.
- **LIFECYCLE_FAILURE**: the run did not finalise, exhausted its turn budget, repeated an identical successful investigation without relevant state change, or continued after evidence already supported a terminal assessment.
- **REASONING_FAILURE**: the run selected a wrong subject/disposition, failed to connect sufficient evidence to a terminal conclusion, or made an unsupported conclusion. Correct intermediate suspicion alone did not prevent this classification when the run never converted it into a decision.
- **RESPONSE_FAILURE**: a supported compromise conclusion lacked a correct proportional response, targeted the wrong object, or kept recommending/attempting actions without completing the response lifecycle.
- **GROUNDING_FAILURE**: the evaluator recorded no grounded final evidence, evidence was materially altered/fabricated, or the final conclusion was unsupported. In this baseline, all 20 unsuccessful records had `grounded_evidence=false`; most did so because no final assessment survived validation.

Evaluator truth and attack/control labels remain confined to offline analysis and scoring. This document is not model-facing. Examples below replace scenario identities, sessions, addresses, assets, and ticket values with opaque placeholders and do not reveal expected answers.

## Exact overlapping counts

| Category | Count | Unsuccessful run IDs |
|---|---:|---|
| PROTOCOL_FAILURE | 10 | run-000001, run-000003, run-000004, run-000011, run-000015, run-000017, run-000018, run-000019, run-000020, run-000023 |
| LIFECYCLE_FAILURE | 16 | run-000001, run-000003, run-000004, run-000005, run-000006, run-000007, run-000009, run-000011, run-000013, run-000015, run-000017, run-000018, run-000019, run-000020, run-000021, run-000023 |
| REASONING_FAILURE | 12 | run-000001, run-000003, run-000005, run-000007, run-000009, run-000011, run-000013, run-000015, run-000017, run-000019, run-000021, run-000023 |
| RESPONSE_FAILURE | 8 | run-000001, run-000003, run-000005, run-000007, run-000011, run-000017, run-000019, run-000023 |
| GROUNDING_FAILURE | 20 | run-000001, run-000003, run-000004, run-000005, run-000006, run-000007, run-000008, run-000009, run-000010, run-000011, run-000013, run-000015, run-000017, run-000018, run-000019, run-000020, run-000021, run-000022, run-000023, run-000024 |

The four unsuccessful runs not classified as lifecycle failures (run-000008, run-000010, run-000022, run-000024) did finalise promptly with the correct benign disposition, but their final evidence was not evaluator-grounded. The four successful runs were run-000002, run-000012, run-000014, and run-000016 and are excluded from failure counts.

## Findings by category

### Protocol failures

All ten protocol failures contain a preserved `ValidationError: model output rejected`; each affected run ended immediately after that invalid response, with no repair attempt in v1. The malformed rate among unsuccessful runs was 10/20, and 10/24 overall. The raw malformed responses remain in the frozen JSON for audit.

Representative redacted example: after several valid investigation turns, a response used an action shape that did not satisfy the declared union. The runtime recorded the raw object and validation error, but could not produce a final assessment. This is both a schema failure and a completion failure.

### Lifecycle failures

Sixteen unsuccessful runs never produced a valid final action. Ten ended on a malformed response. Six others consumed all 12 model turns or stopped after repeated investigation/response cycling. Exact duplicate successful investigations were common, such as repeatedly requesting `get_authentication_history({"identity_id":"subject-A"})` or `inspect_identity({"identity_id":"subject-A"})` after the same result was already available. The baseline counted these against the investigation budget and resent growing context.

Representative redacted example: a run asserted `COMPROMISE` for `subject-A` on every turn, repeated the same two investigation calls, issued several recommendations, and reached turn 12 without `final`. The evidence threshold had already been met on turn 1.

### Reasoning failures

All 12 unsuccessful attack runs recognised the correct suspicious subject in at least one schema-valid intermediate assessment, but none converted that recognition into evaluator-confirmed final detection. They are classified as failure to connect sufficient evidence to a terminal conclusion, not as failure to notice the subject. This distinction motivates separate attack-recognition and final-detection metrics in Experiment 002.

Representative redacted example: the model repeatedly reported high-confidence compromise for `subject-B` using observable authentication and data-access signals, then continued investigating until the run ended. The intermediate reasoning was directionally correct, but no final decision existed for evaluator credit.

### Response failures

Eight attack runs had a supported intermediate compromise conclusion but did not complete a correct proportional response. These were the A1 and A3 failures without evaluator-confirmed containment: run-000001, run-000003, run-000005, run-000007, run-000011, run-000017, run-000019, and run-000023. Some recommended the correct session action but never finalised; others created/escalated an incident without the required containment or ended malformed.

Representative redacted example: the model recommended revoking `session-X`, later repeated the same recommendation, but neither completed an executable response under the active autonomy nor emitted a terminal response stating what was recommended or performed.

### Grounding failures

All 20 unsuccessful runs have `grounded_evidence=false` in their frozen evaluator-derived outcome. Sixteen lacked a valid final assessment. Four benign runs did finalise but did not carry sufficient exact observable evidence into the final assessment. The v1 requirement to reproduce arbitrary evidence prose exactly made otherwise reasonable conclusions fragile and provided no stable referential link for evaluator resolution.

Representative redacted example: a final response stated that activity was consistent with an approved workflow, but its final evidence field did not preserve the exact observable fact needed by the evaluator. The disposition was correct, yet the record was ungrounded.

## Pre-change conclusion

The baseline failure modes support a narrowly scoped v2 intervention: stable opaque evidence references, explicit lifecycle states, duplicate-investigation accounting, bounded schema repair, compact separated context, and explicit terminal fields. They do not justify changing scenario content, truth, scoring, authorization, tools, budgets, seeds, model parameters, or evaluator semantics. The baseline already shows that intermediate recognition can be strong while final detection is zero, so Experiment 002 must report both without granting scoring credit to recognition.
