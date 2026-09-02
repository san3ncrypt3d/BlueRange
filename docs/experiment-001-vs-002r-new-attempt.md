# Experiment 001 vs Experiment 002R New Attempt

## Comparison question

This is not a pure prompt comparison. Defender-v2 also includes generic protocol, provider-compatibility, auditing and lifecycle corrections introduced after Experiment 001.

The appropriate question is:

> How much did removing protocol confounding change measured defender performance?

Both experiments used the same Qwen model family/configuration, seeds, profiles, autonomy levels and attack/benign structure, but v2's runtime presentation and lifecycle are materially different. With 24 runs each, differences are directional rather than statistically significant.

## Side-by-side results

| Metric | Experiment 001 / v1 | Experiment 002R new attempt / v2 | Directional change |
|---|---:|---:|---:|
| Provider success | 100% | 100% | unchanged |
| Runs with malformed initial output | 41.7% | 54.2% | worse at run level |
| First-pass protocol validity | 58.3% run-level | 65.9% turn-level | not directly equivalent |
| Post-repair validity | 58.3% (no repair) | 78.0% turn-level | improved with repair |
| Finalisation | 33.3% | 62.5% | +29.2 pp |
| Grounded finalisation | 16.7% | 62.5% | +45.8 pp |
| Attack recognition | 100%* | 16.7% | lower under stricter v2 diagnostic |
| Final attack detection | 0% | 33.3% | +33.3 pp |
| Correct containment | 16.7% | 58.3% | +41.7 pp |
| Benign specificity | 100% | 100% | unchanged |
| False containment | 0% | 0% | unchanged |
| Overall safe success | 16.7% | attack 33.3%; benign 83.3% | materially improved, definition split |
| Mean score | 52.79 | 71.75 | +18.96 |
| Mean safety | 27.83 | 29.92 | +2.08 |
| Model turns/run | 8.21 | 2.29 | −72.1% |
| Tool calls/run | 5.58 | 0.625 | −88.8% |
| Tokens/run | 28,646.7 | 7,334.8 | −74.4% |
| Provider latency/run | 209,938 ms | 68,039 ms | −67.6% |

`*` Experiment 001's retrospective recognition metric counted any valid intermediate compromise assessment. The v2 metric is more tightly tied to its recorded subject sequence; treat this comparison cautiously.

## Autonomy change

Experiment 001 attack containment by autonomy:

- A1: 0%
- A2: 50%
- A3: 0%

Experiment 002R new attempt:

- A1: 0%
- A2: 100%
- A3: 75%

The v2 runtime converted greater autonomy into more effective containment without false benign containment. The gain was not monotonic: A2 outperformed A3 on containment.

## Protocol/runtime versus reasoning

Evidence that protocol confounding was reduced:

- Finalisation rose from 33.3% to 62.5%.
- Grounded finalisation rose from 16.7% to 62.5%.
- Turns, tool calls, tokens and latency fell sharply.
- Final detection and containment both improved.
- Provider success remained 100%, ruling out infrastructure degradation.

Evidence of remaining defender/model difficulty:

- More than half of v2 runs experienced at least one malformed initial response.
- Post-repair turn validity was 78.0%, not near-perfect.
- Only 35.7% of attempted repairs succeeded.
- Attack finalisation was 33.3%.
- Evaluator-confirmed attack detection was 33.3%.
- Some attacks were contained without a valid final conclusion.

## Safety

Benign specificity remained 100%, with no false containment in either experiment. V2 benign safe success increased to 83.3%. No legitimate critical identity was disabled or isolated.

This is encouraging directional evidence, but not evidence of general autonomous-defender safety. There is only one scenario family, two seeds and two evidence profiles.

## Conclusion

Removing protocol confounding materially changed the measured result: the runtime became substantially more efficient, grounded lifecycle completion improved, and attack containment increased without a benign false-containment penalty. However, the model still struggled to complete attack investigations and conform reliably to the schema.

The next discriminating experiment is a second model under exactly the same frozen benchmark/runtime—not a larger Qwen run and not a benchmark redesign.

`TEST_SECOND_MODEL_FIRST`
