# BlueRange v0.1 Benchmark Validation

## Executive summary

The corrected 240-run experiment leaves the verdict **NOT READY**. The normal baseline detects and correctly contains all 20 attacks (mean score 90.25), but falsely contains all 10 benign controls (mean score 53.00), giving 0% benign specificity. The baseline was not tuned during this corrective pass.

## Methodology

Attack seeds are 101–120 and benign seeds are 9001–9010. Each of eight agents runs all 30 instances. Profiles rotate deterministically through `[COMPLETE, PARTIAL, AMBIGUOUS, NOISY]`. Distributions use population standard deviation for this predetermined measured population and also store sample standard deviation.

```bash
.venv/bin/python -m tests.validation --output results/benchmark-validation-v0.1.json
```

The canonical JSON contains all 240 run records and corrected semantic labels. Attack containment means a successful action against the evaluator-known compromised identity/session. False containment means successful containment of an evaluator-known legitimate identity/session; generic successful action counts are no longer used. Regeneration after the final public-surface fix was byte-for-byte unchanged (SHA-256 `8e0758bca25658fe3b52c7ce8874a91102e161cce28dc459ac33f11c67c2ef64`), so measurements and instance fingerprints did not change.

## Corrected results

| Agent | Attack score mean | Benign score mean | Attack detection | Correct attack containment | False containment | Mean safety |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 90.25 | 53.00 | 100% | 100% | 100% | 27.00 |
| do-nothing | 37.00 | 47.00 | 0% | 0% | 0% | 27.00 |
| disable-everything | 27.00 | 12.00 | 0% | 100% | 100% | 2.00 |
| random-responder | 52.65 | 44.00 | 0% | 75% | 100% | 10.67 |
| overconfident | 63.00 | 51.00 | 0% | 100% | 100% | 17.00 |
| minimal-investigator | 61.75 | 72.00 | 0% | 0% | 0% | 32.00 |
| safe-control | 69.75 | 95.00 | 0% | 0% | 0% | 32.00 |
| oracle | 95.50 | 95.00 | 100% | 100% | 0% | 34.00 |

Baseline attack scores: mean 90.25, median 93, population SD 4.7631, sample SD 4.8869, min 82, max 93. Baseline benign scores are uniformly 53. Random-responder attack scores: mean 52.65, median 53, population SD 10.8916, min 27, max 73. All exact distributions and fingerprints are in the JSON artifact.

## Corrective changes represented in these measurements

The regenerated data includes evaluator-target containment labels, successful A3 compromised-identity disablement, legitimate and critical-session collateral, grounded benign evidence, typed dispositions, semantically distinct benign profiles, and seed-derived timing jitter. Penalty output uses `maximum_component_loss`, explicitly describing the maximum already represented by component scoring; it is not separately subtracted.

The first corrective pass left a residual documented-API leak: `bluerange.scenarios.build_instance` let callers select attack/control generation, and its exported `ObservableInstance` disclosed `control`. The corrected public scenario surface exports neither symbol, nor `GroundTruth` or `load_ground_truth`; observable generation is private evaluator/orchestrator implementation and its observable wrapper has no control field. Supported instance, context, and result surfaces expose no control label. Arbitrary in-process Python can still import private generator/evaluator modules or inspect/read repository state, so no security boundary is claimed.

## First-pass defects and current disposition

The first pass found identity-derived sessions, inert seeds, a leaked result control label, fabricated evidence credit, missing legitimate-session harm, unsupported escalation/narrative credit, repeated/failed action gaming, and misleading penalty semantics. The corrective review additionally found public truth-bearing generation, incorrect containment-rate labels, non-semantic benign profiles, fixed event timing, missing direct invariants, benign conclusion/evidence gaming, inconsistent identity disablement, critical-session mapping gaps, and exact generator learnability. A final residual review then found that the nominally observable public generator still selected control state and returned an observable object with a public control field; both surfaces are now private/unexported and the field is removed. All except learnability and genuine process isolation are corrected and directly tested; the complete itemized record is in `docs/benchmark-integrity-review.md`.

## Remaining threats and recommendation

The private generator and one-family template remain learnable through same-process private imports or repository reads. Benign controls are structurally narrow, and the safe-control/oracle benign scores have zero variance. Before public release, isolate agents from evaluator code/files, use held-out private generation, add independently authored families, broaden benign contexts, and calibrate semantic rubrics with human raters.

Verdict: **NOT READY for unqualified external alpha.**
