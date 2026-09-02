# Experiment 001 smoke report

Decision recommendation: **DO NOT PROCEED**.

Prompt SHA-256: `bb152360c77131b5d4b1b53bf33668a1b57d8a50499c979ebe361f4a52c5fdae`
Command: `.venv/bin/python -m bluerange.experiment001`
Runs: 24; infrastructure retries: 0.

## Autonomy results

| Autonomy | Runs | Mean score | Attack detection | Correct attack containment | Benign specificity | FP containment | Mean safety | Mean effectiveness | Tool calls | Model turns | Input tokens | Output tokens | Latency ms | Malformed | Policy attempts | Safe success | A1 recommendation quality |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| A1 | 8 | 49.875 | 0.000 | 0.000 | 1.000 | 0.000 | 27.625 | 11.250 | 5.875 | 9.625 | 31058.625 | 2265.125 | 250876.911 | 0.375 | 0.000 | 0.125 | 0.750 |
| A2 | 8 | 62.750 | 0.000 | 0.500 | 1.000 | 0.000 | 28.875 | 21.125 | 5.625 | 7.750 | 25739.000 | 1743.875 | 195311.297 | 0.250 | 0.000 | 0.375 | n/a |
| A3 | 8 | 45.750 | 0.000 | 0.000 | 1.000 | 0.000 | 27.000 | 8.750 | 5.250 | 7.250 | 23505.875 | 1627.625 | 183625.677 | 0.625 | 0.000 | 0.000 | n/a |

## Attack/benign and evidence-profile aggregates

### Kind

| Group | Runs | Mean score | Detection | Containment | Benign specificity | Safe success | Malformed | Tool calls | Turns | Input tokens | Output tokens | Latency ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| attack | 12 | 37.667 | 0.000 | 0.167 | n/a | 0.000 | 0.583 | 7.000 | 10.333 | 34359.000 | 2363.083 | 259105.127 |
| benign | 12 | 67.917 | n/a | n/a | 1.000 | 0.333 | 0.250 | 4.167 | 6.083 | 19176.667 | 1394.667 | 160770.796 |

### Evidence Profile

| Group | Runs | Mean score | Detection | Containment | Benign specificity | Safe success | Malformed | Tool calls | Turns | Input tokens | Output tokens | Latency ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| AMBIGUOUS | 12 | 54.417 | 0.000 | 0.333 | 1.000 | 0.167 | 0.167 | 4.667 | 7.500 | 24286.500 | 1726.750 | 189049.865 |
| COMPLETE | 12 | 51.167 | 0.000 | 0.000 | 1.000 | 0.167 | 0.667 | 6.500 | 8.917 | 29249.167 | 2031.000 | 230826.058 |


## Integrity and release gates

- PASS — `a1_response_actions_non_executable`
- PASS — `a2_only_configured_actions`
- PASS — `a3_bounded_by_scenario_permissions`
- PASS — `attack_and_benign_present`
- PASS — `audits_contain_no_credentials`
- PASS — `canonical_v01_byte_identical`
- PASS — `exact_real_model`
- PASS — `exactly_24_runs`
- PASS — `latency_is_provider_measured`
- PASS — `malformed_outputs_preserved`
- PASS — `no_fake_provider_results`
- PASS — `no_ground_truth_in_model_input`
- PASS — `no_scoring_information_in_model_input`
- PASS — `prompt_exact_and_frozen`
- PASS — `provider_errors_distinguishable`
- PASS — `token_accounting_plausible`

## Verification

- PASS — `ruff check .`: All checks passed
- PASS — `mypy bluerange`: no issues in 38 source files
- PASS — `pytest -q`: 85 passed
- PASS — `python -m tests.validation`: SHA-256 8e0758bca25658fe3b52c7ce8874a91102e161cce28dc459ac33f11c67c2ef64
- PASS — `independent aggregate recomputation`: exact match from 24 individual records
- PASS — `git diff --check`: no whitespace errors
- Changed-file inspection: completed for every modified, deleted, and untracked path; no unexpected experiment-scope changes found

## Decision gate assessment

Investigation grounding was 0.167, but evaluator-confirmed attack detection was 0.000. Structured-output reliability was 0.583 (0.417 malformed-run rate), and benign safe success was 0.333. Autonomy and leakage gates passed with no policy-violation attempts. Mean use was 5.583 tool calls and 8.208 model turns per run, 26767.833 input tokens, 1878.875 output tokens, and 209937.962 ms provider latency per run. Overall evaluator-grounded safe success was 0.167; the poor detection and structured-output results do not justify scaling.

Execution stopped at this gate. The 480-run experiment was not run.
