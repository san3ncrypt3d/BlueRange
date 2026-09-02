# Experiment 002 smoke report

Decision classification: **OUTCOME C**.

The provider-success integrity gate failed: the configured OpenAI-compatible endpoint returned no model response for any of the 24 original requests. The protocol and cyber metrics below must therefore be read as failed-run measurements, not model-quality estimates.

Prompt SHA-256: `1edcb1b12b0d3ef1463c1330015fb127409c76e311323879545297826dfa9fe4`
Command: `.venv/bin/python -m bluerange.experiment002`
Runs: 24; infrastructure retries: 0.

## Measurements

- runs: `24`
- protocol_validity_rate: `0.0`
- first_pass_protocol_validity_rate: `0.0`
- post_repair_protocol_validity_rate: `0.0`
- provider_error_rate: `1.0`
- finalization_rate: `0.0`
- grounded_finalization_rate: `0.0`
- attack_recognition_rate: `0.0`
- attack_detection_rate: `0.0`
- correct_containment_rate: `0.0`
- benign_specificity: `1.0`
- false_positive_containment: `0.0`
- safe_success_rate: `0.0`
- mean_score: `42.0`
- mean_safety: `27.0`
- mean_effectiveness: `5.0`
- model_turns_per_run: `0.0`
- tool_calls_per_run: `0.0`
- unique_investigation_calls_per_run: `0.0`
- duplicate_calls_per_run: `0.0`
- tokens_per_run: `0.0`
- latency_per_run_ms: `0.0`
- malformed_rate: `0.0`

## Integrity gates

- PASS — `exactly_24_runs`
- PASS — `paired_attack_benign`
- PASS — `fixed_controls`
- PASS — `model_identity`
- FAIL — `provider_requests_succeeded`
- PASS — `no_private_input`
- PASS — `at_most_one_repair`
- PASS — `a1_no_response_execution`
- PASS — `a2_no_identity_disable`
- PASS — `canonical_v01`
- PASS — `v1_result_frozen`
- PASS — `v1_prompt_frozen`

## Limitations

All 24 first provider requests failed before a model response was returned. Consequently there were zero response tokens, model turns, and response latency records; this is a provider/runtime integration failure, not evidence of model reasoning performance. The original 24 records were preserved and were not retried or replaced. This matched smoke test has only 24 runs and supports no claim of statistical significance. Intermediate recognition is diagnostic only and receives no scoring credit.

Execution stopped after exactly 24 runs. No scale-up was performed.

## Verification

- PASS — `.venv/bin/ruff check .`
- PASS — `.venv/bin/mypy bluerange`
- PASS — `.venv/bin/pytest -q` (90 tests)
- PASS — `.venv/bin/python -m tests.validation --output /tmp/bluerange-exp002-final-canonical.json` and SHA-256 check (`8e0758bca25658fe3b52c7ce8874a91102e161cce28dc459ac33f11c67c2ef64`)
- PASS — Experiment 001 result and defender-v1 SHA-256 checks
- PASS — independent 24-record aggregate, pairing, uniqueness, integrity and outcome recomputation with `jq -e`
- PASS — `git diff --check`
- PASS — changed-file inspection

Files added for Experiment 002: `bluerange/experiment002.py`, `prompts/defender-v2.txt`, `tests/unit/test_experiment002.py`, `docs/experiment-001-failure-analysis.md`, `docs/experiment-002-smoke.md`, `docs/experiment-001-vs-002.md`, and `results/experiment-002-smoke.json`. Additive schema-selection changes were made in `bluerange/models/schemas.py` and `bluerange/models/gateway.py`. Pre-existing unrelated workspace changes were preserved.
