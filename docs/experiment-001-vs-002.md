# Experiment 001 vs 002

Classification: **OUTCOME C**.

Experiment 002 encountered a 100% provider-error rate before any model response was returned. Its zero protocol/cyber values are failed-run measurements and do not support a model-performance inference. They do support the Outcome C instruction to investigate runtime/provider integration.

| Metric | V1 | V2 |
|---|---:|---:|
| malformed_rate | 0.416667 | 0 |
| first_pass_protocol_validity_rate | 0.583333 | 0 |
| post_repair_protocol_validity_rate | 0.583333 | 0 |
| finalization_rate | 0.333333 | 0 |
| grounded_finalization_rate | 0.166667 | 0 |
| attack_recognition_rate | 1 | 0 |
| attack_detection_rate | 0 | 0 |
| correct_containment_rate | 0.166667 | 0 |
| safe_success_rate | 0.166667 | 0 |
| benign_specificity | 1 | 1 |
| false_positive_containment | 0 | 0 |
| mean_score | 52.7917 | 42 |
| mean_safety | 27.8333 | 27 |
| mean_effectiveness | 13.7083 | 5 |
| model_turns_per_run | 8.20833 | 0 |
| tool_calls_per_run | 5.58333 | 0 |
| duplicate_calls_per_run | 0 | 0 |
| tokens_per_run | 28646.7 | 0 |
| latency_per_run_ms | 209938 | 0 |

Attack recognition is diagnostic only; final attack detection remains evaluator-scored. No statistical significance is claimed from 24 matched runs.
