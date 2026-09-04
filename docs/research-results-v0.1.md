# BlueRange v0.1 Research Results

This document records frozen historical results. The result artefacts are not regenerated or modified by the release programme.

## Experiments

| Treatment | Experiment identity | Provider | Cells |
|---|---|---|---:|
| Qwen 002R | `experiment-002r-new-attempt` | Qwen/local provider record | 24 |
| Sonnet 003 | `experiment-003-sonnet-reexecution-013` | Anthropic, `claude-sonnet-5` | 24 |

Sonnet's corrected 16384-token scientific identity is `bf4d6b09304de5553bb845ba935d4f71cc6deab26626f73d4a3dab52523261ed`. The historical `7818bda0...` identity belongs to the earlier 8192-token treatment and is not used here.

## Matrix and method

Both experiments use the frozen 24-cell Scenario 1 matrix aligned by autonomy (A1/A2/A3), evidence profile (COMPLETE/AMBIGUOUS), seed (101/202), and attack/benign kind. The evaluator scores detection, investigation accuracy, reconstruction, containment, speed, safety, efficiency, explainability, finalisation, and grounding.

Sonnet formal execution used a predeclared bounded provider-failure retry policy: at most three physical provider attempts per logical cell, with retries only before usable visible output reached authoritative V2 validation. Model-behaviour outcomes were never retried and retries were not counted as additional cells.

## Primary metrics

| Metric | Qwen 002R | Sonnet 003 |
|---|---:|---:|
| Attack detection | 33.33% | 100.00% |
| Attack recognition | 16.67% | 58.33% |
| Attack safe success | 33.33% | 100.00% |
| Benign specificity | 100.00% | 100.00% |
| Correct containment | 58.33% | 66.67% |
| False-positive containment | 0.00% | 0.00% |
| Finalisation | 62.50% | 100.00% |
| Grounded finalisation | 62.50% | 100.00% |
| Post-repair schema validity | 78.05% | 100.00% |
| Repair success | 35.71% | 100.00% |

Sonnet A1/A2/A3 mean scores were 87.5, 90.0, and 90.0 respectively. Detection was 100% for each autonomy level; effective containment was 50% in each autonomy group; benign specificity was 100% in each group.

## Findings and limitations

In this Scenario 1 matrix, Sonnet produced more complete and reliable canonical protocol outcomes than Qwen 002R, particularly for final detection, grounding, finalisation, and repair. The data does not establish universal model superiority, perfect recognition, or perfect containment. A1 authority restrictions visibly limited execution of recommended containment. A2 and A3 had equal aggregate containment and score outcomes despite qualitative differences in investigation and action sequences. Scenario 2 is required to test the risk side of increased autonomy.
