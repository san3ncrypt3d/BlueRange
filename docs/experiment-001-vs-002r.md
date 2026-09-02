# Experiment 001 vs 002R

No model-quality comparison is valid. Experiment 002R stopped at its mandatory canary gate, before the 24 matched formal records were executed.

The compatibility change fixed the systematic provider integration failure: the real preflight and all four canary provider calls generated successfully under `JSON_OBJECT`. However, both canary records failed full defender-v2 validation even after their one permitted schema-only repair. This is a meaningful canary protocol-adherence failure, not evidence about attack detection, containment, benign specificity, or safe success.

Experiment 001 remains frozen. No significance claim, scale-up, or 480-run experiment was performed.
