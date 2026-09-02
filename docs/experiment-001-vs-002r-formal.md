# Experiment 001 vs Formal Experiment 002R

No valid performance comparison is available.

Experiment 001 completed 24 runs. Formal Experiment 002R aborted during BlueRange result construction after an internal invalid-target sentinel failed `ActionRecord` validation. Although Ollama recorded 15 successful provider calls, no canonical formal run records were checkpointed before process termination.

Accordingly, malformed-rate, protocol-validity, finalisation, recognition, detection, containment, benign-safety, score, tool, token and latency comparisons are all **not available**. Treating missing formal records as zero performance would conflate a benchmark-runtime failure with defender behaviour.

The defender-v2 prompt, model, scenario, scoring, autonomy rules and experiment parameters remained frozen. A comparison must wait for a separately identified rerun after runtime serialisation and per-run checkpointing are corrected and independently verified.

**Current recommendation: RUNTIME_REPAIR_REQUIRED.**
