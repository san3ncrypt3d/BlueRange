# Architecture and trust boundaries

Public YAML and telemetry are validated into agent-safe models. The deterministic environment exposes observations and a fixed defensive tool set. The control plane validates typed arguments, enforces autonomy and scenario permissions, invokes environment methods, and appends immutable audit records. Model output is always untrusted and must validate as a supported typed call.

Evaluator-only `GroundTruth` has a private derivation/loader module. The runner holds it separately for scoring; it is never stored on the environment, observation, public instance/scenario, controller results, prompts, or agent context. Agent-facing results contain operational facts, not compromise labels, hidden metadata, or MITRE answers. This private-module boundary is not a same-process Python security boundary.

No agent receives shell, Python execution, filesystem, network, secrets, or arbitrary extension tools. BlueRange needs no secrets and does not read environment credential files. The current in-process architecture is a benchmark trust boundary, not a hostile-code sandbox: custom Python agents are trusted local code and should be isolated before evaluating untrusted submissions.

Scenario authors version schemas, keep observable noise realistic, avoid truth-like labels in public data, and validate with `bluerange validate-scenario PATH`.
