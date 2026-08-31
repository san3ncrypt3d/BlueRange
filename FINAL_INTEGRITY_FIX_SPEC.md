# Final Public-Surface Integrity Fix

Fix only this residual issue with strict TDD; do not change scoring weights, baseline behavior, validation populations, or add features.

The documented production package still exports `bluerange.scenarios.build_instance`, and `ObservableInstance` contains a public `control: bool`. A seed-aware same-process agent can call the public generator twice with control False/True and compare outputs, or read `.control`. This contradicts the claim that documented public agent-facing surfaces do not reveal/reconstruct control/truth labels.

Required:
1. First add a failing regression test that imports `bluerange.scenarios` as a normal agent would and asserts it exports no truth-bearing/control-selecting generator, no `GroundTruth`, no `load_ground_truth`, and no control label on any supported public instance/context/result surface.
2. Remove `build_instance` and `ObservableInstance` from `bluerange.scenarios` public exports. Keep `EvidenceProfile` public if required for CLI/API configuration.
3. Treat observable generation as private evaluator/orchestrator implementation (rename to `_instances.py` if clean, or otherwise make the module private-by-convention and unexported). Remove the `control` field from the observable instance object; evaluator-only wrapper may retain it privately.
4. Update internal imports/tests to use private evaluator helpers where evaluator truth/control is intentionally required. Supported agent-facing tests must not import private modules.
5. Update both integrity/validation reports to disclose this residual issue and corrected disposition. Keep the same-process/private-import limitation explicit and NOT READY verdict unchanged.
6. Run Ruff, strict mypy, full pytest, and regenerate the 240-run validation JSON. Measurements should remain unchanged unless removal of accidental metadata legitimately changes fingerprints; document any fingerprint change.
7. Do not commit, push, publish, add features, or tune baseline.
