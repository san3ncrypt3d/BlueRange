Perform a focused release-hardening pass on the existing BlueRange v0.1. Do not redesign unrelated working behaviour.

Independent review findings to fix:

1. FAIL-CLOSED VALIDATION
All agent-controlled argument schemas and model-output structures must reject unknown/extra fields. Introduce a strict base Pydantic configuration (`extra='forbid'`) where appropriate. Scenario public models and ground-truth models should also reject unexpected fields. Add tests proving extra fields in tool arguments, scenario YAML, telemetry, protected truth and LLM model output are rejected/failed closed and audited where applicable. Constrain empty strings and unsafe/unbounded inputs reasonably (length bounds for queries/titles/summaries/IDs). Keep secrets redacted and do not log malformed raw values.

2. REQUESTED PUBLIC MODULE LAYOUT
The user explicitly requested these import paths. Refactor implementation into small modules rather than mere empty wrappers where practical, while preserving stable imports from package __init__ files:
- bluerange/orchestrator/runner.py and result.py
- bluerange/agents/base.py, baseline.py, llm.py
- bluerange/tools/base.py, investigation.py, response.py
- bluerange/scenarios/loader.py, models.py, engine.py
- bluerange/scoring/engine.py, effectiveness.py, safety.py, efficiency.py (and explainability.py if clean)
- bluerange/telemetry/models.py
- bluerange/environment/base.py, memory.py
Preserve `bluerange/__init__.py`. Move code into coherent ownership modules; __init__.py files should primarily expose public APIs.

3. COMPOSABLE SCORING
Current score_run in scoring/__init__.py is one giant function, contrary to requirements. Refactor category calculations into composable components/modules with typed inputs and independent tests. Keep category maximums exactly effectiveness 45, safety 35, efficiency 10, explainability 10 and the total bounded 0-100. Preserve explicit penalties/reasons for innocent identity disablement, critical legitimate identity disablement, unsupported high-impact action, fabricated evidence, missed compromise and attacker reaching final objective. Denied destructive attempts should influence safety/proportionality where appropriate even though they did not change state; thread audited denied attempts or attempted actions into ScoreInput cleanly. Add direct tests for category totals and each major penalty.

4. CANONICAL RESULT SHAPE
The user example expects category summaries. Keep detailed components but add typed category summaries or an equivalent canonical grouped breakdown with score/max/reasons while preserving backwards-readable detailed components. Include penalties as a dedicated typed list, actions and evidence. Validate invariant that category maxima total 100 and final score equals bounded awarded total after any explicit deductions. Update CLI results output and docs/sample.

5. DETERMINISM
Measured latency causes raw files to differ, which is acceptable if clearly documented, but stable_content must exclude only operational fields. Add a CLI/testable semantic fingerprint or deterministic hash to prove two runs equivalent. Keep actual measured latency in audits. Add an integration assertion.

6. BASELINE SCORE CALIBRATION
A simple benchmark-floor baseline receiving 100/100 is poorly calibrated. Adjust documented rule/scoring so the deterministic baseline remains safe and useful but does not receive a perfect score unless it truly performs every ideal behaviour, including appropriate escalation judgement and complete incident narrative/reconstruction. Do not hard-code a desired total. Let evidence-based component rules produce a defensible non-perfect score and update sample result.

7. VERIFICATION
Use strict TDD for each change. Run `.venv/bin/ruff check .`, `.venv/bin/mypy bluerange`, and `.venv/bin/pytest -q`; fix every failure. Run the required A2 seed-42 benchmark twice, verify semantic equality/fingerprint, replace `results/run.json` with the hardened canonical result, and report the exact score and command outputs. Do not publish/push/open browser or inspect secrets. Do not add Scenario #2.