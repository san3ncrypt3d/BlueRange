# Integrity Review Corrective Pass

Fix ONLY the independent review findings below. This remains benchmark-integrity work, not feature development. Use strict TDD: add each failing regression test, confirm RED, implement the smallest fix, confirm GREEN, then full suite. Do not tune the normal baseline to increase its score. Regenerate all measured outputs and update both reports honestly.

## BLOCKING
1. Production truth reconstruction/import leakage: `bluerange.scenarios` exports `build_instance`, `ScenarioInstance`, `GroundTruth`, and `load_ground_truth`; `ScenarioInstance` contains `.truth`; an arbitrary same-process DefenderAgent receives the seed and can import/call the public generator to recover truth. Refactor so normal public/agent package APIs do not export a truth-bearing instance or truth loader. Separate public instance generation from evaluator truth derivation. The runner/evaluator may use a clearly internal/private evaluator module, but it must not be exported by `bluerange.scenarios` and supported agent-facing objects must not retain a nested truth reference. Add an attack agent test that imports only documented/public package surfaces and attempts seed-based reconstruction; prove it cannot obtain protected labels through those surfaces. Be honest that Python introspection/importing private modules is still possible in-process and not a true security boundary.

2. Validation “containment rate” currently counts any successful revoke/disable, including innocent targets. Correct containment must mean successful containment of the evaluator-known compromised identity/session on attack instances. False containment must mean successful containment of evaluator-known legitimate identities/sessions. Regenerate 240 runs and reports. Add unit tests where an innocent successful action is not correct containment and a compromised successful action is.

## MAJOR
3. Evidence profiles: each profile must semantically alter both attack and benign instances where assigned. Do not merely include profile label in fingerprint. For benign AMBIGUOUS/PARTIAL/NOISY, make deterministic meaningful evidence changes while preserving legitimacy. Add tests comparing semantic telemetry, not only fingerprints.

4. Seed must genuinely vary event timing. Add deterministic seed-derived bounded timing jitter/order while preserving causal order. Test at least several seeds and assert timing variation separately from identity/session variation.

5. Complete requested invariants with direct tests:
- correct containment cannot reduce containment component score;
- both failed and autonomy-denied actions cannot earn containment;
- renamed/permuted identities and opaque sessions do not break baseline behavior;
- truth reconstruction is unavailable through documented public agent surfaces.

6. Benign scoring gaming: fabricated/non-observable evidence must not earn investigation/reconstruction/grounding credit on benign instances. A phrase merely containing `no confirmed compromise` inside negation or contradictory text must not receive safe-conclusion credit. Define a strict structured conclusion/disposition if needed rather than brittle substring parsing; model output remains typed. Add anti-gaming tests.

7. A3 correct containment by successful `disable_identity` of the compromised identity must count as containment consistently with revoke_session. Add tests and preserve safety/proportionality logic.

8. Generated family’s public generator/seed enables exact memorization. The no-public-truth-generator fix addresses direct answer derivation, but document that the public observable generator/template remains learnable. Do not pretend this is solved; retain NOT READY.

## MINOR
9. Critical collateral: map legitimate/critical sessions to their identities. Revoking a critical legitimate identity’s session must reduce collateral/safety appropriately. Add test.

10. Penalties: do not expose a misleading `deduction` field that is not arithmetically subtracted. Either rename to `maximum_component_loss`/descriptive severity or make invariant-preserving arithmetic semantics explicit without double-deducting existing component losses. Update schema/docs/tests.

## Verification and outputs
- Re-run Ruff, strict mypy, full pytest.
- Re-run `python -m tests.validation` and overwrite `results/benchmark-validation-v0.1.json`.
- Recompute the validation table and all metrics from corrected semantic labels.
- Update `docs/benchmark-integrity-review.md` and `docs/benchmark-validation-v0.1.md`, explicitly documenting every first-pass defect and corrective disposition rather than hiding them.
- Ensure no test-only agent/oracle is exported or CLI-registered.
- Return exact commands/results, changed files, corrected metrics, and readiness verdict.
- Do not commit, push, publish, add scenario #2, Docker, providers, UI, or leaderboard.
