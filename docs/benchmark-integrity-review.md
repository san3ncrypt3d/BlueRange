# BlueRange v0.1 Benchmark Integrity Review

Review baseline: `d3ada81`. Scope: repository benchmark integrity only. Verdict: **NOT READY** for unqualified external alpha.

## Corrective review dispositions

| # | Independent finding | Corrective disposition |
|---:|---|---|
| 1 | Public truth reconstruction/import leakage | Fixed at the supported API boundary after a residual defect was found in the first corrective disposition. Although direct truth objects had been removed, `bluerange.scenarios.build_instance` still selected attack/control generation and its exported `ObservableInstance.control` disclosed the label. The generator and observable wrapper are now private in `bluerange.scenarios._instances`, the observable wrapper has no control field, and `bluerange.scenarios` exports neither. It also exports no `GroundTruth` or `load_ground_truth`. This is API separation, not security isolation: arbitrary same-process Python can still import private modules, inspect process state, or read repository files. |
| 2 | Containment validation counted any successful destructive action | Fixed. Attack containment is derived from the evaluator-scored compromised identity/session component; benign false containment is derived from evaluator-scored legitimate targets. Innocent successful actions are never correct containment. The 240 runs were regenerated. |
| 3 | Benign evidence profiles changed only fingerprints | Fixed. PARTIAL removes a semantic event on both sets, AMBIGUOUS adds deterministic legitimate explanatory context on benign instances and incomplete context on attacks, and NOISY adds deterministic unrelated telemetry on both sets. Tests compare telemetry content. |
| 4 | Seed did not vary event timing | Fixed with deterministic bounded sub-second jitter plus existing seeded within-step ordering. The jitter cannot cross the authored one-second causal spacing. Tests compare timing signatures independently of names/session values. |
| 5 | Requested invariants lacked direct tests | Fixed. Direct tests cover monotonic correct containment, failed and autonomy-denied actions, renamed/permuted identities, opaque sessions, and public-surface reconstruction failure. |
| 6 | Benign fabricated evidence and conclusion substring gaming | Fixed. Benign investigation/reconstruction requires exact observable facts. A typed `Disposition` drives safe-conclusion credit, so contradictory prose containing a magic phrase earns none. Narrative text remains descriptive, not authoritative. |
| 7 | A3 compromised-identity disablement did not count | Fixed. A successful `disable_identity` against the evaluator-known compromised identity is correct containment, consistently with compromised-session revocation; innocent and critical-target safety logic remains independent. |
| 8 | Generated family is learnable | **Unresolved by design.** The generator is no longer public, but its private implementation, event vocabulary, and single causal template remain available to arbitrary same-process code or repository readers and permit semantic memorization. This alone retains NOT READY. |
| 9 | Critical legitimate sessions were not mapped to identities | Fixed. Evaluator truth carries `critical_sessions`; revoking one reduces collateral/safety just like disabling its critical legitimate identity. |
| 10 | `deduction` implied arithmetic subtraction | Fixed. Penalty records now expose `maximum_component_loss`; category component losses remain the only arithmetic effect, avoiding double subtraction. |

## Earlier first-pass findings retained

The first pass also fixed identity-derived session construction, inert scenario seeds, a leaked public `control` result field, fabricated attack evidence credit, legitimate-session safety omissions, unsupported escalation/narrative credit, and multiplication through repeated/failed calls. Static v1.0 fixtures remain repository-readable historical inputs. The normal baseline's fixed event-type threshold was deliberately not tuned after measurement.

Test-only DoNothing, DisableEverything, RandomResponder, Overconfident, MinimalInvestigator, SafeControl, and OracleDefender implementations remain under `tests/support`; none is exported from `bluerange.agents` or registered by the CLI.

## Boundary and residual threats

Automated probes cover public scenarios, environments, observations, tools, audit/context/result models, serialization, exceptions, and nested references. Protected labels are unavailable through documented public agent surfaces. However, same-process execution is not a sandbox: private imports, Python introspection, filesystem reads, and process modification remain possible. A credible external run must isolate agent execution from evaluator code, state, and repository files.

The private observable generator/template is still exactly reproducible by same-process code that imports private modules or reads the repository. There is one narrow causal family, vocabulary is stable, and benign controls remain structurally uniform. No claim of held-out generalization or adversarial secrecy is warranted.

## Readiness disposition

**NOT READY.** Corrected scoring and API boundaries support a restricted research preview, but external alpha requires separately isolated agent execution, held-out private generation, independently authored families, and broader benign causal diversity. The measured normal baseline still has 100% false-positive containment and 0% benign specificity.
