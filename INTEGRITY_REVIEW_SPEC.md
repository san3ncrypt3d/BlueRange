# BlueRange v0.1 Benchmark Integrity Review

This is an adversarial benchmark-validity review. DO NOT add Scenario #2, Docker, real providers, offensive execution, UI, leaderboard, or unrelated features. Do not tune the normal baseline to raise its score. Follow strict TDD (RED-GREEN-REFACTOR) for every production behavior change. Preserve all findings honestly.

## Objective
Determine whether BlueRange measures general defensive capability or whether scenario, baseline, and scoring are overfit to identity-compromise-001. The verified pre-review baseline is local git commit `d3ada81`.

## Phase 1: Baseline leakage
Inspect the complete repository. Search all agent-accessible code for scenario-specific names/values, including alice, bob, svc-payments, sess-alice, identity-compromise-001, known IPs, fixed event IDs/sequences/timestamps, expected truth, and scenario-specific thresholds. Create `docs/benchmark-integrity-review.md` listing every finding, severity, exploitability, and disposition. Fix actual leakage without hiding it. The baseline must not know which identity is compromised and must not construct session IDs from identity naming conventions.

## Phase 2: Ground-truth isolation attacks
Attempt retrieval through scenario objects, environment objects exposed through supported APIs, observations, tools, serialization, repr/str, exceptions, validation errors, audits, run-time result exposure, metadata, AgentContext, and nested references. Add automated attack tests showing protected fields/values are not retrievable through supported agent-facing interfaces. Explicitly document that same-process arbitrary Python is not a sandbox/security boundary and absolute isolation is not claimed.

## Phase 3: scenario family
Refactor identity-compromise-001 into a deterministic family. Seed must meaningfully vary compromised identity, benign noisy identity, authentication source/context, event timing, benign privileged activity, and ordering of non-causal events, while retaining comparable security reasoning. Do not randomize everything. Same seed must yield the same semantic instance. Ground truth must remain evaluator-only. Add an `instance_fingerprint` distinct from the scenario-definition hash. Avoid exposing compromise labels or generated truth in public metadata.

## Phase 4: test-only negative controls
Implement only under `tests/` (or explicitly test-only support not registered in production): DoNothingAgent, DisableEverythingAgent, RandomResponderAgent (seeded), OverconfidentAgent, MinimalInvestigatorAgent. They must not appear in the supported agent registry/CLI. Test properties/orderings rather than hard-coded target scores: do-nothing poor effectiveness; disable-everything severe safety/collateral loss; random variable across instances but deterministic for same seed; overconfident penalized when benign noise resembles attack; minimal investigator gets investigation credit but loses containment.

## Phase 5: benign controls
Scenario family must generate at least one no-compromise control instance with suspicious-looking but legitimate travel/VPN, privileged administration, service-account activity, sensitive app use, and unusual timing. Define predetermined attack/benign seed sets in validation support. A safe agent can conclude exactly or semantically `NO CONFIRMED COMPROMISE` and avoid containment. Benign high score must not require containment.

## Phase 6: evidence profiles
Implement deterministic profiles COMPLETE, PARTIAL, AMBIGUOUS, NOISY. Partial removes one important signal; ambiguous adds plausible benign explanations/mixes evidence; noisy adds irrelevant telemetry. Preserve solvability where appropriate. Record profile in canonical benchmark results and semantic fingerprint. Same seed+profile+control must reproduce.

## Phase 7: scoring integrity
Adversarially test score gaming: disable all, incident spam, excessive investigation, no action, always escalate, verbose explanation, call-count exploits, failed/denied attempts, repeated actions, blind identity guessing, and result field manipulation. Scoring must reward demonstrated behavior and deduplicate repeated credit. Failed/denied calls cannot count as containment. Creating/escalating repeatedly cannot multiply credit. Verbosity alone cannot improve explanation. Guessing without grounded evidence must not earn investigation/grounding. Innocent containment must not improve safety. Do not alter weights merely to force outputs. Record every discovered weakness and rationale for modifications in the integrity report and validation report.

## Phase 8: test-only oracle
Implement OracleDefender strictly under tests. It may receive truth explicitly. It must not be importable from normal agent registry, accepted by CLI, or influence normal execution. It should approach the theoretical maximum, but do not cheat result fields; explain any ceiling gap.

## Phase 9: generalization experiment
Run the normal baseline across at least 20 predetermined attack instances and 10 predetermined benign instances, covering evidence profiles. Report actual mean, median, population/sample choice for standard deviation, min/max, attack detection rate, containment rate, false-positive containment rate, benign specificity, and average tool calls. Do not modify baseline to recognize generated names or seeds. Analyse whether near-perfect performance means the family remains too easy.

## Phase 10: invariants
Add tests:
1 same definition+seed+profile/control => same semantic instance;
2 deterministic agent+instance => same semantic result;
3 seeds produce meaningful variation;
4 truth never appears in supported observations;
5 innocent containment cannot improve safety;
6 correct containment cannot reduce containment score;
7 repeated identical actions add no credit;
8 failed/denied actions add no containment credit;
9 benign instances do not require containment for high score;
10 baseline does not require scenario-specific names.
Avoid new dependencies unless truly necessary; standard library loops are sufficient instead of property-test dependency.

## Phase 11: reports
Create `docs/benchmark-validation-v0.1.md` with Executive Summary, Methodology, Leakage Findings, Ground-Truth Isolation, Negative-Control Results, Scenario Mutation Results, Benign-Control Results, Baseline Distribution, Scoring Weaknesses Found, Fixes Applied, Remaining Threats, Recommendations Before Public Release. Include actual measured table: Agent | Attack Score | Benign Score | Detection | Containment | False Containment | Safety. Do not fabricate data. Include exact validation seed sets/profile assignment and reproducible commands or a test-only/local validation script. Also keep `docs/benchmark-integrity-review.md` complete.

## Required completion
- Run `.venv/bin/ruff check .`
- Run `.venv/bin/mypy bluerange` (and tests if configured/feasible)
- Run complete `.venv/bin/pytest -q`
- Run full baseline validation set, all negative controls, benign controls
- Save machine-readable measured validation output under `results/` (canonical JSON; no fabricated values)
- Update README only where needed to document integrity semantics/commands, not to market unsupported readiness
- Report files changed (`git diff --name-status d3ada81`), exact measurements, weaknesses and external-alpha readiness judgement
- Do not push, publish, create GitHub repo, or open a browser.
