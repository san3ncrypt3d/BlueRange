# Experiment 002R smoke report

Status: **stopped at the mandatory two-run canary gate**. The 24-run formal experiment was not executed.

The exact Experiment 002 failure was an Ollama 0.31.1 HTTP 400 before generation: `Failed to initialize samplers: failed to parse grammar`. The complete strict defender-v2 schema exceeded the provider grammar-complexity limit. This is classified as `PROVIDER_FAILURE`.

002R changed only the Ollama output constraint to `JSON_OBJECT` while retaining full unchanged defender-v2 validation, evidence validation, tool argument validation, lifecycle rules, external authorization, budgets, and one schema-only repair maximum. Provider attempts now receive complete secret-safe audits with real failure latency.

The single preflight passed with HTTP 200, generation begun, 1,031 tokens, and 27,029.899 ms latency. The A1 attack/benign canary made four successful provider calls totaling 8,024 tokens and 83,140.199 ms. Both initial outputs were syntactically valid JSON but failed the v2 schema; both single repairs also failed. Provider success and JSON syntax validity were 100%; first-pass and post-repair schema validity, repair success, finalization, and grounded finalization were 0%.

Defender-quality metrics are not reported because a two-run canary is not a quality estimate and the formal records do not exist. Ruff, strict mypy, all 104 tests, canonical regeneration, frozen hashes, audit secret scan, and `git diff --check` passed.

Recommendation: inspect the generic schema-only repair mechanics and model adherence without using benchmark outcomes, then request approval before any new real calls. Do not infer defender quality from this canary.
