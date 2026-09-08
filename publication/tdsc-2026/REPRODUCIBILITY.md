# Reproducibility

## Fully reproducible from this public artifact

- Inspection of the released aggregate data.
- Deterministic regeneration of aggregate table views.
- Verification of the authority, condition, profile and denominator structure.
- Reproduction of the published aggregate counts from `data/canonical_results.json`.

The public BlueRange repository contains the benchmark/software material at the cited commit.

## Provider-dependent

Qwen execution requires a compatible documented model/runtime artifact. Sonnet execution requires compatible Anthropic access. LLM outputs, timings and provider responses may not be byte-identical across reruns. This release makes no claim of exact LLM-output reproducibility.

No model or experiment was run to create this release.
