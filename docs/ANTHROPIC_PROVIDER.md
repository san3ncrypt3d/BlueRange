# Anthropic provider

Status: offline implementation complete. No Anthropic text-mode request, Claude benchmark, or formal experiment has run.

## Architecture and trust boundary

`AnthropicProvider` implements the provider-neutral `ModelProvider` boundary. BlueRange constructs defender-v2 and its public run context, then sends only public system/user messages and controlled-tool metadata through the official Anthropic Messages SDK. It never gives Claude provider-native tools, repository, filesystem, shell, evaluator truth, scoring state, or hidden metadata.

Delivered text remains untrusted and is preserved without semantic rewriting. The unchanged authoritative `ModelDecision`/`V2Decision` Pydantic validation, controlled-tool validation, autonomy enforcement, lifecycle, budgets, repair policy, evaluator, and scoring remain authoritative.

## Configuration

The project declares `anthropic>=0.68,<1`. Configure credentials only through the environment:

```sh
export BLUERANGE_MODEL_PROVIDER=anthropic
export BLUERANGE_MODEL=claude-sonnet-5
export ANTHROPIC_API_KEY='<secret managed outside BlueRange>'
```

The factory is lazy. Keys are not placed in messages, responses, audits, exceptions, forensics, or result JSON. Do not pass credentials on a command line.

## Qwen-comparable API mode

The Qwen-comparable Anthropic path uses ordinary Messages text generation. `client.messages.create` receives the configured model, output-token cap, timeout, system text, and messages. It receives **no `output_config` argument**—not even `output_config=None`—and BlueRange does not transmit `response_schema` to Anthropic constrained decoding.

The audit output mode is `ANTHROPIC_TEXT_JSON`. `response_schema` may remain on the internal `ProviderRequest` for protocol presentation, provenance, and authoritative validation, but the Anthropic adapter neither projects nor constrains it. The old Anthropic transport-schema projection and open-map key/value codec were removed.

Claude sees the authoritative decision schema through the same defender-v2 protocol presentation used for Qwen. The provider accepts exactly one non-empty text block and returns its text unchanged. Non-JSON, prose-wrapped JSON, schema-invalid JSON, missing or hallucinated argument keys, and other delivered model outputs remain model behaviour and enter the existing at-most-one schema-repair lifecycle. Invalid response envelopes remain provider failures.

This also resolves the generic `LLMDefenderAgent` defect where an Anthropic request could omit `response_schema`: text mode does not require or transmit a constrained schema.

## Comparability decision

Anthropic constrained structured output requires closed object schemas. BlueRange's authoritative action `arguments` maps are intentionally open because inferring valid argument names is measured behaviour. Closing the map by enumerating keys would disclose action-argument information that Qwen did not receive; converting the map to a provider-specific key/value structure would alter generation syntax. Both were rejected for the frozen Qwen-vs-Claude comparison.

The provider transports are not identical and must be reported:

- Qwen/Ollama: `JSON_OBJECT` transport assistance, seed 17, temperature 0.2, top_p 0.9.
- Claude/Anthropic: text generation without constrained JSON Schema; no equivalent seed; unsupported or non-equivalent sampling controls omitted; adaptive thinking/default effort behaviour as configured by the API defaults.

This is a provider-specific transport difference, not a provider-specific decision contract. Ollama's JSON-object syntactic assistance has no exact Anthropic equivalent in this design, so protocol adherence must be measured and disclosed rather than normalised away.

## Auditing and failures

Each Anthropic call audit records provider/model, run/turn correlation, safe request ID when available, HTTP status, timestamps, latency, generation status, token usage, `ANTHROPIC_TEXT_JSON`, repair eligibility, and bounded allowlisted diagnostics. Credential data, request/response headers, nested SDK data, and raw exception representations are excluded.

Three historical structured-schema connectivity requests failed before inference on Anthropic schema-subset incompatibilities. They are provider compatibility diagnostics, not experimental model results. No Claude benchmark inference or performance evidence resulted.

## Experiment entry-point requirement

`experiment002r._provider()` currently hardcodes Ollama. A future Experiment 003 prerequisite is a minimal explicit provider/model configuration that reuses the same frozen 24-cell machinery. That change is intentionally outside this provider-mode task.

## Next gate

A separately approved, single synthetic Anthropic text-connectivity request may validate authentication, model availability, request protocol, text response handling, authoritative validation, token accounting, and audit correlation. It must not include benchmark scenarios or count as experimental evidence. No such request is authorised by this document.
