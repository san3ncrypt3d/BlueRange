# LLM agent runtime

BlueRange v0.2 adds an iterative, provider-neutral defender without changing the frozen v0.1 runner or scoring. The lifecycle is `observe → decide → investigate/act → decide → finalize`. Legacy agents continue to use `reset()` and `step()` unchanged.

## Trust boundary and protocol

The model receives only the public scenario ID and description, observable telemetry, results of its own calls, requestable tool names, autonomy, and remaining independent budgets. Evaluator truth, attack/control labels, fingerprints, targets, scores, and private modules are excluded. Provider network access is only inference transport; it is not an agent tool. The agent has no shell, filesystem, Python, direct environment, evaluator, scoring API, or general network access.

Every response must validate as strict JSON. Unknown fields and action types are forbidden, strings and collections are bounded, and confidence is in `[0,1]`:

```json
{
  "assessment": {
    "attack_suspected": true,
    "confidence": 0.91,
    "subject_identity_id": "riley",
    "summary": "Multiple observable anomalies affect riley.",
    "evidence": ["New unmanaged device and unusual geography with no matching travel record"],
    "disposition": "COMPROMISE"
  },
  "next_action": {
    "type": "tool",
    "name": "get_active_sessions",
    "arguments": {"identity_id": "riley"}
  },
  "reason": "Confirm active sessions before proportional containment."
}
```

`next_action.type` is exactly `tool`, `recommendation`, or `final`; action prose is never parsed. On every turn the system message contains the exact `ModelDecision` JSON Schema, discriminator values, tool names and the external-authorization rule. Every tool descriptor carries the JSON Schema generated from its existing strict Pydantic argument model. Malformed output consumes a model turn, executes nothing, is audited, and terminates safely. Tool arguments are independently validated by `ToolController`.

Only `tool` requests can reach `ToolController`. A `recommendation` is recorded with a structured unsuccessful result stating `recommendation recorded; not executed`; it never invokes a tool or mutates the environment at any autonomy level. Response-action recommendations consume the response-attempt budget, while investigation recommendations consume the investigation-call budget. An A1 response recommendation is therefore a recorded proposal, not an unauthorized execution attempt.

## Budgets and audit

Model turns, investigation calls, and response attempts are independent bounded counters. Defaults are 12, 8, and 2, configurable using `--model-turns`, `--investigation-calls`, and `--response-actions`. The displayed model-turn count includes the turn about to be consumed; investigation and response counts are available future calls. Repeated requests consume the corresponding budget. Exhaustion is a denied, audited result and is not sent to `ToolController`.

Each interaction has an immutable model audit containing public input, requestable tools, remaining budgets, parsed request or safe malformed error, result/authorization outcome, assessment, usage, latency, and optional cost. Model audits live beside—not inside—the canonical v0.1 run record. The additive experiment envelope identifies itself with `schema_version: "2.0"` and `runtime_version: "0.2.0"`; nested benchmark records retain the frozen v0.1 core version for reproducibility.

## Providers

Configuration uses `BLUERANGE_MODEL_PROVIDER`, `BLUERANGE_MODEL`, `BLUERANGE_API_KEY`, `BLUERANGE_MODEL_BASE_URL`, and `BLUERANGE_MODEL_TIMEOUT`. OpenAI-compatible chat-completions endpoints receive JSON Schema structured-output metadata plus non-executing function descriptors. Ollama's local OpenAI-compatible endpoint defaults to `http://localhost:11434/v1/chat/completions` and uses the same adapter with its compatible `json_object` response mode; the complete protocol schema remains in the system message. BlueRange does not accept provider-native tool execution: it parses `ModelDecision` and routes tool requests through `ToolController`. Local endpoints and fake runs need no key. Keep credentials in the environment; keys and authorization headers are never prompts, bodies, audits, results, or errors. The HTTP timeout is the stricter of the provider configuration and each `ProviderRequest.timeout_seconds` value.

Experiment envelopes retain `kind` for evaluator aggregation. That field is never included in model input or model audits. Audit-visible run IDs are deterministic experiment-scoped opaque ordinals and contain no truth or control label.

Models and telemetry are untrusted. Prompt injection can still influence model judgment; strict schemas, external authorization, and budgets limit effects but do not make model output trustworthy. Because the evaluator and agent run in one Python process, Python is not a security sandbox; production isolation needs a process/container boundary. A local inference endpoint can retain prompts or expose them to other local users. Token counts and costs are provider-reported when available and may be missing or inaccurate.

Experiments always pair attack and benign-control instances for every seed, profile, and autonomy. Both use the same seed mapping, while the label stays outside model input. Aggregates use arithmetic mean, median, and population standard deviation. Attack detection is credit on the evaluator-scored `detection` component; correct attack containment is credit on evaluator-targeted `containment`; false-positive containment is a benign run where the evaluator withholds containment credit because a legitimate identity/session was contained; benign specificity is exactly `1 - false-positive containment rate`. Model disposition and generic action success do not define these metrics.
