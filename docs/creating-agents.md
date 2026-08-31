# Creating defenders

Subclass `DefenderAgent`, give it a stable `id`, and implement `reset(context)` and `step(observation, tools)`. Reset all mutable state in `reset`. Only use observation fields and tool results; never load scenario files or evaluator truth. Return a `Decision` containing typed `ToolCall` values, evidence tied to observed steps, a typed `Disposition`, and an evidence-backed conclusion/narrative.

See `examples/custom_defender.py`. Model-backed agents should implement `ModelProvider.generate`; `LLMDefenderAgent` treats generated JSON as untrusted and fails closed on malformed or unsupported output. Registering additional CLI agent names is intentionally deferred until the plugin surface is stabilised.
