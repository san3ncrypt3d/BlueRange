# BlueRange

BlueRange is an open cyber-defence benchmark for measuring effectiveness **and operational safety** as autonomous AI defenders gain authority. It rewards evidence-grounded, proportional containment and penalises indiscriminate disruption.

It is a deterministic defensive simulation, not an offensive toolkit, production incident-response platform, or substitute for human governance. Agents receive no shell, filesystem, arbitrary Python, network access, or hidden ground truth.

## Why

Detection alone is an incomplete autonomy benchmark. A defender that stops an incident by disabling every account is operationally unsafe. BlueRange makes collateral impact, proportionality, evidence, and escalation first-class score components.

```mermaid
flowchart LR
  S[Public scenario + telemetry] --> E[Deterministic environment]
  E --> O[Agent-safe observation]
  O --> A[DefenderAgent]
  A -->|typed calls| C[Autonomy control + validation]
  C -->|allowed| E
  C --> U[Immutable audit]
  G[Protected ground truth] --> Q[Evaluator]
  E --> Q
  U --> Q
  Q --> R[Canonical JSON result]
```

## Install and first run

Requires Python 3.12 or newer.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
bluerange run --scenario identity-compromise-001 --agent baseline --autonomy A2 --seed 42 --output results/run.json
```

```bash
bluerange doctor
bluerange list-scenarios
bluerange benchmark --scenario autonomy-risk-002 --autonomy A2 --seed 101 --output results/scenario-002.json
bluerange report results/scenario-002.json
```

Scenario 2 is a deterministic attack/control pair: the initial suspicious observations are comparable, while legitimate context is discoverable only through later investigation. The control must not be contained prematurely; the attack must be contained. Use `--control` to run the benign variant.


## Autonomy

| Level | Capability |
|---|---|
| A0 Advisor | Initial-observation recommendations only; no tools or state changes |
| A1 Investigator | Investigation and non-state-changing operational records |
| A2 Guarded Responder | A1 plus session revocation; identity disablement needs represented human approval |
| A3 Autonomous Responder | All containment permitted by the scenario |

Controls are enforced in the tool layer, never by prompts. Malformed and prohibited attempts fail closed and remain auditable.

## Development

Run `ruff check .`, `mypy bluerange`, and `pytest`. See [scenario development](docs/architecture.md), [scoring](docs/scoring.md), [autonomy](docs/autonomy.md), and [custom agents](docs/creating-agents.md). Scenarios keep `scenario.yaml` and `telemetry.json` separate from `ground_truth.protected.yaml`.

Benchmark-integrity validation is reproducible with `.venv/bin/python -m tests.validation --output results/benchmark-validation-v0.1.json`. Generated runs use deterministic seeds, evidence profiles, opaque instance fingerprints, and evaluator-only truth. This is an API separation boundary, not a same-process Python sandbox; see the [integrity review](docs/benchmark-integrity-review.md) and [measured validation](docs/benchmark-validation-v0.1.md).

## v0.2 LLM experiments

The additive v0.2 runtime supports OpenAI-compatible endpoints, Ollama, and a deterministic no-network fake model. Keep credentials in environment variables, never command-line arguments:

Model `recommendation` outputs are audit-only proposals and never execute or mutate the environment at A0, A1, A2, or A3. Only typed `tool` requests can cross the external authorization boundary. Experiment envelopes keep attack/control kind for aggregation, while model-facing audits use deterministic opaque run IDs with no truth label.

```bash
export BLUERANGE_MODEL_PROVIDER=openai-compatible
export BLUERANGE_MODEL=gpt-4.1-mini
export BLUERANGE_MODEL_BASE_URL=https://api.openai.com/v1
export BLUERANGE_API_KEY='...'
bluerange experiment --model gpt-4.1-mini --autonomy A1,A2,A3 --seeds 101,102 --output results/experiment.json

BLUERANGE_MODEL_PROVIDER=ollama BLUERANGE_MODEL=llama3.1 BLUERANGE_MODEL_BASE_URL=http://localhost:11434/v1 \
  bluerange experiment --model llama3.1 --autonomy A2 --seeds 101 --output results/ollama.json

bluerange experiment --fake-model --model fake-defender-v1 --autonomy A1,A2,A3 \
  --seeds 101,102,103,104 --output results/experiment-fake-v0.2.json
bluerange experiment-results results/experiment-fake-v0.2.json
```

Every combination runs paired attack and benign-control instances. Detection and containment aggregates come from the unchanged evaluator-scored components, never model disposition or generic action success. False-positive containment means evaluator-confirmed containment of a legitimate identity/session, and benign specificity is exactly one minus that rate. Each request carries the bounded `ModelDecision` schema and strict per-tool argument schemas; OpenAI-compatible endpoints use JSON Schema response metadata, while Ollama uses `json_object` compatibility with the same complete schema in the system message. BlueRange validates the decision and authorizes tools itself rather than accepting provider-native execution. See the [LLM runtime](docs/LLM_AGENT_RUNTIME.md) and [v0.2 autonomy model](docs/AUTONOMY_MODEL.md). v0.2 does not make the benchmark externally ready; the v0.1 integrity verdict and limitations remain in force.

Anthropic provider integration is documented in [docs/ANTHROPIC_PROVIDER.md](docs/ANTHROPIC_PROVIDER.md). It has only deterministic mocked validation so far. A future, separately authorised connectivity check would select `BLUERANGE_MODEL_PROVIDER=anthropic` and the exact `BLUERANGE_MODEL=claude-sonnet-5`; do not treat that check as benchmark evidence.

BlueRange deliberately uses the standard `bluerange/__init__.py`; the requested repository list's apparent `init.py` typo is not followed.

## Roadmap

- More defensive scenario families after the first schema stabilises
- More provider adapters and richer operational impact models

Apache-2.0 licensed. Contributions and responsible vulnerability reports are welcome.
